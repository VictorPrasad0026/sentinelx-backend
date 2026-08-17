"""
SentinelX V5 — Web API Server with Groq AI
Run: python api_server.py
"""

import json
import os
import sys
import threading
import time
import urllib.request
import urllib.error
from datetime import datetime
from flask import Flask, jsonify, request, Response, send_from_directory
from flask_cors import CORS

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

app = Flask(__name__, static_folder="web/dist", static_url_path="")
CORS(app, resources={r"/api/*": {"origins": "*"}})

# ── GROQ CONFIG ───────────────────────────────────────────────────
GROQ_API_KEY = "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"
GROQ_MODEL   = "openai/gpt-oss-120b"
# ─────────────────────────────────────────────────────────────────

scans = {}

def new_scan_id(domain):
    return f"{domain.replace('.','_')}_{int(time.time())}"


def run_scan_thread(scan_id, domain, options):
    scan = scans[scan_id]
    scan["status"] = "running"

    def emit(msg, pct=None):
        scan["events"].append({"type": "progress", "msg": msg, "ts": time.time()})
        if pct is not None:
            scan["progress"] = pct

    try:
        from collectors.asset_profile import build_asset_profile
        from intelligence_engine.v4.v4_engine import run_v4
        from intelligence_engine.v5.v5_engine import run_v5
        from intelligence_engine.business.business_asset_mapper import map_business_assets
        from intelligence_engine.business.crown_jewel_identifier import identify_crown_jewels
        from intelligence_engine.business.compliance_mapper import ComplianceMapper
        from intelligence_engine.business.business_impact import translate_findings

        emit(f"[DNS] Resolving {domain}...", 5)
        profile = build_asset_profile(domain)
        emit(f"[COLLECT] {len(profile.get('subdomain_assets',{}).get('assets',[]))} assets found", 30)
        emit("[V4] Asset correlation, attack graph, exposure scoring...", 35)
        v4 = run_v4(profile, enable_vuln_intel=options.get("vuln", False),
                    enable_api_discovery=True, enable_js_intel=True)
        emit("[V4] V4 complete", 60)
        emit("[V5] TLS grading, login detection, secrets, passive DNS...", 65)
        v5 = run_v5(profile, v4,
                    enable_screenshots=options.get("screenshots", False),
                    enable_passive_dns=options.get("passive", True),
                    enable_github_leaks=options.get("github", False))
        emit("[V5] V5 complete", 80)
        emit("[BIZ] Business impact and compliance mapping...", 85)
        biz_surface = map_business_assets(profile)
        crown = identify_crown_jewels(biz_surface)
        compliance = ComplianceMapper().generate_compliance_report(
            profile.get("risk_assessment", {}).get("findings", []))
        business_impact = translate_findings(
            profile.get("risk_assessment", {}).get("findings", []), domain)
        emit("[BIZ] Done", 92)
        emit("[DONE] Assembling report...", 97)
        scan["result"] = {
            "domain": domain, "scanned_at": datetime.utcnow().isoformat(),
            "profile": profile, "v4": v4, "v5": v5,
            "business": {"attack_surface": biz_surface, "crown_jewels": crown,
                         "compliance": compliance, "business_impact": business_impact},
        }
        scan["status"] = "done"
        scan["progress"] = 100
        emit("[COMPLETE] Done", 100)
    except Exception as e:
        import traceback
        scan["status"] = "error"
        scan["error"] = str(e)
        scan["events"].append({"type": "error", "msg": f"Error: {e}", "ts": time.time()})
        traceback.print_exc()


# ── GROQ AI PROXY ─────────────────────────────────────────────────
@app.route("/api/ai", methods=["POST", "OPTIONS"])
def ai_proxy():
    if request.method == "OPTIONS":
        resp = app.make_default_options_response()
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        resp.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
        return resp

    body       = request.json or {}
    system_msg = body.get("system", "")
    messages   = body.get("messages", [])
    max_tokens = body.get("max_tokens", 1000)

    payload = json.dumps({
        "model": GROQ_MODEL,
        "max_tokens": max_tokens,
        "messages": [
            {"role": "system", "content": system_msg},
            *messages
        ],
    }).encode("utf-8")

    req = urllib.request.Request(
        "https://api.groq.com/openai/v1/chat/completions",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {GROQ_API_KEY}",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            result = json.loads(r.read())
            text = result["choices"][0]["message"]["content"]
            resp = jsonify({"content": [{"type": "text", "text": text}]})
            resp.headers["Access-Control-Allow-Origin"] = "*"
            return resp
    except urllib.error.HTTPError as e:
        err = e.read().decode()
        print(f"[Groq Error {e.code}] {err}")
        return jsonify({"error": f"Groq error {e.code}: {err}"}), e.code
    except Exception as e:
        print(f"[Groq Exception] {e}")
        return jsonify({"error": str(e)}), 500


# ── SCAN ROUTES ───────────────────────────────────────────────────
@app.route("/api/scan", methods=["POST"])
def start_scan():
    body = request.json or {}
    domain = body.get("domain", "").strip().lower()
    domain = domain.replace("https://", "").replace("http://", "").rstrip("/")
    if not domain:
        return jsonify({"error": "domain required"}), 400
    options = body.get("options", {})
    scan_id = new_scan_id(domain)
    scans[scan_id] = {
        "id": scan_id, "domain": domain, "status": "queued",
        "progress": 0, "events": [], "result": None,
        "error": None, "started_at": time.time(),
    }
    threading.Thread(
        target=run_scan_thread,
        args=(scan_id, domain, options),
        daemon=True
    ).start()
    return jsonify({"scan_id": scan_id, "domain": domain})


@app.route("/api/scan/<scan_id>", methods=["GET"])
def get_scan(scan_id):
    scan = scans.get(scan_id)
    if not scan:
        return jsonify({"error": "not found"}), 404
    return jsonify({
        "id": scan["id"], "domain": scan["domain"],
        "status": scan["status"], "progress": scan["progress"],
        "error": scan["error"], "result": scan["result"],
    })


@app.route("/api/scan/<scan_id>/events", methods=["GET"])
def stream_events(scan_id):
    scan = scans.get(scan_id)
    if not scan:
        return jsonify({"error": "not found"}), 404

    def generate():
        sent = 0
        while True:
            events = scan["events"]
            while sent < len(events):
                yield f"data: {json.dumps(events[sent])}\n\n"
                sent += 1
            if scan["status"] in ("done", "error"):
                yield f"data: {json.dumps({'type':'end','status':scan['status']})}\n\n"
                break
            time.sleep(0.3)

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )


@app.route("/api/scans", methods=["GET"])
def list_scans():
    return jsonify([
        {"id": s["id"], "domain": s["domain"], "status": s["status"],
         "progress": s["progress"], "started_at": s["started_at"]}
        for s in scans.values()
    ])


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "version": "SentinelX V5",
        "ai_provider": "Groq",
        "ai_model": GROQ_MODEL,
        "ai_key_set": bool(GROQ_API_KEY),
    })


# ── SERVE REACT UI ────────────────────────────────────────────────
@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_react(path):
    if path and os.path.exists(os.path.join(app.static_folder or "", path)):
        return send_from_directory(app.static_folder, path)
    index = os.path.join(app.static_folder or "", "index.html")
    if os.path.exists(index):
        return send_from_directory(app.static_folder, "index.html")
    return jsonify({"msg": "React UI not built yet"}), 200


if __name__ == "__main__":
    print("\n" + "="*55)
    print("  SentinelX V5 — Web Server (Groq AI)")
    print(f"  Model  : {GROQ_MODEL}")
    print(f"  Key    : {'✓ SET' if GROQ_API_KEY else '✗ NOT SET'}")
    print("  URL    : http://localhost:5000")
    print("="*55 + "\n")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)