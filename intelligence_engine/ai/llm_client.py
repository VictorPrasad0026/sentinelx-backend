"""
SentinelX LLM Client — Groq (Free)
Get free key: console.groq.com → API Keys → Create Key
"""

import json
import urllib.request
import urllib.error

GROQ_API_KEY = "AQ.Ab8RN6KHXcBtbTtsIFao84cgjrb9fAjmFAF14cPutEAeO1OpIA"
MODEL        = "gemini-2.5-flash"


def complete(system: str, user: str, max_tokens: int = 1024) -> str:
    payload = json.dumps({
        "model":      MODEL,
        "max_tokens": max_tokens,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user",   "content": user},
        ],
    }).encode()

    req = urllib.request.Request(
        "https://api.groq.com/openai/v1/chat/completions",
        data=payload,
        headers={
            "Authorization": f"Bearer {GROQ_API_KEY}",
            "Content-Type":  "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
            return data["choices"][0]["message"]["content"]
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        if e.code == 401:
            return "[Groq error: invalid API key — update GROQ_API_KEY in llm_client.py]"
        if e.code == 429:
            return "[Groq error: rate limit hit — wait a moment and retry]"
        return f"[Groq error {e.code}: {body[:200]}]"
    except Exception as e:
        return f"[Groq error: {e}]"


def is_available() -> tuple[bool, str]:
    if GROQ_API_KEY == "YOUR_GROQ_API_KEY_HERE":
        return False, "Paste your Groq API key in llm_client.py (get free key at console.groq.com)"
    return True, f"Groq ready — model: {MODEL}"
