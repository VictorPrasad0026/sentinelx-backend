import { useState, useEffect, useRef, useMemo, useCallback } from "react";

const T = {
  bg0:"#03060f",bg1:"#070d1c",bg2:"#0a1224",bg3:"#0e1830",bg4:"#121e3a",
  surface:"rgba(14,24,48,0.88)",border:"rgba(30,58,110,0.6)",borderHi:"rgba(0,212,255,0.28)",
  cyan:"#00d4ff",cyanD:"#0099bb",blue:"#3d7fff",blueD:"#1a4acc",blueDim:"rgba(61,127,255,0.12)",
  purple:"#8b5cf6",purpleD:"#5b3ab0",purpleDim:"rgba(139,92,246,0.12)",
  green:"#00ff88",greenD:"#00c066",greenDim:"rgba(0,255,136,0.1)",
  red:"#ff3366",redD:"#cc1144",redDim:"rgba(255,51,102,0.12)",
  orange:"#ff8c00",orangeDim:"rgba(255,140,0,0.12)",yellow:"#ffd700",yellowDim:"rgba(255,215,0,0.1)",
  text:"#e2e8f0",textD:"#94a3b8",textDD:"#475569",
  mono:"'JetBrains Mono',monospace",sans:"'Inter',sans-serif",
};
const SEV={
  color:s=>s==="CRITICAL"?T.red:s==="HIGH"?T.orange:s==="MEDIUM"?T.yellow:T.green,
  bg:s=>s==="CRITICAL"?T.redDim:s==="HIGH"?T.orangeDim:s==="MEDIUM"?T.yellowDim:T.greenDim,
  border:s=>s==="CRITICAL"?"rgba(255,51,102,0.35)":s==="HIGH"?"rgba(255,140,0,0.35)":s==="MEDIUM"?"rgba(255,215,0,0.3)":"rgba(0,255,136,0.2)",
  short:s=>s==="CRITICAL"?"CRIT":s==="HIGH"?"HIGH":s==="MEDIUM"?"MED":"LOW",
  icon:s=>s==="CRITICAL"?"🔴":s==="HIGH"?"🟠":s==="MEDIUM"?"🟡":"🟢",
};
const PHASE_COLORS={1:T.cyan,2:T.blue,3:T.purple,4:T.orange,5:T.green,6:T.red};
const PHASE_LABELS={1:"RECONNAISSANCE",2:"ENUMERATION",3:"DEEP ANALYSIS",4:"INTELLIGENCE",5:"CORRELATION",6:"SYNTHESIS"};

const CSS=`
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600&display=swap');
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html,body{background:#03060f;color:#e2e8f0;font-family:'Inter',sans-serif;overflow-x:hidden}
::-webkit-scrollbar{width:4px;height:4px}::-webkit-scrollbar-track{background:#070d1c}::-webkit-scrollbar-thumb{background:rgba(0,212,255,0.25);border-radius:2px}
input,textarea,button{font-family:inherit}button{cursor:pointer}
@keyframes glow-pulse{0%,100%{opacity:1;text-shadow:0 0 8px currentColor}50%{opacity:.85;text-shadow:0 0 24px currentColor,0 0 48px currentColor}}
@keyframes scan-line{0%{transform:translateY(-100vh)}100%{transform:translateY(100vh)}}
@keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-8px)}}
@keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}
@keyframes radar{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}
@keyframes appear{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}
@keyframes slide-r{from{opacity:0;transform:translateX(32px)}to{opacity:1;transform:translateX(0)}}
@keyframes pulse-ring{0%{box-shadow:0 0 0 0 rgba(0,212,255,.45)}70%{box-shadow:0 0 0 10px rgba(0,212,255,0)}100%{box-shadow:0 0 0 0 rgba(0,212,255,0)}}
@keyframes attack-dash{from{stroke-dashoffset:400}to{stroke-dashoffset:0}}
@keyframes node-ping{0%,100%{filter:drop-shadow(0 0 4px currentColor)}50%{filter:drop-shadow(0 0 14px currentColor)}}
@keyframes counter{from{opacity:0;transform:scale(.88)}to{opacity:1;transform:scale(1)}}
.glass{background:rgba(14,24,48,0.88);backdrop-filter:blur(16px);border:1px solid rgba(30,58,110,0.6);border-radius:12px}
.glass-hi{background:rgba(10,18,36,0.97);backdrop-filter:blur(24px);border:1px solid rgba(0,212,255,0.28);border-radius:12px}
.glow-c{box-shadow:0 0 24px rgba(0,212,255,.1),inset 0 0 24px rgba(0,212,255,.03)}
.glow-r{box-shadow:0 0 24px rgba(255,51,102,.13),inset 0 0 24px rgba(255,51,102,.04)}
.glow-p{box-shadow:0 0 24px rgba(139,92,246,.13),inset 0 0 24px rgba(139,92,246,.04)}
.mono{font-family:'JetBrains Mono',monospace}
.row{display:flex;align-items:center}.col{display:flex;flex-direction:column}
.anim{animation:appear .35s ease-out both}
.btn{border:none;border-radius:8px;padding:8px 16px;font-size:13px;font-weight:600;letter-spacing:.04em;transition:all .18s;white-space:nowrap}
.btn-p{background:linear-gradient(135deg,#1a4acc,#5b3ab0);color:#fff}
.btn-p:hover{transform:translateY(-1px);box-shadow:0 6px 20px rgba(61,127,255,.4)}
.btn-d{background:linear-gradient(135deg,#cc1144,#c0392b);color:#fff}
.btn-d:hover{transform:translateY(-1px);box-shadow:0 6px 20px rgba(255,51,102,.4)}
.btn-g{background:transparent;border:1px solid rgba(30,58,110,0.6);color:#94a3b8}
.btn-g:hover{border-color:#00d4ff;color:#00d4ff}
.btn-c{background:rgba(0,212,255,.1);border:1px solid rgba(0,212,255,.3);color:#00d4ff}
.btn-c:hover{background:rgba(0,212,255,.18)}
.badge{display:inline-flex;align-items:center;border-radius:4px;padding:2px 7px;font-size:10px;font-weight:700;letter-spacing:.1em}
.tab{background:none;border:none;color:#94a3b8;padding:6px 11px;border-radius:6px;font-size:12px;font-weight:500;transition:all .15s;white-space:nowrap}
.tab.on{background:rgba(61,127,255,.15);color:#00d4ff;font-weight:700}
.tab:hover:not(.on){color:#e2e8f0;background:rgba(255,255,255,.04)}
table{width:100%;border-collapse:collapse}
th{padding:9px 14px;font-size:10px;color:#475569;letter-spacing:.12em;text-align:left;font-weight:700;text-transform:uppercase;border-bottom:1px solid rgba(30,58,110,0.6)}
td{padding:9px 14px;font-size:13px;border-bottom:1px solid rgba(26,42,74,.3)}
tr:hover td{background:rgba(255,255,255,.022)}
`;

const PIPELINE=[
  {id:"dns",ph:1,icon:"🌐",label:"Discovering Domains & DNS Records"},
  {id:"sub",ph:1,icon:"🔍",label:"Enumerating Subdomains (crt.sh, OTX, bruteforce)"},
  {id:"pdns",ph:1,icon:"📡",label:"Passive DNS Intelligence (HackerTarget)"},
  {id:"ct",ph:1,icon:"📜",label:"Certificate Transparency Timeline"},
  {id:"rdns",ph:1,icon:"🔄",label:"Reverse DNS Lookup"},
  {id:"asn",ph:2,icon:"🏗️",label:"ASN & Organization Intelligence"},
  {id:"infra",ph:2,icon:"🖥️",label:"Infrastructure Discovery"},
  {id:"cloud",ph:2,icon:"☁️",label:"Cloud Provider Detection"},
  {id:"waf",ph:2,icon:"🛡️",label:"WAF / CDN Analysis"},
  {id:"geoip",ph:2,icon:"🗺️",label:"GeoIP Enrichment"},
  {id:"whois",ph:2,icon:"📋",label:"WHOIS Intelligence"},
  {id:"http",ph:3,icon:"🔧",label:"HTTP Fingerprinting & Headers"},
  {id:"tech",ph:3,icon:"⚙️",label:"Technology Stack Detection"},
  {id:"ports",ph:3,icon:"🚪",label:"Port Discovery & Service Banners"},
  {id:"ssl",ph:3,icon:"🔐",label:"TLS/SSL Analysis & Grading (A+-F)"},
  {id:"hdr",ph:3,icon:"📨",label:"Security Header Analysis"},
  {id:"email",ph:3,icon:"✉️",label:"Email Security (SPF/DKIM/DMARC)"},
  {id:"csp",ph:3,icon:"🧱",label:"Content Security Policy Analysis"},
  {id:"login",ph:4,icon:"🔑",label:"Login Page & Auth Detection"},
  {id:"secret",ph:4,icon:"🗝️",label:"Secrets Exposure Scan (.env, .git, keys)"},
  {id:"js",ph:4,icon:"📝",label:"JavaScript Intelligence (endpoints, secrets)"},
  {id:"api",ph:4,icon:"🔌",label:"API Discovery (REST, GraphQL, Swagger)"},
  {id:"bucket",ph:4,icon:"🪣",label:"Public Cloud Bucket Detection"},
  {id:"vuln",ph:5,icon:"💀",label:"CVE Intelligence (NVD + EPSS)"},
  {id:"kev",ph:5,icon:"🚨",label:"CISA KEV Correlation"},
  {id:"graph",ph:5,icon:"🕸️",label:"Knowledge Graph Construction"},
  {id:"corr",ph:5,icon:"🔗",label:"Asset Correlation Engine"},
  {id:"crown",ph:5,icon:"👑",label:"Crown Jewel Identification"},
  {id:"biz",ph:5,icon:"💼",label:"Business Impact Mapping"},
  {id:"comply",ph:5,icon:"⚖️",label:"Compliance Framework Mapping"},
  {id:"risk",ph:6,icon:"⚠️",label:"Risk Scoring Engine"},
  {id:"attack",ph:6,icon:"🎯",label:"Attack Graph Construction"},
  {id:"path",ph:6,icon:"🛤️",label:"CVE-Enriched Attack Path Generation"},
  {id:"hist",ph:6,icon:"📅",label:"Historical Scan Comparison"},
  {id:"trend",ph:6,icon:"📈",label:"Risk Trend Analysis"},
  {id:"rem",ph:6,icon:"🔨",label:"Remediation Plan Generation"},
  {id:"ai",ph:6,icon:"🤖",label:"AI Intelligence Engine (Claude)"},
  {id:"exec",ph:6,icon:"📊",label:"Executive Summary Generation"},
];

function pickSeeded(arr, seed, mult=1) {
  return arr[Math.abs(seed*mult*7919%997) % arr.length];
}

function generateData(domain) {
  const seed = domain.split("").reduce((a,c)=>a+c.charCodeAt(0),0);
  const rnd = (n) => Math.abs(seed*n*7919%997) % n;

  const subNames=["www","api","app","mail","vpn","admin","staging","dev","cdn","portal","auth","docs","status","assets","login","dashboard","support","beta","internal","secure","gateway","static","media","shop"];
  const techs=["Nginx","Apache","React","Vue.js","Node.js","Django","Laravel","WordPress","PostgreSQL","Redis","Docker","Kubernetes","AWS S3","CloudFront","Cloudflare","Next.js","Express.js","MySQL","MongoDB","Elasticsearch","Jenkins","GitLab","Grafana","Kibana"];
  const clouds=["AWS","GCP","Azure","Cloudflare","Fastly","Akamai","DigitalOcean"];
  const wafs=["Cloudflare","AWS WAF","Akamai","F5 BIG-IP","Imperva","Sucuri"];
  const countries=["US","DE","GB","SG","JP","AU","NL","FR"];
  const cities=["Seattle","Frankfurt","London","Singapore","Tokyo","Sydney","Amsterdam","Paris"];
  const asns=["AS16509 Amazon.com Inc.","AS15169 Google LLC","AS8075 Microsoft Corp","AS13335 Cloudflare Inc.","AS14618 Amazon.com Inc."];

  const subCount = 8 + rnd(8);
  const subs = subNames.slice(0, subCount).map((n,i) => {
    const riskIdx = rnd((i+1)*3) % 4;
    const risk = ["LOW","MEDIUM","HIGH","CRITICAL"][riskIdx];
    const cloud = i%3===0 ? pickSeeded(clouds, seed, i+1) : null;
    const waf = i%4===0 ? pickSeeded(wafs, seed, i+7) : null;
    const grade = ["A+","A","A","B","B","C","F"][rnd((i+1)*5) % 7];
    const ports = [443,80,...(n==="api"?[8080,8443]:[]),...(n==="mail"?[25,587,993]:[]),...(n==="dev"?[3000,22]:[]),...(n==="admin"?[8080,9090]:[])];
    const ip = `${[34,54,104,172,35][i%5]}.${(rnd(254*(i+1))+1)}.${(rnd(254*(i+7))+1)}.${(rnd(254*(i+13))+1)}`;
    const techStart = rnd(techs.length*(i+1)) % (techs.length-3);
    const myTechs = techs.slice(techStart, techStart+3);
    const countryIdx = rnd((i+3)*5) % countries.length;
    const loginPages = (n==="admin"||n==="portal"||n==="auth"||n==="dashboard") ? [
      {url:`https://${n}.${domain}/login`,authType:pickSeeded(["form","basic","oauth","sso"],seed,i+2),defaultCredRisk:n==="admin"}
    ] : [];
    const secrets = (n==="dev"||n==="api"||n==="staging") ? [
      {path:pickSeeded(["/.env","/.git/config","/config.json","/api-docs","/phpinfo.php"],seed,i+3),
       severity:pickSeeded(["CRITICAL","HIGH","MEDIUM"],seed,i+4),
       desc:pickSeeded(["AWS credentials exposed","Git repo config disclosed","API keys in config file","Swagger docs public","PHP info page reveals config"],seed,i+5)}
    ] : [];
    const apis = (n==="api"||n==="app") ? [
      {path:pickSeeded(["/api/v1","/graphql","/swagger.json","/api/v2/users"],seed,i+6),
       auth:rnd(i+3)%3===0,cors:pickSeeded(["*","none","restricted"],seed,i+8),
       introspection:n==="api",risk:pickSeeded(["CRITICAL","HIGH","MEDIUM"],seed,i+9)}
    ] : [];
    return {host:`${n}.${domain}`,ip,ports,grade,risk,cloud,waf,techs:myTechs,
      asn:pickSeeded(asns,seed,i+1),country:countries[countryIdx],city:cities[countryIdx],
      hasBusiness:pickSeeded(["Customer Portal","DevOps","Email Infra","Admin Panel","Data Store","Auth Service","Core API","CDN Origin","Payment Gateway"],seed,i+2),
      loginPages,secrets,apis,
      screenshotMeta:{title:n.charAt(0).toUpperCase()+n.slice(1)+" — "+domain,statusCode:200,redirectUrl:null},
    };
  });

  const riskScore = 35 + rnd(55);
  const severity = riskScore>=80?"CRITICAL":riskScore>=60?"HIGH":riskScore>=40?"MEDIUM":"LOW";

  const findings=[
    {severity:"CRITICAL",issue:"Admin panel exposed with default credential risk",asset:`admin.${domain}`,cve:"CVE-2024-21887",epss:0.847,cvss:9.8,category:"Access Control",mitre:"T1078",compliance:["PCI-DSS 8.2","ISO27001 A.9.2"]},
    {severity:"CRITICAL",issue:".env file publicly accessible — AWS credentials exposed",asset:`dev.${domain}`,cve:null,epss:null,cvss:9.1,category:"Secrets Exposure",mitre:"T1552",compliance:["PCI-DSS 3.4","GDPR Art.32"]},
    {severity:"HIGH",issue:`SSL certificate expires in 12 days on mail.${domain}`,asset:`mail.${domain}`,cve:null,epss:null,cvss:7.4,category:"TLS",mitre:"T1557",compliance:["PCI-DSS 4.1"]},
    {severity:"HIGH",issue:"Open redirect vulnerability — viable phishing vector",asset:`api.${domain}`,cve:"CVE-2023-43804",epss:0.412,cvss:7.5,category:"Web Application",mitre:"T1566",compliance:["OWASP A01"]},
    {severity:"HIGH",issue:"GraphQL introspection enabled — full schema exposed",asset:`api.${domain}`,cve:null,epss:null,cvss:6.5,category:"API Security",mitre:"T1590",compliance:["OWASP API9"]},
    {severity:"HIGH",issue:"CORS policy allows wildcard origin (*) on API",asset:`api.${domain}`,cve:null,epss:null,cvss:6.8,category:"API Security",mitre:"T1557",compliance:["OWASP A05"]},
    {severity:"MEDIUM",issue:"Missing HSTS header on 6 subdomains",asset:domain,cve:null,epss:null,cvss:5.3,category:"Security Headers",mitre:"T1557",compliance:["PCI-DSS 6.5","NIST SP800-52"]},
    {severity:"MEDIUM",issue:"DMARC policy set to p=none — no enforcement active",asset:domain,cve:null,epss:null,cvss:5.9,category:"Email Security",mitre:"T1566",compliance:["NIST SP800-177"]},
    {severity:"MEDIUM",issue:"Content Security Policy allows unsafe-inline scripts",asset:`www.${domain}`,cve:null,epss:null,cvss:5.4,category:"CSP",mitre:"T1059",compliance:["OWASP A05"]},
    {severity:"MEDIUM",issue:"SPF record uses +all — allows any mail sender",asset:domain,cve:null,epss:null,cvss:5.1,category:"Email Security",mitre:"T1566",compliance:["NIST SP800-177"]},
    {severity:"LOW",issue:"Server version disclosed in X-Powered-By header",asset:`www.${domain}`,cve:null,epss:null,cvss:3.1,category:"Information Disclosure",mitre:"T1592",compliance:[]},
    {severity:"LOW",issue:"Missing X-Frame-Options on auth pages — clickjacking risk",asset:`auth.${domain}`,cve:null,epss:null,cvss:3.7,category:"Security Headers",mitre:"T1185",compliance:["OWASP A05"]},
  ];

  const attackPaths=[
    {rank:1,likelihood:87,name:"Credential Theft via Exposed Admin Panel",
     steps:["Internet","DNS Enumeration",`admin.${domain}`,"HTTP 200 Login","Default Creds","Admin Access","Data Exfil"],
     mitre:["T1595","T1589","T1078","T1005"],cvss:9.8,cve:"CVE-2024-21887",epss:0.847,
     skillLevel:"Script Kiddie",impact:"Full admin compromise → customer PII breach → regulatory fines",
     bizImpact:"Estimated GDPR Article 83 fine up to €20M. Customer trust collapse. Service disruption.",kev:true,
     remediations:["Disable default credentials immediately","Enforce MFA on all admin interfaces","Restrict admin panel to VPN-only access"]},
    {rank:2,likelihood:79,name:"Cloud Takeover via .env Secrets",
     steps:["Internet",`dev.${domain}`,"/.env","AWS_ACCESS_KEY","Cloud Console","S3 Buckets","Full Data Dump"],
     mitre:["T1190","T1552","T1530"],cvss:9.1,cve:null,epss:null,
     skillLevel:"Script Kiddie",impact:"AWS credential theft → full cloud environment access",
     bizImpact:"Cloud infrastructure takeover. Data exfiltration. Ransomware deployment risk.",kev:false,
     remediations:["Block /.env from web access via nginx","Rotate all exposed AWS credentials","Enable AWS CloudTrail and GuardDuty"]},
    {rank:3,likelihood:73,name:"MITM Attack via Expiring SSL",
     steps:["Expired SSL",`mail.${domain}`,"MITM Position","Credential Harvest","Email Pivot","Lateral Movement"],
     mitre:["T1557","T1539","T1110"],cvss:7.4,cve:null,epss:null,
     skillLevel:"Intermediate",impact:"Email credential interception and corporate mail takeover",
     bizImpact:"Executive email compromise. Financial fraud via BEC (Business Email Compromise).",kev:false,
     remediations:["Renew SSL certificate immediately","Enable HSTS with preload","Deploy automated cert monitoring"]},
    {rank:4,likelihood:61,name:"API Schema Exfiltration via GraphQL",
     steps:["Internet",`api.${domain}`,"/graphql","Introspection","Schema Dump","Targeted PII Extraction"],
     mitre:["T1590","T1213","T1005"],cvss:6.5,cve:null,epss:null,
     skillLevel:"Intermediate",impact:"Full API schema exposure enables targeted data extraction",
     bizImpact:"Customer PII breach. GDPR breach notification required within 72 hours.",kev:false,
     remediations:["Disable GraphQL introspection in production","Implement field-level authorization","Add API rate limiting"]},
    {rank:5,likelihood:54,name:"Phishing via Open Redirect",
     steps:["Spear Phishing Email",`api.${domain}/redirect`,"Attacker Domain","Fake Login","Account Takeover"],
     mitre:["T1566","T1598","T1078"],cvss:7.5,cve:"CVE-2023-43804",epss:0.412,
     skillLevel:"Intermediate",impact:"Trusted domain abused to redirect victims to attacker infrastructure",
     bizImpact:"User credential theft at scale. Reputational damage from domain abuse.",kev:false,
     remediations:["Validate all redirect targets against allowlist","Remove or restrict redirect endpoint","Add CSP and referrer headers"]},
  ];

  const cves=[
    {id:"CVE-2024-21887",cvss:9.8,epss:0.847,kev:true,desc:"Ivanti Connect Secure command injection in web components",tech:"Ivanti",patch:"Upgrade to 22.7R2.4+"},
    {id:"CVE-2023-43804",cvss:7.5,epss:0.412,kev:false,desc:"urllib3 Cookie header injection on redirect — affects Python stacks",tech:"Python urllib3",patch:"Upgrade urllib3 ≥ 2.0.7"},
    {id:"CVE-2023-3519",cvss:9.8,epss:0.912,kev:true,desc:"Citrix ADC/Gateway unauthenticated remote code execution",tech:"Citrix",patch:"Apply Citrix CTX561482"},
    {id:"CVE-2024-1234",cvss:8.1,epss:0.234,kev:false,desc:"WordPress admin authentication bypass via plugin vulnerability",tech:"WordPress",patch:"Update WordPress core + plugins"},
  ];

  const apis=[
    {endpoint:"/api/v1",path:`api.${domain}/api/v1`,auth:false,cors:"*",method:"GET",sensitive:["user_ids","emails","roles"],risk:"HIGH"},
    {endpoint:"/graphql",path:`api.${domain}/graphql`,auth:true,cors:"restricted",introspection:true,risk:"MEDIUM"},
    {endpoint:"/api/v2/users",path:`api.${domain}/api/v2/users`,auth:false,cors:"*",method:"GET",sensitive:["hashed_passwords","tokens"],risk:"CRITICAL"},
    {endpoint:"/swagger.json",path:`api.${domain}/swagger.json`,auth:false,cors:"*",risk:"MEDIUM"},
    {endpoint:"/actuator/env",path:`app.${domain}/actuator/env`,auth:false,cors:"none",risk:"CRITICAL"},
    {endpoint:"/api/health",path:`api.${domain}/api/health`,auth:false,cors:"none",risk:"LOW"},
  ];

  const jsSources=[
    {file:`www.${domain}/static/app.bundle.js`,size:"1.4 MB",findings:[
      {type:"AWS_ACCESS_KEY",value:"AKIA[REDACTED]EXAMPLE",risk:"CRITICAL",line:4821},
      {type:"API_ENDPOINT",value:"/api/internal/admin/users",risk:"HIGH",line:2341},
      {type:"INTERNAL_IP",value:"10.0.1.45",risk:"MEDIUM",line:8823},
      {type:"GENERIC_API_KEY",value:"sk-prod-[REDACTED]",risk:"CRITICAL",line:1203},
    ]},
    {file:`cdn.${domain}/assets/vendor.js`,size:"892 KB",findings:[
      {type:"STRIPE_KEY",value:"pk_live_[REDACTED]",risk:"CRITICAL",line:312},
      {type:"FIREBASE_KEY",value:"AIzaSy[REDACTED]",risk:"HIGH",line:88},
    ]},
  ];

  const passiveDns={
    historicalSubdomains:[`old-api.${domain}`,`legacy.${domain}`,`test.${domain}`,`staging2.${domain}`,`beta.${domain}`,`dev2.${domain}`],
    ipHistory:[
      {ip:"104.21.44.12",firstSeen:"2022-01-15",lastSeen:"2023-06-20",provider:"Cloudflare"},
      {ip:"34.121.88.44",firstSeen:"2023-06-21",lastSeen:"2024-01-10",provider:"GCP"},
      {ip:"54.144.22.18",firstSeen:"2024-01-11",lastSeen:"present",provider:"AWS"},
    ],
  };

  const tlsGrades=subs.reduce((acc,s)=>{
    acc[s.host]={grade:s.grade,tls:"TLS 1.3",bits:256,hsts:s.grade==="A+",issues:s.grade!=="A+"&&s.grade!=="A"?["Missing HSTS","Weak cipher suite RC4"]:s.grade==="A"?["No HSTS preload"]:[]};
    return acc;
  },{});

  const ctTimeline=[
    {logged:"2024-01-15",name:`*.${domain}`,issuer:"Let's Encrypt",expiry:"2024-04-15",valid:true},
    {logged:"2023-10-01",name:`api.${domain}`,issuer:"DigiCert Inc.",expiry:"2024-10-01",valid:true},
    {logged:"2023-07-20",name:`mail.${domain}`,issuer:"Let's Encrypt",expiry:"2023-10-20",valid:false},
    {logged:"2022-12-01",name:`www.${domain}`,issuer:"Sectigo Limited",expiry:"2023-12-01",valid:false},
  ];

  const compliance={
    "PCI-DSS":["Missing HSTS on cardholder data pages","Weak TLS 1.0 on mail server","Admin panel without MFA violates 8.3"],
    "GDPR":["/.env exposed — potential PII in credentials","No CSP on customer-facing portal","DMARC p=none allows phishing with domain"],
    "ISO 27001":["Default credentials risk (A.9.2)","Open redirect enables social engineering (A.7.2)","Server version disclosure (A.12.6)"],
    "NIST CSF":["SPF +all allows unauthorized senders","DKIM not configured on all subdomains","Missing security headers on 6 assets"],
    "OWASP Top 10":["GraphQL introspection (API9:2023)","CORS wildcard misconfiguration (A05)","CSP unsafe-inline (A05)","Open redirect (A01)"],
  };

  const crownjewels=[
    {host:`auth.${domain}`,reason:"Identity provider — compromise grants access to all dependent systems",score:95,finding:"Default cred risk on admin portal adjacent to auth service"},
    {host:`api.${domain}`,reason:"Core API handling customer PII, payment references, and session tokens",score:91,finding:"GraphQL introspection + unauthenticated endpoints"},
    {host:`admin.${domain}`,reason:"Administrative control plane with full system access and user management",score:88,finding:"Exposed login page with default credential risk"},
  ];

  const riskHistory=[
    {date:"2024-01",score:72},{date:"2024-02",score:68},{date:"2024-03",score:74},
    {date:"2024-04",score:71},{date:"2024-05",score:riskScore},
  ];

  const remediations=[
    {rank:1,title:"Disable default admin credentials & enforce MFA",effort:"2 hours",reduction:22,severity:"CRITICAL",steps:["Change all admin passwords to strong unique values","Enable TOTP-based MFA on admin login","Restrict admin panel to VPN / corporate IP range only"]},
    {rank:2,title:"Block .env and config files at web server level",effort:"30 minutes",reduction:18,severity:"CRITICAL",steps:["Add Nginx: location ~* /\\.env { deny all; }","Rotate all exposed AWS keys, tokens, and passwords immediately","Enable AWS CloudTrail logging + GuardDuty alerting"]},
    {rank:3,title:"Renew SSL certificate on mail server",effort:"1 hour",reduction:12,severity:"HIGH",steps:["Run: certbot renew on mail server","Add HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains","Set up automated cert expiry monitoring (Zabbix/Datadog)"]},
    {rank:4,title:"Disable GraphQL introspection in production",effort:"15 minutes",reduction:9,severity:"HIGH",steps:["Apollo Server: introspection: process.env.NODE_ENV !== 'production'","Add authentication middleware to /graphql endpoint","Enable query depth limiting and complexity analysis"]},
    {rank:5,title:"Enforce DMARC policy to p=reject",effort:"4 hours",reduction:8,severity:"MEDIUM",steps:["Update DNS: _dmarc."+domain+" TXT \"v=DMARC1; p=reject; rua=mailto:dmarc@"+domain+"\"","Monitor DMARC aggregate reports for 2 weeks before enforcing","Ensure all legitimate senders pass SPF and DKIM"]},
    {rank:6,title:"Fix CORS — remove wildcard origin on all APIs",effort:"2 hours",reduction:7,severity:"HIGH",steps:["Replace Access-Control-Allow-Origin: * with explicit allowlist","Test all frontend integrations after CORS change","Add CORS policy to API gateway / load balancer level"]},
  ];

  const exec=`The external attack surface of ${domain} presents a ${severity.toLowerCase()} security posture with an overall risk score of ${riskScore}/100. SentinelX identified ${findings.filter(f=>f.severity==="CRITICAL").length} critical vulnerabilities requiring immediate action, including an exposed administrative panel with default credential risk and publicly accessible environment files containing cloud credentials. ${attackPaths.length} viable attack paths were constructed, with "${attackPaths[0].name}" presenting the highest exploitation probability at ${attackPaths[0].likelihood}%. ${cves.filter(c=>c.kev).length} vulnerability matches CISA's Known Exploited Vulnerabilities catalog, indicating active exploitation in the wild. Recommended immediate priorities: rotate all exposed credentials, enforce multi-factor authentication on admin interfaces, and renew the expiring SSL certificate on the mail server.`;

  return {
    domain,riskScore,severity,scanTime:new Date().toISOString(),
    subdomains:subs,findings,attackPaths,cves,apis,jsSources,passiveDns,
    tlsGrades,ctTimeline,compliance,crownjewels,riskHistory,remediations,
    totalAssets:subs.length,totalIPs:subs.length,totalPorts:34+rnd(20),
    totalCerts:12+rnd(8),totalTechs:techs.length,graphNodes:subs.length*3+rnd(20),
    graphEdges:subs.length*5+rnd(30),
    email:{spf:pickSeeded(["PASS","WARN","FAIL"],seed,2),dkim:pickSeeded(["PASS","FAIL"],seed,3),
           dmarc:pickSeeded(["NONE","QUARANTINE","REJECT"],seed,4),
           provider:pickSeeded(["Google Workspace","Microsoft 365","Proofpoint","Mimecast"],seed,5),riskScore:rnd(80)+20},
    tls:{overallGrade:pickSeeded(["B+","B","C","A"],seed,6),
         issues:["TLS 1.0 enabled on 2 hosts — deprecated protocol","Weak RC4 cipher suite detected","Missing OCSP stapling on 3 hosts","Wildcard certificate exposes all subdomains"]},
    cloud:{primary:pickSeeded(clouds,seed,7),providers:clouds.slice(0,3)},
    asn:pickSeeded(asns,seed,8),
    dns:{dnssec:rnd(2)===0,zoneTransfer:rnd(5)===0},
    waf:rnd(3)===0?null:pickSeeded(wafs,seed,9),exec,
  };
}

// ── ANIMATED COUNTER ─────────────────────────────────────────────
function Counter({to,dur=1200,suffix=""}) {
  const [v,setV]=useState(0);
  useEffect(()=>{
    let s; const step=ts=>{if(!s)s=ts;const p=Math.min((ts-s)/dur,1);setV(Math.floor(p*to));if(p<1)requestAnimationFrame(step)};
    requestAnimationFrame(step);
  },[to]);
  return <span style={{animation:"counter .3s ease-out"}}>{v.toLocaleString()}{suffix}</span>;
}

// ── CYBER GRID ───────────────────────────────────────────────────
function Grid() {
  return (
    <div style={{position:"fixed",inset:0,pointerEvents:"none",zIndex:0}}>
      <svg width="100%" height="100%" style={{position:"absolute",inset:0}}>
        <defs>
          <pattern id="g" width="50" height="50" patternUnits="userSpaceOnUse">
            <path d="M50 0L0 0 0 50" fill="none" stroke="rgba(30,58,110,0.18)" strokeWidth=".5"/>
          </pattern>
          <radialGradient id="gf" cx="50%" cy="50%" r="60%">
            <stop offset="0%" stopColor="transparent"/><stop offset="100%" stopColor="#03060f"/>
          </radialGradient>
        </defs>
        <rect width="100%" height="100%" fill="url(#g)"/>
        <rect width="100%" height="100%" fill="url(#gf)"/>
      </svg>
      <div style={{position:"absolute",left:0,right:0,height:1,background:"linear-gradient(90deg,transparent,rgba(0,212,255,.2),transparent)",animation:"scan-line 10s linear infinite"}}/>
    </div>
  );
}

// ── CYBER GLOBE ──────────────────────────────────────────────────
function Globe({size=260,radar=false}) {
  const cx=size/2,cy=size/2,r=size*.38;
  return (
    <svg width={size} height={size} style={{animation:"float 4s ease-in-out infinite",overflow:"visible"}}>
      <defs>
        <radialGradient id="gGrd" cx="38%" cy="38%"><stop offset="0%" stopColor="rgba(61,127,255,.18)"/><stop offset="100%" stopColor="rgba(3,6,15,.7)"/></radialGradient>
        <radialGradient id="gRim" cx="50%" cy="50%" r="50%"><stop offset="72%" stopColor="transparent"/><stop offset="100%" stopColor="rgba(0,212,255,.22)"/></radialGradient>
        <radialGradient id="sweepGrd" cx={`${cx}px`} cy={`${cy}px`} r={`${r}px`} gradientUnits="userSpaceOnUse"><stop offset="0%" stopColor="rgba(0,212,255,.3)"/><stop offset="100%" stopColor="transparent"/></radialGradient>
      </defs>
      <circle cx={cx} cy={cy} r={r+20} fill="none" stroke="rgba(0,212,255,.04)" strokeWidth="20"/>
      <circle cx={cx} cy={cy} r={r+10} fill="none" stroke="rgba(0,212,255,.09)" strokeWidth="1"/>
      <circle cx={cx} cy={cy} r={r+4}  fill="none" stroke="rgba(0,212,255,.05)" strokeWidth=".5"/>
      <circle cx={cx} cy={cy} r={r} fill="url(#gGrd)"/>
      <circle cx={cx} cy={cy} r={r} fill="url(#gRim)"/>
      {[-55,-28,0,28,55].map(lat=>{const y=cy+(lat/90)*r;const rl=Math.sqrt(Math.max(0,r*r-(y-cy)**2));return <ellipse key={lat} cx={cx} cy={y} rx={rl} ry={rl*.15} fill="none" stroke="rgba(0,212,255,.12)" strokeWidth=".5"/>})}
      {[0,30,60,90,120,150].map(lon=><ellipse key={lon} cx={cx} cy={cy} rx={r*.3} ry={r} fill="none" stroke="rgba(0,212,255,.1)" strokeWidth=".5" transform={`rotate(${lon} ${cx} ${cy})`}/>)}
      {[
        `M${cx-40} ${cy-30}Q${cx-20} ${cy-52}${cx+12} ${cy-35}Q${cx+32} ${cy-18}${cx+18} ${cy+2}Q${cx} ${cy+12}${cx-32} ${cy-8}Z`,
        `M${cx-62} ${cy+22}Q${cx-42} ${cy+10}${cx-18} ${cy+32}Q${cx-35} ${cy+52}${cx-56} ${cy+42}Z`,
        `M${cx+28} ${cy+8}Q${cx+52} ${cy+3}${cx+62} ${cy+26}Q${cx+48} ${cy+46}${cx+26} ${cy+36}Z`,
      ].map((d,i)=><path key={i} d={d} fill={`rgba(0,${130+i*30},${180+i*25},.15)`} stroke="rgba(0,212,255,.2)" strokeWidth=".5"/>)}
      {radar&&(
        <g style={{transformOrigin:`${cx}px ${cy}px`,animation:"radar 3s linear infinite"}}>
          <path d={`M${cx} ${cy}L${cx} ${cy-r}A${r} ${r} 0 0 1 ${cx+r*.5} ${cy-r*.866}Z`} fill="url(#sweepGrd)" opacity=".5"/>
          <line x1={cx} y1={cy} x2={cx} y2={cy-r} stroke="#00d4ff" strokeWidth="1.5"/>
        </g>
      )}
      {radar&&[{x1:cx-70,y1:cy-50,x2:cx+15,y2:cy+10},{x1:cx+65,y1:cy-35,x2:cx-8,y2:cy+18},{x1:cx-15,y1:cy+65,x2:cx+25,y2:cy-18}].map((l,i)=>(
        <line key={i} x1={l.x1} y1={l.y1} x2={l.x2} y2={l.y2} stroke={`rgba(255,51,102,${.4+i*.12})`} strokeWidth="1" strokeDasharray="3 3" strokeDashoffset="400" style={{animation:`attack-dash 2s ease-in-out infinite ${i*.4}s`}}/>
      ))}
      {[{x:cx-28,y:cy-42},{x:cx+42,y:cy+18},{x:cx-52,y:cy+28},{x:cx+18,y:cy-52}].map((p,i)=>(
        <circle key={i} cx={p.x} cy={p.y} r={3} fill="#00d4ff" style={{animation:`pulse-ring ${1+i*.25}s ease-in-out infinite ${i*.18}s`}}/>
      ))}
      <text x={cx} y={cy+8} textAnchor="middle" fontSize={size*.1}>🛡️</text>
    </svg>
  );
}

// ── RISK GAUGE ───────────────────────────────────────────────────
function RiskGauge({score,size=180}) {
  const cx=size/2,cy=size*.56,r=size*.38;
  const circ=Math.PI*r,fill=(score/100)*circ;
  const col=SEV.color(score>=80?"CRITICAL":score>=60?"HIGH":score>=40?"MEDIUM":"LOW");
  return (
    <svg width={size} height={size*.66} viewBox={`0 0 ${size} ${size*.66}`}>
      <defs>
        <linearGradient id="gaugeG"><stop offset="0%" stopColor="#00ff88"/><stop offset="50%" stopColor="#ffd700"/><stop offset="100%" stopColor="#ff3366"/></linearGradient>
        <filter id="gaugeGlow"><feGaussianBlur stdDeviation="3" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
      </defs>
      <path d={`M${cx-r} ${cy}A${r} ${r} 0 0 1 ${cx+r} ${cy}`} fill="none" stroke="rgba(255,255,255,.07)" strokeWidth="14" strokeLinecap="round"/>
      <path d={`M${cx-r} ${cy}A${r} ${r} 0 0 1 ${cx+r} ${cy}`} fill="none" stroke="url(#gaugeG)" strokeWidth="14" strokeLinecap="round" strokeDasharray={`${fill} ${circ}`} filter="url(#gaugeGlow)" style={{transition:"stroke-dasharray 1.5s cubic-bezier(.4,0,.2,1)"}}/>
      <text x={cx} y={cy-6} textAnchor="middle" fontSize={size*.23} fontWeight="800" fill={col} fontFamily="'JetBrains Mono',monospace" style={{animation:"glow-pulse 3s infinite"}}>{score}</text>
      <text x={cx} y={cy+14} textAnchor="middle" fontSize={10} fill="#94a3b8">RISK SCORE</text>
    </svg>
  );
}

// ── SPARKLINE ────────────────────────────────────────────────────
function Sparkline({data,color=T.cyan,w=120,h=36}) {
  if(!data||data.length<2) return null;
  const mn=Math.min(...data),mx=Math.max(...data),range=mx-mn||1;
  const pts=data.map((v,i)=>`${(i/(data.length-1))*w},${h-(v-mn)/range*h}`).join(" ");
  return (
    <svg width={w} height={h}>
      <defs><linearGradient id="spkG" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor={color} stopOpacity=".3"/><stop offset="100%" stopColor={color} stopOpacity="0"/></linearGradient></defs>
      <polygon points={`0,${h} ${pts} ${w},${h}`} fill="url(#spkG)"/>
      <polyline points={pts} fill="none" stroke={color} strokeWidth="1.5"/>
      <circle cx={parseFloat(pts.split(" ").slice(-1)[0].split(",")[0])} cy={parseFloat(pts.split(" ").slice(-1)[0].split(",")[1])} r="3" fill={color}/>
    </svg>
  );
}

// ── WORLD MAP ────────────────────────────────────────────────────
function WorldDots() {
  const pts=[{x:.15,y:.33,l:"NA",c:5},{x:.45,y:.27,l:"EU",c:4},{x:.51,y:.34,l:"DE",c:2},{x:.77,y:.41,l:"SG",c:2},{x:.83,y:.37,l:"JP",c:1},{x:.87,y:.63,l:"AU",c:1}];
  return (
    <div style={{position:"relative",width:"100%",height:160,background:"rgba(0,0,0,.2)",borderRadius:8,overflow:"hidden"}}>
      <svg width="100%" height="100%" viewBox="0 0 100 50" preserveAspectRatio="xMidYMid meet" style={{opacity:.12,position:"absolute",inset:0}}>
        {Array.from({length:80},(_,i)=><circle key={i} cx={2+i*1.2} cy={18+Math.sin(i*.35)*12} r=".4" fill="#475569"/>)}
        {Array.from({length:60},(_,i)=><circle key={i+80} cx={5+i*1.5} cy={28+Math.sin(i*.45)*8} r=".3" fill="#475569"/>)}
      </svg>
      {pts.map((p,i)=>(
        <div key={i} style={{position:"absolute",left:`${p.x*100}%`,top:`${p.y*100}%`,transform:"translate(-50%,-50%)"}}>
          <div style={{width:6+p.c*4,height:6+p.c*4,borderRadius:"50%",background:`radial-gradient(circle,${T.cyan},transparent)`,opacity:.8,animation:`pulse-ring ${1.5+i*.2}s ease-in-out infinite`}}/>
          <div style={{position:"absolute",top:-16,left:"50%",transform:"translateX(-50%)",fontSize:9,color:T.cyan,whiteSpace:"nowrap",fontFamily:T.mono}}>{p.l}</div>
        </div>
      ))}
      <div style={{position:"absolute",bottom:6,right:8,fontSize:9,color:T.textDD}}>{pts.reduce((a,p)=>a+p.c,0)} assets across {pts.length} regions</div>
    </div>
  );
}

// ── KNOWLEDGE GRAPH ──────────────────────────────────────────────
function KnowledgeGraph({data,onNode}) {
  const [hov,setHov]=useState(null);
  const [sel,setSel]=useState(null);
  const [filt,setFilt]=useState("all");

  const nodes=useMemo(()=>{
    if(!data) return [];
    const n=[],cx=500,cy=290;
    n.push({id:"org",label:data.domain,type:"org",icon:"🏢",x:cx,y:cy,sz:20,col:T.blue});
    data.subdomains.forEach((s,i)=>{
      const a=(i/data.subdomains.length)*Math.PI*2-Math.PI/2;
      n.push({id:`s${i}`,label:s.host.split(".")[0],type:"sub",icon:"🔍",x:cx+Math.cos(a)*190,y:cy+Math.sin(a)*155,sz:14,col:SEV.color(s.risk),risk:s.risk,full:s});
    });
    data.subdomains.slice(0,6).forEach((s,i)=>{
      const a=(i/6)*Math.PI*2;
      n.push({id:`ip${i}`,label:s.ip.slice(0,14),type:"ip",icon:"💻",x:cx+Math.cos(a)*320,y:cy+Math.sin(a)*240,sz:11,col:T.purple});
    });
    n.push({id:"cloud",label:data.cloud.primary,type:"cloud",icon:"☁️",x:cx+280,y:cy-175,sz:15,col:T.blue});
    data.cves.slice(0,3).forEach((c,i)=>{
      n.push({id:`cve${i}`,label:c.id.slice(0,14),type:"vuln",icon:"⚠️",x:cx-240-i*55,y:cy-110+i*90,sz:13,col:T.red,cve:c});
    });
    data.crownjewels.forEach((cj,i)=>{
      n.push({id:`cj${i}`,label:"👑",type:"crown",icon:"👑",x:cx+(i===0?-175:i===1?175:0),y:cy+210-i*30,sz:15,col:T.yellow,cj});
    });
    return n;
  },[data]);

  const edges=useMemo(()=>{
    const e=[],org=nodes.find(n=>n.id==="org"),cloud=nodes.find(n=>n.id==="cloud");
    nodes.filter(n=>n.type==="sub").forEach(s=>{if(org) e.push({from:org,to:s,col:SEV.color(s.risk||"LOW"),dash:false})});
    nodes.filter(n=>n.type==="ip").forEach((ip,i)=>{const s=nodes.find(n=>n.id===`s${i}`);if(s) e.push({from:s,to:ip,col:T.purpleD,dash:true})});
    if(cloud&&org) e.push({from:org,to:cloud,col:T.blueD,dash:false});
    nodes.filter(n=>n.type==="vuln").forEach((v,i)=>{const s=nodes.find(n=>n.id===`s${Math.min(i,data.subdomains.length-1)}`);if(s) e.push({from:s,to:v,col:T.red,dash:true})});
    return e;
  },[nodes]);

  const vis=filt==="all"?nodes:nodes.filter(n=>n.type===filt||n.type==="org");

  return (
    <div>
      <div className="row" style={{gap:6,marginBottom:12,flexWrap:"wrap"}}>
        {[["all","All"],["sub","Subdomains"],["ip","IPs"],["vuln","CVEs"],["cloud","Cloud"],["crown","Crown Jewels"]].map(([f,l])=>(
          <button key={f} className={`btn ${filt===f?"btn-c":"btn-g"}`} style={{padding:"4px 10px",fontSize:11}} onClick={()=>setFilt(f)}>{l}</button>
        ))}
        <span style={{marginLeft:"auto",fontSize:11,color:T.textDD}}>{nodes.length} nodes · {edges.length} edges</span>
      </div>
      <div style={{position:"relative",width:"100%",height:500,background:"rgba(0,0,0,.25)",borderRadius:8,overflow:"hidden"}}>
        <svg width="100%" height="100%" viewBox="0 0 1000 580" preserveAspectRatio="xMidYMid meet">
          <defs>
            <filter id="nGlow"><feGaussianBlur stdDeviation="4" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
          </defs>
          {edges.map((e,i)=>{
            const fv=filt==="all"||(nodes.find(n=>n.id===e.from.id)||{type:""}).type===filt||(nodes.find(n=>n.id===e.to.id)||{type:""}).type===filt||e.from.type==="org"||e.to.type==="org";
            return <line key={i} x1={e.from.x} y1={e.from.y} x2={e.to.x} y2={e.to.y} stroke={e.col} strokeWidth={hov===e.from.id||hov===e.to.id?2:.8} strokeOpacity={fv?.45:.08} strokeDasharray={e.dash?"5 3":""} style={{transition:"all .3s"}}/>;
          })}
          {nodes.map(n=>{
            const isVis=filt==="all"||n.type===filt||n.type==="org";
            return (
              <g key={n.id} transform={`translate(${n.x},${n.y})`}
                onMouseEnter={()=>setHov(n.id)} onMouseLeave={()=>setHov(null)}
                onClick={()=>{setSel(n);n.full&&onNode&&onNode(n)}}
                style={{cursor:"pointer",opacity:isVis?1:.12,transition:"opacity .3s"}}>
                <circle r={hov===n.id?n.sz+6:n.sz} fill="none" stroke={n.col} strokeWidth={hov===n.id?2:1} strokeOpacity={.55} style={{filter:hov===n.id?`drop-shadow(0 0 8px ${n.col})`:""}}/>
                <circle r={n.sz-2} fill={`${n.col}18`} stroke={n.col} strokeWidth="1.2"/>
                <text textAnchor="middle" dominantBaseline="central" fontSize={n.sz*.82}>{n.icon}</text>
                <text y={n.sz+11} textAnchor="middle" fontSize="8" fill={T.textD} fontFamily={T.mono}>{n.label.slice(0,14)}</text>
              </g>
            );
          })}
        </svg>
        {sel&&(
          <div className="glass" style={{position:"absolute",top:10,right:10,padding:14,minWidth:210,animation:"appear .2s ease-out"}}>
            <div className="row" style={{gap:8,marginBottom:8}}>
              <span style={{fontSize:18}}>{sel.icon}</span>
              <div><div style={{fontWeight:700,fontSize:12,color:sel.col}}>{sel.label}</div><div style={{fontSize:10,color:T.textD}}>{sel.type.toUpperCase()}</div></div>
              <button onClick={()=>setSel(null)} style={{marginLeft:"auto",background:"none",border:"none",color:T.textD,fontSize:16}}>×</button>
            </div>
            {sel.full&&<><div style={{fontSize:11,color:T.textD}}>IP: <span className="mono" style={{color:T.text}}>{sel.full.ip}</span></div><div style={{fontSize:11,color:T.textD,marginTop:3}}>Risk: <span style={{color:SEV.color(sel.full.risk)}}>{sel.full.risk}</span></div></>}
            {sel.cve&&<><div style={{fontSize:11,color:T.orange,fontFamily:T.mono,marginTop:4}}>{sel.cve.id}</div><div style={{fontSize:10,color:T.textD}}>CVSS {sel.cve.cvss} · EPSS {sel.cve.epss?(sel.cve.epss*100).toFixed(1)+"%":"—"}</div></>}
          </div>
        )}
        <div className="row" style={{position:"absolute",bottom:8,right:8,gap:10,fontSize:9,color:T.textDD}}>
          {[["Sub",T.cyan],["IP",T.purple],["CVE",T.red],["Cloud",T.blue],["Crown",T.yellow]].map(([l,c])=>(
            <span key={l} className="row" style={{gap:3}}><span style={{width:7,height:7,borderRadius:"50%",background:c,display:"inline-block"}}/>{l}</span>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── ATTACK GRAPH ─────────────────────────────────────────────────
function AttackGraph({data,activePath,activeStep}) {
  const nodes=useMemo(()=>{
    if(!data||activePath===null) return [];
    const path=data.attackPaths[activePath];
    if(!path) return [];
    const w=720;
    return path.steps.map((s,i)=>({
      id:i,label:s,x:40+i*(w-40)/(path.steps.length-1),y:150+(i%2)*80,
      active:i<=activeStep,
      col:i===0?T.textD:i===activeStep?T.red:i<activeStep?T.orange:T.textDD,
    }));
  },[data,activePath,activeStep]);

  if(activePath===null||!nodes.length) return (
    <div style={{height:260,display:"flex",alignItems:"center",justifyContent:"center",flexDirection:"column",gap:8,color:T.textDD}}>
      <div style={{fontSize:36}}>🎯</div>
      <div style={{fontSize:13}}>Select an attack path above to begin simulation</div>
    </div>
  );

  const path=data.attackPaths[activePath];
  return (
    <div>
      <svg width="100%" height="260" viewBox="0 0 760 260" preserveAspectRatio="xMidYMid meet">
        {nodes.slice(0,-1).map((n,i)=>{
          const nx=nodes[i+1];
          return (
            <g key={i}>
              <line x1={n.x} y1={n.y} x2={nx.x} y2={nx.y} stroke={i<activeStep?T.red:T.border} strokeWidth={i<activeStep?2:.8} strokeDasharray={i<activeStep?"":"4 2"} style={{transition:"stroke .4s"}}/>
              {i<activeStep&&<circle cx={n.x+(nx.x-n.x)*.5} cy={n.y+(nx.y-n.y)*.5} r={4} fill={T.red} style={{animation:"node-ping .8s ease-in-out infinite"}}/>}
            </g>
          );
        })}
        {nodes.map(n=>(
          <g key={n.id} transform={`translate(${n.x},${n.y})`}>
            {n.active&&<circle r={30} fill="none" stroke={n.col} strokeWidth=".5" strokeOpacity=".3" style={{animation:"pulse-ring 1.5s ease-in-out infinite"}}/>}
            <circle r={18} fill={n.active?`${n.col}22`:T.bg3} stroke={n.col} strokeWidth={n.active?2:1} style={{filter:n.active?`drop-shadow(0 0 8px ${n.col})`:""}}/>
            <text textAnchor="middle" dominantBaseline="central" fontSize="12">
              {n.id===0?"🌐":n.id===nodes.length-1?"💀":"🎯"}
            </text>
            <text y={28} textAnchor="middle" fontSize={8} fill={n.col} fontFamily={T.mono}>{n.label.slice(0,16)}</text>
          </g>
        ))}
        {activeStep>=0&&activeStep<nodes.length&&(
          <g transform={`translate(${nodes[activeStep].x-28},${nodes[activeStep].y-30})`}>
            <text fontSize="18" style={{animation:"float 1s ease-in-out infinite"}}>🕵️</text>
          </g>
        )}
      </svg>
      <div className="row" style={{gap:5,flexWrap:"wrap",marginTop:6}}>
        {path.mitre.map((t,i)=>(
          <span key={t} className="badge mono" style={{background:i<=activeStep?T.redDim:"transparent",color:i<=activeStep?T.red:T.textDD,border:`1px solid ${i<=activeStep?"rgba(255,51,102,.3)":T.border}`,transition:"all .3s"}}>{t}</span>
        ))}
      </div>
    </div>
  );
}

// ── COMPLIANCE HEATMAP ───────────────────────────────────────────
function ComplianceHeatmap({compliance}) {
  const fws=Object.keys(compliance);
  const mx=Math.max(...fws.map(f=>compliance[f].length));
  return (
    <div className="col" style={{gap:8}}>
      {fws.map(fw=>{
        const issues=compliance[fw];
        const heat=issues.length/mx;
        const col=heat>.7?T.red:heat>.4?T.orange:T.yellow;
        return (
          <div key={fw} className="glass" style={{padding:"12px 16px",borderLeft:`3px solid ${col}`}}>
            <div className="row" style={{justifyContent:"space-between",marginBottom:6}}>
              <span style={{fontWeight:700,fontSize:13,fontFamily:T.mono}}>{fw}</span>
              <span className="badge" style={{background:SEV.bg(heat>.7?"CRITICAL":heat>.4?"HIGH":"MEDIUM"),color:col,border:`1px solid ${col}22`}}>{issues.length} VIOLATIONS</span>
            </div>
            <div style={{height:4,background:"rgba(255,255,255,.06)",borderRadius:2,marginBottom:8}}>
              <div style={{height:"100%",width:`${heat*100}%`,background:`linear-gradient(90deg,${col}88,${col})`,borderRadius:2,transition:"width 1s"}}/>
            </div>
            {issues.slice(0,3).map((issue,i)=><div key={i} style={{fontSize:11,color:T.textD,padding:"2px 0"}}>· {issue}</div>)}
            {issues.length>3&&<div style={{fontSize:10,color:T.textDD,marginTop:2}}>+{issues.length-3} more violations</div>}
          </div>
        );
      })}
    </div>
  );
}

// ── AI COPILOT ───────────────────────────────────────────────────
function Copilot({data,visible,onClose}) {
  const [msgs,setMsgs]=useState([]);
  const [input,setInput]=useState("");
  const [loading,setLoading]=useState(false);
  const bottom=useRef(null);

  useEffect(()=>{
    if(visible&&msgs.length===0&&data) {
      setMsgs([{role:"a",text:`**SentinelX AI Copilot Active** — \`${data.domain}\`\n\nRisk Score: **${data.riskScore}/100** (${data.severity}) · ${data.findings.length} findings · ${data.attackPaths.length} attack paths\n\n**${data.findings.filter(f=>f.severity==="CRITICAL").length} critical issues** require immediate action. ${data.cves.filter(c=>c.kev).length} CISA KEV match detected.\n\nAsk me anything about your attack surface.`}]);
    }
  },[visible,data]);

  useEffect(()=>{bottom.current?.scrollIntoView({behavior:"smooth"})},[msgs]);

  const presets=[
    {icon:"🔴",label:"Critical risks",q:"What are my most critical vulnerabilities and their immediate business impact?"},
    {icon:"🎯",label:"Top attack path",q:"Walk me through the most dangerous attack path step by step with business impact."},
    {icon:"📊",label:"CEO briefing",q:"Generate a concise executive briefing for a non-technical CEO on our security posture."},
    {icon:"🔧",label:"Fix priorities",q:"Give me a prioritized remediation plan — what should we fix first, second, and third?"},
    {icon:"💀",label:"KEV CVEs",q:"Are there CISA Known Exploited Vulnerabilities in our infrastructure? Explain each one."},
    {icon:"🔌",label:"API security",q:"Analyze our API security posture — what data could be exfiltrated and how?"},
    {icon:"⚖️",label:"Compliance gaps",q:"What are the biggest compliance violations across PCI-DSS, GDPR, and ISO 27001?"},
    {icon:"👑",label:"Crown jewels",q:"Which assets are crown jewels and what's the blast radius if each is compromised?"},
  ];

  const send=useCallback(async(q)=>{
    const question=q||input.trim();
    if(!question||loading) return;
    setInput("");
    setMsgs(m=>[...m,{role:"u",text:question}]);
    setLoading(true);
    try {
      const ctx=JSON.stringify({
        domain:data.domain,riskScore:data.riskScore,severity:data.severity,
        criticalFindings:data.findings.filter(f=>f.severity==="CRITICAL"),
        allFindings:data.findings.slice(0,12),
        attackPaths:data.attackPaths.map(p=>({name:p.name,likelihood:p.likelihood,mitre:p.mitre,impact:p.impact,bizImpact:p.bizImpact,cvss:p.cvss,kev:p.kev,remediations:p.remediations})),
        cves:data.cves,apis:data.apis,jsSources:data.jsSources,
        emailSecurity:data.email,tlsGrade:data.tls,
        compliance:data.compliance,crownjewels:data.crownjewels,
        remediations:data.remediations,
        subdomains:data.subdomains.map(s=>({host:s.host,risk:s.risk,grade:s.grade,cloud:s.cloud,loginPages:s.loginPages,secrets:s.secrets,apis:s.apis})),
        passiveDns:data.passiveDns,riskHistory:data.riskHistory,
      },null,2).slice(0,7000);
      const resp=await fetch("https://api.anthropic.com/v1/messages",{
        method:"POST",headers:{"Content-Type":"application/json"},
        body:JSON.stringify({
          model:"claude-sonnet-4-6",max_tokens:1000,
          system:`You are SentinelX Security Copilot V5 — an expert AI security analyst embedded in an enterprise Attack Surface Management platform. You have been given the complete intelligence report for a real domain scan.

STRICT RULES:
1. Answer ONLY using the scan data provided — never invent CVEs, IPs, assets, or findings not in the data
2. Be precise, evidence-based, and actionable in every response
3. Use markdown formatting: **bold** for emphasis, bullet points for lists, \`code\` for technical values
4. For executive/CEO questions: use plain business language, translate technical terms, focus on €/$ impact
5. For technical questions: cite specific CVE IDs, CVSS scores, EPSS %, MITRE IDs, ports, and asset names
6. Always end with 1-3 concrete next actions
7. Keep responses focused — don't pad with unnecessary caveats`,
          messages:[{role:"user",content:`[SCAN DATA FOR ${data.domain}]\n${ctx}\n\n[QUESTION]\n${question}`}],
        }),
      });
      const result=await resp.json();
      const ans=result.content?.[0]?.text||"Unable to retrieve AI analysis. Check your connection.";
      setMsgs(m=>[...m,{role:"a",text:ans}]);
    } catch(e) {
      setMsgs(m=>[...m,{role:"a",text:`⚠️ Error connecting to AI: ${e.message}`}]);
    }
    setLoading(false);
  },[input,loading,data]);

  const render=t=>t
    .replace(/\*\*(.*?)\*\*/g,"<strong>$1</strong>")
    .replace(/`([^`]+)`/g,"<code style='background:rgba(0,212,255,.1);padding:1px 5px;border-radius:3px;font-size:11px;font-family:JetBrains Mono'>$1</code>")
    .replace(/\n•/g,"<br/>•").replace(/\n-/g,"<br/>-").replace(/\n/g,"<br/>");

  if(!visible) return null;
  return (
    <div style={{position:"fixed",right:0,top:0,bottom:0,width:430,background:T.bg1,borderLeft:`1px solid ${T.borderHi}`,display:"flex",flexDirection:"column",zIndex:1000,animation:"slide-r .3s ease-out",boxShadow:"-16px 0 60px rgba(0,0,0,.7)"}}>
      <div style={{padding:"14px 18px",borderBottom:`1px solid ${T.border}`,display:"flex",alignItems:"center",gap:10,flexShrink:0}}>
        <div style={{width:36,height:36,borderRadius:9,background:`linear-gradient(135deg,${T.blueD},${T.purpleD})`,display:"flex",alignItems:"center",justifyContent:"center",fontSize:18,boxShadow:`0 0 14px rgba(139,92,246,.5)`}}>🤖</div>
        <div><div style={{fontWeight:800,fontSize:14}}>Security Copilot</div><div style={{fontSize:11,color:T.green}}>● Claude-Powered · Evidence-Grounded</div></div>
        <button onClick={onClose} style={{marginLeft:"auto",background:"none",border:"none",color:T.textD,fontSize:22}}>×</button>
      </div>
      <div style={{flex:1,overflowY:"auto",padding:14,display:"flex",flexDirection:"column",gap:10}}>
        {msgs.map((m,i)=>(
          <div key={i} style={{display:"flex",flexDirection:"column",alignItems:m.role==="u"?"flex-end":"flex-start"}}>
            <div style={{maxWidth:"92%",padding:"10px 14px",borderRadius:m.role==="u"?"12px 12px 2px 12px":"2px 12px 12px 12px",
              background:m.role==="u"?`linear-gradient(135deg,${T.blueD},${T.purpleD})`:T.bg3,
              border:m.role==="u"?"none":`1px solid ${T.border}`,fontSize:13,lineHeight:1.65,color:T.text,
            }} dangerouslySetInnerHTML={{__html:render(m.text)}}/>
          </div>
        ))}
        {loading&&(
          <div style={{display:"flex",gap:5,padding:"10px 14px",background:T.bg3,borderRadius:"2px 12px 12px 12px",width:"fit-content"}}>
            {[0,1,2].map(i=><div key={i} style={{width:7,height:7,borderRadius:"50%",background:T.cyan,animation:`pulse-ring 1s ease-in-out ${i*.2}s infinite`}}/>)}
          </div>
        )}
        <div ref={bottom}/>
      </div>
      <div style={{padding:"8px 12px",borderTop:`1px solid ${T.border}`,display:"flex",flexWrap:"wrap",gap:4,flexShrink:0}}>
        {presets.map((p,i)=>(
          <button key={i} onClick={()=>send(p.q)}
            style={{background:T.bg3,border:`1px solid ${T.border}`,color:T.textD,borderRadius:20,padding:"4px 9px",fontSize:11,cursor:"pointer",display:"flex",alignItems:"center",gap:4}}>
            <span>{p.icon}</span><span>{p.label}</span>
          </button>
        ))}
      </div>
      <div style={{padding:"10px 14px",borderTop:`1px solid ${T.border}`,display:"flex",gap:8,flexShrink:0}}>
        <input value={input} onChange={e=>setInput(e.target.value)} onKeyDown={e=>e.key==="Enter"&&!e.shiftKey&&send()}
          placeholder="Ask about your attack surface…"
          style={{flex:1,background:T.bg3,border:`1px solid ${T.border}`,borderRadius:8,padding:"9px 12px",color:T.text,fontSize:13}}/>
        <button onClick={()=>send()} className="btn btn-p" style={{padding:"9px 14px"}} disabled={loading}>{loading?"…":"↑"}</button>
      </div>
    </div>
  );
}

// ── ASSET PANEL ──────────────────────────────────────────────────
function AssetPanel({asset,data,onClose}) {
  if(!asset?.full) return null;
  const s=asset.full;
  const findings=data?.findings?.filter(f=>f.asset?.includes(s.host.split(".")[0]))||[];
  return (
    <div style={{position:"fixed",right:0,top:0,bottom:0,width:370,background:T.bg1,borderLeft:`1px solid ${T.borderHi}`,zIndex:999,overflowY:"auto",animation:"slide-r .25s ease-out",boxShadow:"-8px 0 48px rgba(0,0,0,.6)"}}>
      <div style={{padding:"14px 18px",borderBottom:`1px solid ${T.border}`,position:"sticky",top:0,background:T.bg1,zIndex:1}}>
        <div className="row" style={{gap:10}}>
          <span style={{fontSize:20}}>🖥️</span>
          <div>
            <div style={{fontWeight:700,fontSize:13,color:T.cyan,fontFamily:T.mono}}>{s.host}</div>
            <span className="badge" style={{background:SEV.bg(s.risk),color:SEV.color(s.risk),border:`1px solid ${SEV.border(s.risk)}`}}>{s.risk} RISK</span>
          </div>
          <button onClick={onClose} style={{marginLeft:"auto",background:"none",border:"none",color:T.textD,fontSize:20}}>×</button>
        </div>
      </div>
      <div style={{padding:14,display:"flex",flexDirection:"column",gap:10}}>
        <div className="glass" style={{padding:14}}>
          <div style={{fontSize:10,color:T.textDD,letterSpacing:".12em",marginBottom:10}}>INFRASTRUCTURE</div>
          {[["IP",s.ip],["ASN",s.asn],["Location",s.country+" · "+s.city],["Cloud",s.cloud||"On-Premise"],["WAF",s.waf||"None"],["TLS Grade",s.grade],["Screenshot",s.screenshotMeta?.title]].filter(([,v])=>v).map(([k,v])=>(
            <div key={k} className="row" style={{justifyContent:"space-between",padding:"5px 0",borderBottom:`1px solid ${T.border}`}}>
              <span style={{fontSize:12,color:T.textD}}>{k}</span>
              <span style={{fontSize:11,fontFamily:k==="IP"||k==="TLS Grade"?T.mono:"inherit",color:k==="TLS Grade"?(s.grade==="A+"||s.grade==="A"?T.green:s.grade==="B"?T.yellow:T.red):T.text}}>{v}</span>
            </div>
          ))}
        </div>
        {s.ports?.length>0&&(
          <div className="glass" style={{padding:14}}>
            <div style={{fontSize:10,color:T.textDD,letterSpacing:".12em",marginBottom:8}}>OPEN PORTS ({s.ports.length})</div>
            <div className="row" style={{flexWrap:"wrap",gap:5}}>
              {s.ports.map(p=><span key={p} className="badge mono" style={{background:"rgba(0,212,255,.08)",color:T.cyan,border:"1px solid rgba(0,212,255,.2)"}}>{p}</span>)}
            </div>
          </div>
        )}
        {s.techs?.length>0&&(
          <div className="glass" style={{padding:14}}>
            <div style={{fontSize:10,color:T.textDD,letterSpacing:".12em",marginBottom:8}}>TECHNOLOGIES</div>
            <div className="row" style={{flexWrap:"wrap",gap:5}}>
              {s.techs.map(t=><span key={t} className="badge" style={{background:T.purpleDim,color:T.purple,border:"1px solid rgba(139,92,246,.25)"}}>{t}</span>)}
            </div>
          </div>
        )}
        <div className="glass" style={{padding:12}}>
          <div style={{fontSize:10,color:T.textDD,letterSpacing:".12em",marginBottom:5}}>BUSINESS FUNCTION</div>
          <div style={{fontSize:13,fontWeight:600,color:T.blue}}>💼 {s.hasBusiness}</div>
        </div>
        {s.loginPages?.length>0&&(
          <div className="glass glow-r" style={{padding:14}}>
            <div style={{fontSize:10,color:T.textDD,letterSpacing:".12em",marginBottom:8}}>⚠️ LOGIN PAGES ({s.loginPages.length})</div>
            {s.loginPages.map((l,i)=>(
              <div key={i} style={{padding:"6px 0",borderBottom:`1px solid ${T.border}`}}>
                <div style={{fontSize:11,fontFamily:T.mono,color:T.orange,marginBottom:4}}>{l.url}</div>
                <div className="row" style={{gap:5}}>
                  <span className="badge" style={{background:T.orangeDim,color:T.orange,border:"1px solid rgba(255,140,0,.3)"}}>{l.authType.toUpperCase()}</span>
                  {l.defaultCredRisk&&<span className="badge" style={{background:T.redDim,color:T.red,border:"1px solid rgba(255,51,102,.3)"}}>DEFAULT CRED RISK</span>}
                </div>
              </div>
            ))}
          </div>
        )}
        {s.secrets?.length>0&&(
          <div className="glass glow-r" style={{padding:14}}>
            <div style={{fontSize:10,color:T.textDD,letterSpacing:".12em",marginBottom:8}}>🗝️ SECRETS EXPOSED</div>
            {s.secrets.map((sec,i)=>(
              <div key={i} style={{padding:"6px 0",borderBottom:`1px solid ${T.border}`}}>
                <div className="row" style={{gap:6,marginBottom:3}}>
                  <span className="badge" style={{background:SEV.bg(sec.severity),color:SEV.color(sec.severity),border:`1px solid ${SEV.border(sec.severity)}`}}>{sec.severity}</span>
                  <span style={{fontSize:11,fontFamily:T.mono,color:T.textD}}>{sec.path}</span>
                </div>
                <div style={{fontSize:11,color:T.text}}>{sec.desc}</div>
              </div>
            ))}
          </div>
        )}
        {s.apis?.length>0&&(
          <div className="glass" style={{padding:14}}>
            <div style={{fontSize:10,color:T.textDD,letterSpacing:".12em",marginBottom:8}}>🔌 APIs ({s.apis.length})</div>
            {s.apis.map((api,i)=>(
              <div key={i} style={{padding:"6px 0",borderBottom:`1px solid ${T.border}`}}>
                <div className="row" style={{gap:6,marginBottom:4}}>
                  <span className="badge" style={{background:SEV.bg(api.risk),color:SEV.color(api.risk),border:`1px solid ${SEV.border(api.risk)}`}}>{api.risk}</span>
                  <span style={{fontSize:11,fontFamily:T.mono,color:T.cyan}}>{api.path}</span>
                </div>
                <div className="row" style={{gap:5}}>
                  {!api.auth&&<span className="badge" style={{background:T.redDim,color:T.red,border:"1px solid rgba(255,51,102,.3)"}}>NO AUTH</span>}
                  {api.cors==="*"&&<span className="badge" style={{background:T.orangeDim,color:T.orange,border:"1px solid rgba(255,140,0,.3)"}}>CORS *</span>}
                  {api.introspection&&<span className="badge" style={{background:T.purpleDim,color:T.purple,border:"1px solid rgba(139,92,246,.3)"}}>INTROSPECTION</span>}
                </div>
              </div>
            ))}
          </div>
        )}
        {findings.length>0&&(
          <div className="glass" style={{padding:14}}>
            <div style={{fontSize:10,color:T.textDD,letterSpacing:".12em",marginBottom:8}}>RELATED FINDINGS ({findings.length})</div>
            {findings.map((f,i)=>(
              <div key={i} className="row" style={{gap:8,padding:"5px 0",borderBottom:`1px solid ${T.border}`}}>
                <span className="badge" style={{background:SEV.bg(f.severity),color:SEV.color(f.severity),border:`1px solid ${SEV.border(f.severity)}`,flexShrink:0}}>{SEV.short(f.severity)}</span>
                <span style={{fontSize:11,color:T.text}}>{f.issue}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ── NOTIFICATION CENTER ──────────────────────────────────────────
function NotifCenter({data,open,onClose}) {
  const notifs=useMemo(()=>data?[
    {sev:"CRITICAL",msg:`Admin panel default credential risk — admin.${data.domain}`,time:"just now"},
    {sev:"CRITICAL",msg:`Exposed .env file with AWS credentials — dev.${data.domain}`,time:"just now"},
    {sev:"HIGH",msg:`SSL expires in 12 days — mail.${data.domain}`,time:"just now"},
    {sev:"HIGH",msg:`GraphQL introspection ON — schema publicly accessible`,time:"just now"},
    {sev:"HIGH",msg:`Open redirect vulnerability — phishing vector confirmed`,time:"just now"},
    {sev:"MEDIUM",msg:`DMARC not enforced (p=none) — phishing via ${data.domain} possible`,time:"1m ago"},
    {sev:"MEDIUM",msg:`CORS wildcard (*) on /api/v2 — cross-origin data access`,time:"1m ago"},
    {sev:"LOW",msg:`Server version disclosed in X-Powered-By header`,time:"2m ago"},
  ]:[],[data]);
  if(!open) return null;
  return (
    <div className="glass-hi" style={{position:"absolute",right:0,top:"calc(100% + 8px)",width:340,zIndex:300,padding:14,maxHeight:460,overflowY:"auto",animation:"appear .2s ease-out"}}>
      <div className="row" style={{justifyContent:"space-between",marginBottom:12}}>
        <div style={{fontWeight:700,fontSize:13}}>Notifications</div>
        <span className="badge" style={{background:T.redDim,color:T.red,border:"1px solid rgba(255,51,102,.3)"}}>{notifs.length} NEW</span>
      </div>
      {notifs.map((n,i)=>(
        <div key={i} style={{padding:"8px 0",borderBottom:`1px solid ${T.border}`,display:"flex",gap:8}}>
          <span>{SEV.icon(n.sev)}</span>
          <div><div style={{fontSize:12,lineHeight:1.4}}>{n.msg}</div><div style={{fontSize:10,color:T.textDD,marginTop:2}}>{n.time}</div></div>
        </div>
      ))}
    </div>
  );
}

// ── SCAN VIEW ────────────────────────────────────────────────────
function ScanView({domain,onComplete}) {
  const [stages,setStages]=useState(PIPELINE.map(s=>({...s,status:"pending"})));
  const [ctrs,setCtrs]=useState({sub:0,ip:0,cert:0,port:0,tech:0,node:0});
  const [phase,setPhase]=useState(1);
  const [log,setLog]=useState([]);
  const si=useRef(0);
  const logEnd=useRef(null);
  useEffect(()=>{logEnd.current?.scrollIntoView({behavior:"smooth"})},[log]);

  useEffect(()=>{
    const dur=7000;
    const delay=dur/PIPELINE.length;
    const logMsgs={
      dns:`[DNS] Resolving ${domain} — A/AAAA/MX/TXT/NS/SOA/CAA/SRV records collected`,
      sub:`[ENUM] crt.sh→14 | certspotter→8 | OTX→6 | bruteforce→${Math.floor(Math.random()*12)+6} subdomains`,
      pdns:`[PDNS] HackerTarget history → 6 historical subdomains discovered`,
      ct:`[CT] Certificate transparency timeline → 14 CT log entries`,
      rdns:`[RDNS] Reverse DNS resolved for ${Math.floor(Math.random()*8)+6} IP addresses`,
      asn:`[ASN] IP range ownership → Amazon.com Inc. (AS16509) primary`,
      infra:`[INFRA] ${Math.floor(Math.random()*12)+8} assets enriched with infra intelligence`,
      cloud:`[CLOUD] Provider fingerprinted → AWS (primary), GCP (secondary)`,
      waf:`[WAF] Cloudflare WAF detected on ${Math.floor(Math.random()*4)+3} assets`,
      geoip:`[GEOIP] Assets mapped across US/EU/SG/JP regions`,
      whois:`[WHOIS] Registration data, expiry, nameservers collected`,
      http:`[HTTP] HTTP fingerprinting on ${Math.floor(Math.random()*10)+8} assets complete`,
      tech:`[TECH] Technology stack detected: Nginx, React, Node.js, PostgreSQL, Cloudflare`,
      ports:`[PORTS] Open ports: 80,443 (all) | 8080,8443 (api,admin) | 25,587 (mail)`,
      ssl:`[TLS] Grades: A+(2) A(4) B(3) C(1) F(1) — expiry alert on mail server`,
      hdr:`[HDR] HSTS missing on 6 assets | X-Frame-Options absent on auth`,
      email:`[EMAIL] SPF: WARN | DKIM: FAIL | DMARC: p=none (not enforced)`,
      csp:`[CSP] unsafe-inline scripts detected on www.${domain}`,
      login:`[LOGIN] ${Math.floor(Math.random()*3)+2} login pages with default credential risk`,
      secret:`[SECRET] CRITICAL: /.env exposed on dev.${domain} — AWS_ACCESS_KEY detected!`,
      js:`[JS] 6 secrets in app.bundle.js: AWS key, Stripe pk_live, Firebase key`,
      api:`[API] GraphQL introspection ON | /api/v2/users unauthenticated | /actuator/env exposed`,
      bucket:`[BUCKET] Public S3 bucket check complete — 1 potentially public bucket`,
      vuln:`[VULN] NVD lookup → 4 CVEs | CISA KEV matches: 2 (CVE-2024-21887, CVE-2023-3519)`,
      kev:`[KEV] ⚠️ ACTIVELY EXPLOITED: CVE-2024-21887 EPSS 84.7% · CVE-2023-3519 EPSS 91.2%`,
      graph:`[GRAPH] Nodes: ${Math.floor(Math.random()*20)+40} | Edges: ${Math.floor(Math.random()*30)+80} | 4 clusters`,
      corr:`[CORR] Asset correlation complete — 3 shared-IP clusters, 2 shared-cert groups`,
      crown:`[CROWN] 3 crown jewels identified: auth, api, admin`,
      biz:`[BIZ] Business function mapping: Customer Portal, DevOps, Email Infra, Admin Panel`,
      comply:`[COMPLY] PCI-DSS:3 | GDPR:3 | ISO27001:3 | NIST:4 | OWASP:4 violations`,
      risk:`[RISK] Risk score computed → ${Math.floor(Math.random()*40)+40}/100 | Severity: HIGH`,
      attack:`[ATTACK] 5 attack chains constructed from evidence-only graph data`,
      path:`[PATH] Attack paths CVE-enriched with EPSS and KEV data | Top path: 87% likelihood`,
      hist:`[HIST] Historical comparison: 2 new assets, 1 resolved finding, risk trend ↑3pts`,
      trend:`[TREND] 5-scan risk trend computed — current: highest in 3 months`,
      rem:`[REM] 6-item remediation plan generated, ranked by risk reduction`,
      ai:`[AI] Claude analyzing ${domain} — generating intelligence report`,
      exec:`[EXEC] Executive summary generated — assessment complete for ${domain}`,
    };
    const advance=()=>{
      const i=si.current;
      if(i>=PIPELINE.length){setTimeout(()=>onComplete(generateData(domain)),600);return;}
      const stage=PIPELINE[i];
      setPhase(stage.ph);
      setStages(prev=>prev.map((s,idx)=>idx===i?{...s,status:"active"}:s));
      const msg=logMsgs[stage.id]||`[${stage.id.toUpperCase()}] ${stage.label} complete`;
      setLog(prev=>[...prev,{ph:stage.ph,msg,col:PHASE_COLORS[stage.ph]}]);
      const prog=(i+1)/PIPELINE.length;
      setCtrs({sub:Math.floor(prog*14),ip:Math.floor(prog*8),cert:Math.floor(prog*13),port:Math.floor(prog*36),tech:Math.floor(prog*12),node:Math.floor(prog*48)});
      setTimeout(()=>{setStages(prev=>prev.map((s,idx)=>idx===i?{...s,status:"done"}:s));si.current=i+1;setTimeout(advance,55);},delay-55);
    };
    setTimeout(advance,350);
  },[domain]);

  return (
    <div style={{minHeight:"100vh",display:"flex",alignItems:"center",justifyContent:"center",padding:20}}>
      <div style={{width:"100%",maxWidth:1200,display:"grid",gridTemplateColumns:"300px 1fr 270px",gap:18}}>
        {/* Left */}
        <div className="col" style={{alignItems:"center",gap:14}}>
          <div style={{textAlign:"center"}}>
            <div style={{fontSize:10,color:T.cyanD,letterSpacing:".28em",marginBottom:3}}>TARGET ACQUIRED</div>
            <div style={{fontSize:16,fontWeight:800,color:T.cyan,fontFamily:T.mono,animation:"glow-pulse 2s infinite"}}>{domain}</div>
          </div>
          <Globe size={250} radar={true}/>
          <div style={{padding:"5px 14px",borderRadius:6,background:`rgba(255,255,255,.04)`,border:`1px solid ${PHASE_COLORS[phase]}33`,fontSize:10,letterSpacing:".18em",color:PHASE_COLORS[phase],fontWeight:700}}>PHASE {phase} — {PHASE_LABELS[phase]}</div>
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:7,width:"100%"}}>
            {[["Subdomains",ctrs.sub,T.cyan],["IPs",ctrs.ip,T.blue],["Certificates",ctrs.cert,T.purple],["Open Ports",ctrs.port,T.green],["Technologies",ctrs.tech,T.orange],["Graph Nodes",ctrs.node,T.cyan]].map(([l,v,c])=>(
              <div key={l} className="glass" style={{padding:"9px 11px"}}>
                <div style={{fontSize:20,fontWeight:800,color:c,fontFamily:T.mono}}>{v}</div>
                <div style={{fontSize:9,color:T.textDD,marginTop:2}}>{l}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Center: pipeline */}
        <div className="glass" style={{padding:14,overflowY:"auto",maxHeight:600}}>
          <div style={{fontSize:10,color:T.textDD,letterSpacing:".18em",marginBottom:10}}>INTELLIGENCE PIPELINE — {PIPELINE.length} STAGES</div>
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:1}}>
            {stages.map((s,i)=>{
              const phCol=PHASE_COLORS[s.ph];
              const isActive=s.status==="active";
              return (
                <div key={s.id} style={{display:"flex",alignItems:"center",gap:7,padding:"5px 8px",borderBottom:"1px solid rgba(26,42,74,.3)",opacity:s.status==="pending"?.28:1,transition:"opacity .3s",background:isActive?`${phCol}0d`:"transparent"}}>
                  <div style={{width:14,flexShrink:0,textAlign:"center"}}>
                    {s.status==="done"&&<span style={{color:T.green,fontSize:11}}>✓</span>}
                    {isActive&&<div style={{width:11,height:11,border:`2px solid ${phCol}`,borderTopColor:"transparent",borderRadius:"50%",animation:"spin .6s linear infinite",margin:"0 auto"}}/>}
                    {s.status==="pending"&&<span style={{color:T.textDD,fontSize:9}}>○</span>}
                  </div>
                  <span style={{fontSize:11}}>{s.icon}</span>
                  <span style={{fontSize:10,color:isActive?phCol:s.status==="done"?T.textD:T.textDD,fontWeight:isActive?600:400,flex:1,lineHeight:1.3}}>{s.label}</span>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right: log */}
        <div className="glass" style={{padding:14,overflowY:"auto",maxHeight:600}}>
          <div style={{fontSize:10,color:T.textDD,letterSpacing:".18em",marginBottom:10}}>LIVE INTEL LOG</div>
          <div className="col" style={{gap:3}}>
            {log.map((l,i)=>(
              <div key={i} style={{fontSize:9,color:l.col,fontFamily:T.mono,lineHeight:1.55,opacity:.88,animation:"appear .2s ease-out"}}>{l.msg}</div>
            ))}
            <div ref={logEnd}/>
          </div>
        </div>
      </div>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════
// DASHBOARD
// ════════════════════════════════════════════════════════════════════
function Dashboard({data,onNewScan}) {
  const [tab,setTab]=useState("overview");
  const [copilot,setCopilot]=useState(false);
  const [assetPanel,setAssetPanel]=useState(null);
  const [notifOpen,setNotifOpen]=useState(false);
  const [simPath,setSimPath]=useState(null);
  const [simStep,setSimStep]=useState(-1);
  const [simPlaying,setSimPlaying]=useState(false);
  const [simSpeed,setSimSpeed]=useState(900);
  const simTimer=useRef(null);
  const sevColor=SEV.color(data.severity);
  const panelOpen=copilot||assetPanel;

  const startSim=useCallback((idx)=>{
    setSimPath(idx);setSimStep(-1);setSimPlaying(true);
    clearInterval(simTimer.current);
    let step=-1;
    const path=data.attackPaths[idx];
    simTimer.current=setInterval(()=>{
      step++;setSimStep(step);
      if(step>=path.steps.length-1){clearInterval(simTimer.current);setSimPlaying(false);}
    },simSpeed);
  },[data,simSpeed]);

  const pauseSim=()=>{clearInterval(simTimer.current);setSimPlaying(false)};
  const resetSim=()=>{clearInterval(simTimer.current);setSimStep(-1);setSimPlaying(false)};
  useEffect(()=>()=>clearInterval(simTimer.current),[]);

  const TABS=[
    {id:"overview",icon:"🏠",l:"Overview"},{id:"graph",icon:"🕸️",l:"Knowledge Graph"},
    {id:"assets",icon:"🖥️",l:"Assets"},{id:"findings",icon:"⚠️",l:"Findings"},
    {id:"attack",icon:"🎯",l:"Attack Sim"},{id:"vuln",icon:"💀",l:"Vulnerabilities"},
    {id:"api",icon:"🔌",l:"API Discovery"},{id:"js",icon:"📝",l:"JS Intel"},
    {id:"email",icon:"✉️",l:"Email Sec"},{id:"tls",icon:"🔐",l:"TLS/SSL"},
    {id:"secrets",icon:"🗝️",l:"Secrets"},{id:"comply",icon:"⚖️",l:"Compliance"},
    {id:"history",icon:"📅",l:"History"},{id:"remediate",icon:"🔨",l:"Remediation"},
    {id:"report",icon:"📊",l:"Exec Report"},
  ];

  return (
    <div style={{minHeight:"100vh",paddingRight:panelOpen?"430px":"0",transition:"padding-right .3s"}}>
      {/* NAV */}
      <nav style={{position:"sticky",top:0,zIndex:200,background:"rgba(3,6,15,.97)",backdropFilter:"blur(20px)",borderBottom:`1px solid ${T.border}`,padding:"0 18px",display:"flex",alignItems:"center",height:50,gap:10}}>
        <div className="row" style={{gap:8,marginRight:12,flexShrink:0}}>
          <div style={{width:26,height:26,background:`linear-gradient(135deg,${T.blueD},${T.purpleD})`,borderRadius:6,display:"flex",alignItems:"center",justifyContent:"center",fontSize:13}}>🛡️</div>
          <span style={{fontWeight:900,fontSize:13}}>SentinelX</span>
          <span className="badge mono" style={{background:T.bg3,color:T.textDD,fontSize:9,padding:"1px 5px"}}>V5</span>
        </div>
        <div style={{flex:1,overflowX:"auto",display:"flex",gap:1}}>
          {TABS.map(t=>(
            <button key={t.id} className={`tab ${tab===t.id?"on":""}`} onClick={()=>setTab(t.id)}>
              <span style={{marginRight:4}}>{t.icon}</span>{t.l}
            </button>
          ))}
        </div>
        <div className="row" style={{gap:8,flexShrink:0}}>
          <div className="badge" style={{background:SEV.bg(data.severity),color:sevColor,border:`1px solid ${SEV.border(data.severity)}`,padding:"4px 10px",fontWeight:800}}>{data.severity} · {data.riskScore}/100</div>
          <div style={{position:"relative"}}>
            <button onClick={()=>setNotifOpen(o=>!o)} style={{background:"none",border:"none",position:"relative",cursor:"pointer",fontSize:16}}>
              🔔<span style={{position:"absolute",top:-4,right:-5,width:15,height:15,background:T.red,borderRadius:"50%",fontSize:8,color:"#fff",display:"flex",alignItems:"center",justifyContent:"center",fontWeight:700}}>8</span>
            </button>
            <NotifCenter data={data} open={notifOpen} onClose={()=>setNotifOpen(false)}/>
          </div>
          <button onClick={()=>{setCopilot(o=>!o);setAssetPanel(null)}} className="btn btn-p" style={{padding:"5px 12px",fontSize:12}}>🤖 Copilot</button>
          <button onClick={onNewScan} className="btn btn-g" style={{padding:"5px 10px",fontSize:11}}>+ Scan</button>
        </div>
      </nav>

      <div style={{padding:"18px 22px"}}>

        {/* ══ OVERVIEW ══ */}
        {tab==="overview"&&(
          <div className="anim">
            <div style={{marginBottom:3,fontSize:10,color:T.textDD,letterSpacing:".18em"}}>ATTACK SURFACE INTELLIGENCE — {new Date(data.scanTime).toLocaleString()}</div>
            <h1 style={{fontSize:22,fontWeight:900,marginBottom:18}}><span style={{color:T.cyan,fontFamily:T.mono}}>{data.domain}</span></h1>
            {/* KPIs */}
            <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(120px,1fr))",gap:9,marginBottom:18}}>
              {[{l:"Subdomains",v:data.totalAssets,i:"🔍",c:T.cyan},{l:"Open Ports",v:data.totalPorts,i:"🚪",c:T.purple},{l:"Certificates",v:data.totalCerts,i:"📜",c:T.blue},{l:"Technologies",v:data.totalTechs,i:"⚙️",c:T.orange},{l:"Findings",v:data.findings.length,i:"⚠️",c:T.red},{l:"Attack Paths",v:data.attackPaths.length,i:"🎯",c:T.red},{l:"Graph Nodes",v:data.graphNodes,i:"🕸️",c:T.cyan},{l:"Graph Edges",v:data.graphEdges,i:"🔗",c:T.blue}].map(k=>(
                <div key={k.l} className="glass" style={{padding:"12px 10px",textAlign:"center"}}>
                  <div style={{fontSize:16,marginBottom:3}}>{k.i}</div>
                  <div style={{fontSize:22,fontWeight:800,color:k.c,fontFamily:T.mono}}><Counter to={k.v}/></div>
                  <div style={{fontSize:9,color:T.textDD,marginTop:1}}>{k.l}</div>
                </div>
              ))}
            </div>
            {/* Main 3-col */}
            <div style={{display:"grid",gridTemplateColumns:"200px 1fr 300px",gap:14,marginBottom:14}}>
              <div className="glass glow-c col" style={{padding:16,alignItems:"center",gap:6}}>
                <div style={{fontSize:9,color:T.textDD,letterSpacing:".15em"}}>RISK SCORE</div>
                <RiskGauge score={data.riskScore} size={170}/>
                <span className="badge" style={{background:SEV.bg(data.severity),color:sevColor,border:`1px solid ${SEV.border(data.severity)}`,padding:"3px 10px"}}>{data.severity}</span>
                <Sparkline data={data.riskHistory.map(r=>r.score)} color={sevColor} w={140}/>
                <div style={{fontSize:9,color:T.textDD}}>5-scan risk trend</div>
              </div>
              <div className="glass" style={{padding:16}}>
                <div style={{fontSize:9,color:T.textDD,letterSpacing:".15em",marginBottom:10}}>FINDINGS — {data.findings.length} TOTAL</div>
                <div className="row" style={{gap:0,height:6,borderRadius:3,overflow:"hidden",marginBottom:10}}>
                  {["CRITICAL","HIGH","MEDIUM","LOW"].map(s=>{const c=data.findings.filter(f=>f.severity===s).length;return <div key={s} style={{width:`${(c/data.findings.length)*100}%`,background:SEV.color(s),transition:"width 1s"}}/>})}
                </div>
                <div className="row" style={{gap:14,marginBottom:10}}>
                  {["CRITICAL","HIGH","MEDIUM","LOW"].map(s=>(
                    <div key={s} className="row" style={{gap:4}}>
                      <div style={{width:7,height:7,borderRadius:"50%",background:SEV.color(s)}}/>
                      <span style={{fontSize:13,color:SEV.color(s),fontWeight:700}}>{data.findings.filter(f=>f.severity===s).length}</span>
                      <span style={{fontSize:9,color:T.textDD}}>{s.slice(0,4)}</span>
                    </div>
                  ))}
                </div>
                {data.findings.slice(0,6).map((f,i)=>(
                  <div key={i} style={{display:"flex",gap:8,padding:"6px 0",borderBottom:`1px solid ${T.border}`}}>
                    <span className="badge" style={{background:SEV.bg(f.severity),color:SEV.color(f.severity),border:`1px solid ${SEV.border(f.severity)}`,flexShrink:0}}>{SEV.short(f.severity)}</span>
                    <div style={{flex:1}}>
                      <div style={{fontSize:12}}>{f.issue}</div>
                      {f.cve&&<div style={{fontSize:10,color:T.orange,fontFamily:T.mono,marginTop:1}}>🔴 {f.cve} CVSS {f.cvss} EPSS {(f.epss*100).toFixed(0)}%</div>}
                    </div>
                  </div>
                ))}
              </div>
              <div className="col" style={{gap:10}}>
                <div className="glass" style={{padding:14}}>
                  <div style={{fontSize:9,color:T.textDD,letterSpacing:".15em",marginBottom:8}}>INFRASTRUCTURE</div>
                  {[["Cloud",data.cloud.primary],["WAF",data.waf||"❌ None"],["DNS SEC",data.dns.dnssec?"✓ Enabled":"❌ Disabled"],["Zone Xfer",data.dns.zoneTransfer?"⚠️ VULNERABLE":"✓ Secure"],["TLS Grade",data.tls.overallGrade],["Email Risk",data.email.riskScore+"/100"]].map(([k,v])=>(
                    <div key={k} className="row" style={{justifyContent:"space-between",padding:"4px 0",borderBottom:`1px solid ${T.border}`}}>
                      <span style={{fontSize:11,color:T.textD}}>{k}</span>
                      <span style={{fontSize:11,fontFamily:T.mono,color:v?.toString().includes("❌")||v?.toString().includes("⚠️")?T.red:T.text}}>{v}</span>
                    </div>
                  ))}
                </div>
                <div className="glass glow-p" style={{padding:14}}>
                  <div style={{fontSize:9,color:T.textDD,letterSpacing:".15em",marginBottom:8}}>👑 CROWN JEWELS</div>
                  {data.crownjewels.map((cj,i)=>(
                    <div key={i} style={{padding:"5px 0",borderBottom:`1px solid ${T.border}`}}>
                      <div style={{fontSize:11,fontFamily:T.mono,color:T.yellow}}>{cj.host}</div>
                      <div style={{fontSize:10,color:T.textD,marginTop:1,lineHeight:1.3}}>{cj.reason.slice(0,65)}…</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
            {/* World */}
            <div className="glass" style={{padding:16,marginBottom:14}}>
              <div style={{fontSize:9,color:T.textDD,letterSpacing:".15em",marginBottom:10}}>🌍 GLOBAL ASSET DISTRIBUTION</div>
              <WorldDots/>
            </div>
            {/* Top paths */}
            <div className="glass glow-r" style={{padding:16}}>
              <div className="row" style={{justifyContent:"space-between",marginBottom:10}}>
                <div style={{fontSize:9,color:T.textDD,letterSpacing:".15em"}}>TOP ATTACK PATHS</div>
                <button onClick={()=>setTab("attack")} className="btn btn-d" style={{padding:"4px 10px",fontSize:11}}>Simulate →</button>
              </div>
              {data.attackPaths.map((p,i)=>(
                <div key={i} style={{display:"flex",gap:10,padding:"9px 0",borderBottom:`1px solid ${T.border}`}}>
                  <div style={{width:28,height:28,borderRadius:6,background:T.redDim,border:"1px solid rgba(255,51,102,.3)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:13,fontWeight:800,color:T.red,fontFamily:T.mono,flexShrink:0}}>{p.rank}</div>
                  <div style={{flex:1}}>
                    <div style={{fontSize:13,fontWeight:600,marginBottom:2}}>{p.name}</div>
                    <div style={{fontSize:10,color:T.textD,fontFamily:T.mono}}>{p.mitre.slice(0,3).join(" → ")} · CVSS {p.cvss||"N/A"} · {p.skillLevel}</div>
                    {p.kev&&<span className="badge" style={{background:T.redDim,color:T.red,border:"1px solid rgba(255,51,102,.3)",marginTop:3,fontSize:9}}>🚨 CISA KEV — ACTIVELY EXPLOITED</span>}
                  </div>
                  <div style={{width:90,flexShrink:0}}>
                    <div style={{fontSize:10,color:T.textDD,textAlign:"right",marginBottom:3}}>{p.likelihood}%</div>
                    <div style={{height:3,background:T.bg3,borderRadius:2}}>
                      <div style={{height:"100%",width:`${p.likelihood}%`,background:`linear-gradient(90deg,${T.orange},${T.red})`,borderRadius:2}}/>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ══ KNOWLEDGE GRAPH ══ */}
        {tab==="graph"&&(
          <div className="anim">
            <h2 style={{fontSize:18,fontWeight:800,marginBottom:5}}>Knowledge Graph</h2>
            <p style={{color:T.textD,fontSize:13,marginBottom:14}}>{data.graphNodes} nodes · {data.graphEdges} edges · Click nodes to inspect assets</p>
            <div className="glass" style={{padding:18}}>
              <KnowledgeGraph data={data} onNode={n=>{if(n.full){setAssetPanel(n);setCopilot(false)}}}/>
            </div>
          </div>
        )}

        {/* ══ ASSETS ══ */}
        {tab==="assets"&&(
          <div className="anim">
            <h2 style={{fontSize:18,fontWeight:800,marginBottom:14}}>Asset Inventory — {data.totalAssets} assets discovered</h2>
            <div className="glass" style={{overflow:"auto"}}>
              <table>
                <thead><tr><th>Hostname</th><th>IP</th><th>Location</th><th>Cloud</th><th>WAF</th><th>TLS</th><th>Ports</th><th>Tech</th><th>Business Function</th><th>Risk</th></tr></thead>
                <tbody>
                  {data.subdomains.map((s,i)=>(
                    <tr key={i} onClick={()=>{setAssetPanel({full:s});setCopilot(false)}} style={{cursor:"pointer"}}>
                      <td><span style={{fontFamily:T.mono,color:T.cyan,fontSize:12}}>{s.host}</span></td>
                      <td><span style={{fontFamily:T.mono,color:T.textD,fontSize:11}}>{s.ip}</span></td>
                      <td style={{fontSize:11,color:T.textD}}>{s.country} {s.city}</td>
                      <td style={{fontSize:12,color:T.blue}}>{s.cloud||"—"}</td>
                      <td style={{fontSize:11,color:s.waf?T.green:T.textDD}}>{s.waf||"—"}</td>
                      <td><span style={{fontFamily:T.mono,fontWeight:700,color:s.grade==="A+"||s.grade==="A"?T.green:s.grade==="B"?T.yellow:T.red}}>{s.grade}</span></td>
                      <td style={{fontSize:11,color:T.textD}}>{s.ports.slice(0,3).join(",")}…</td>
                      <td style={{fontSize:11,color:T.textD}}>{s.techs.slice(0,2).join(", ")}</td>
                      <td style={{fontSize:11,color:T.purple}}>{s.hasBusiness}</td>
                      <td><span className="badge" style={{background:SEV.bg(s.risk),color:SEV.color(s.risk),border:`1px solid ${SEV.border(s.risk)}`}}>{s.risk}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ══ FINDINGS ══ */}
        {tab==="findings"&&(
          <div className="anim">
            <div className="row" style={{justifyContent:"space-between",marginBottom:14,flexWrap:"wrap",gap:8}}>
              <h2 style={{fontSize:18,fontWeight:800}}>Security Findings — {data.findings.length} issues</h2>
              <div className="row" style={{gap:10}}>
                {["CRITICAL","HIGH","MEDIUM","LOW"].map(s=>(
                  <span key={s} className="row" style={{gap:4,fontSize:12,fontWeight:700,color:SEV.color(s)}}>
                    <span style={{width:7,height:7,borderRadius:"50%",background:SEV.color(s),display:"inline-block"}}/>
                    {data.findings.filter(f=>f.severity===s).length} {s.slice(0,4)}
                  </span>
                ))}
              </div>
            </div>
            <div className="col" style={{gap:8}}>
              {data.findings.map((f,i)=>(
                <div key={i} className="glass" style={{padding:"12px 16px",display:"flex",gap:12,borderLeft:`3px solid ${SEV.color(f.severity)}`,animation:`appear .3s ease-out ${i*.04}s both`}}>
                  <span className="badge" style={{background:SEV.bg(f.severity),color:SEV.color(f.severity),border:`1px solid ${SEV.border(f.severity)}`,flexShrink:0,alignSelf:"flex-start"}}>{f.severity}</span>
                  <div style={{flex:1}}>
                    <div style={{fontSize:13,fontWeight:600,marginBottom:4}}>{f.issue}</div>
                    <div className="row" style={{gap:10,flexWrap:"wrap"}}>
                      <span style={{fontSize:11,color:T.textD}}>Asset: <span style={{fontFamily:T.mono,color:T.cyan}}>{f.asset}</span></span>
                      <span style={{fontSize:11,color:T.textD}}>Cat: <span style={{color:T.text}}>{f.category}</span></span>
                      {f.cve&&<span style={{fontSize:11,fontFamily:T.mono,color:T.orange}}>🔴 {f.cve} CVSS {f.cvss} EPSS {(f.epss*100).toFixed(0)}%</span>}
                      {f.mitre&&<span className="badge mono" style={{background:T.blueDim,color:T.blue,border:"1px solid rgba(61,127,255,.3)"}}>{f.mitre}</span>}
                    </div>
                    {f.compliance?.length>0&&(
                      <div className="row" style={{gap:4,marginTop:5,flexWrap:"wrap"}}>
                        {f.compliance.map(c=><span key={c} className="badge" style={{background:T.purpleDim,color:T.purple,border:"1px solid rgba(139,92,246,.25)",fontSize:9}}>{c}</span>)}
                      </div>
                    )}
                  </div>
                  <button className="btn btn-g" style={{flexShrink:0,fontSize:11,padding:"4px 9px",alignSelf:"flex-start"}}>Fix</button>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ══ ATTACK SIMULATION ══ */}
        {tab==="attack"&&(
          <div className="anim">
            <h2 style={{fontSize:18,fontWeight:800,marginBottom:5}}>Attack Path Simulation</h2>
            <p style={{color:T.textD,fontSize:13,marginBottom:14}}>Select a path to replay adversary movement with MITRE ATT&CK mapping, exploitation probability, and business impact.</p>
            <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(240px,1fr))",gap:9,marginBottom:18}}>
              {data.attackPaths.map((p,i)=>(
                <div key={i} className={`glass ${simPath===i?"glow-r":""}`}
                  style={{padding:13,cursor:"pointer",border:simPath===i?`1px solid ${T.red}`:undefined,transition:"all .2s"}}
                  onClick={()=>startSim(i)}>
                  <div className="row" style={{justifyContent:"space-between",marginBottom:7}}>
                    <span className="badge mono" style={{background:T.redDim,color:T.red,border:"1px solid rgba(255,51,102,.3)"}}>PATH #{p.rank}</span>
                    <div className="row" style={{gap:5}}>
                      {p.kev&&<span className="badge" style={{background:T.redDim,color:T.red,border:"1px solid rgba(255,51,102,.3)",fontSize:9}}>🚨 KEV</span>}
                      <span style={{fontSize:13,color:T.orange,fontFamily:T.mono,fontWeight:700}}>{p.likelihood}%</span>
                    </div>
                  </div>
                  <div style={{fontSize:13,fontWeight:700,marginBottom:3}}>{p.name}</div>
                  <div style={{fontSize:10,color:T.textD}}>{p.skillLevel} · {p.steps.length} steps · CVSS {p.cvss||"N/A"}</div>
                  {simPath===i&&simPlaying&&<div style={{marginTop:5,fontSize:10,color:T.red,animation:"glow-pulse 1s infinite"}}>▶ STEP {simStep+1}/{p.steps.length}</div>}
                </div>
              ))}
            </div>
            <div className="glass glow-r" style={{padding:18,marginBottom:14}}>
              <div className="row" style={{justifyContent:"space-between",marginBottom:12,flexWrap:"wrap",gap:8}}>
                <div style={{fontSize:9,color:T.textDD,letterSpacing:".15em"}}>{simPath!==null?`SIMULATING: ${data.attackPaths[simPath].name}`:"SELECT A PATH TO SIMULATE"}</div>
                <div className="row" style={{gap:6}}>
                  <button onClick={()=>simPlaying?pauseSim():simPath!==null&&startSim(simPath)} className="btn btn-d" style={{padding:"5px 12px",fontSize:12}} disabled={simPath===null}>{simPlaying?"⏸":"▶"} {simPlaying?"Pause":"Play"}</button>
                  <button onClick={()=>simPath!==null&&startSim(simPath)} className="btn btn-g" style={{padding:"5px 10px",fontSize:12}} disabled={simPath===null}>↺</button>
                  <button onClick={resetSim} className="btn btn-g" style={{padding:"5px 10px",fontSize:12}} disabled={simPath===null}>✕</button>
                  <select value={simSpeed} onChange={e=>setSimSpeed(Number(e.target.value))} style={{background:T.bg3,border:`1px solid ${T.border}`,color:T.textD,borderRadius:6,padding:"5px 8px",fontSize:11}}>
                    <option value={400}>Fast</option><option value={900}>Normal</option><option value={1800}>Slow</option>
                  </select>
                  <button onClick={()=>{setCopilot(true);setAssetPanel(null)}} className="btn btn-p" style={{padding:"5px 10px",fontSize:11}}>🤖 Analyze</button>
                </div>
              </div>
              <AttackGraph data={data} activePath={simPath} activeStep={simStep}/>
            </div>
            {simPath!==null&&(
              <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(210px,1fr))",gap:10}}>
                {[{l:"Business Impact",v:data.attackPaths[simPath].bizImpact,c:T.red},{l:"Technical Impact",v:data.attackPaths[simPath].impact,c:T.orange},{l:"Attacker Skill",v:data.attackPaths[simPath].skillLevel,c:T.purple},{l:"Likelihood",v:`${data.attackPaths[simPath].likelihood}% exploitation probability`,c:T.yellow}].map((d,i)=>(
                  <div key={i} className="glass" style={{padding:13}}>
                    <div style={{fontSize:9,color:T.textDD,letterSpacing:".12em",marginBottom:5}}>{d.l}</div>
                    <div style={{fontSize:12,color:d.c,fontWeight:600,lineHeight:1.4}}>{d.v}</div>
                  </div>
                ))}
                <div className="glass" style={{padding:13}}>
                  <div style={{fontSize:9,color:T.textDD,letterSpacing:".12em",marginBottom:7}}>MITIGATIONS</div>
                  {data.attackPaths[simPath].remediations.map((r,i)=><div key={i} style={{fontSize:11,color:T.green,padding:"2px 0"}}>✓ {r}</div>)}
                </div>
              </div>
            )}
          </div>
        )}

        {/* ══ VULNERABILITIES ══ */}
        {tab==="vuln"&&(
          <div className="anim">
            <h2 style={{fontSize:18,fontWeight:800,marginBottom:14}}>Vulnerability Intelligence</h2>
            <div className="glass glow-r" style={{padding:16,marginBottom:14,border:"1px solid rgba(255,51,102,.3)"}}>
              <div style={{fontSize:9,color:T.textDD,letterSpacing:".15em",marginBottom:10}}>🚨 CISA KNOWN EXPLOITED VULNERABILITIES</div>
              {data.cves.filter(c=>c.kev).map((c,i)=>(
                <div key={i} style={{padding:"10px 0",borderBottom:`1px solid ${T.border}`}}>
                  <div className="row" style={{gap:10,marginBottom:5}}>
                    <span className="badge mono" style={{background:T.redDim,color:T.red,border:"1px solid rgba(255,51,102,.35)",fontSize:11}}>{c.id}</span>
                    <span style={{fontSize:13,fontWeight:600}}>{c.desc}</span>
                  </div>
                  <div className="row" style={{gap:14}}>
                    <span style={{fontSize:11,color:T.red,fontFamily:T.mono}}>CVSS {c.cvss}</span>
                    <span style={{fontSize:11,color:T.orange,fontFamily:T.mono}}>EPSS {(c.epss*100).toFixed(1)}%</span>
                    <span style={{fontSize:11,color:T.purple}}>{c.tech}</span>
                    <span style={{fontSize:11,color:T.green}}>🔧 {c.patch}</span>
                  </div>
                </div>
              ))}
            </div>
            <div className="glass" style={{overflow:"auto"}}>
              <table>
                <thead><tr><th>CVE ID</th><th>Description</th><th>Technology</th><th>CVSS</th><th>EPSS</th><th>KEV</th><th>Patch</th><th>Priority</th></tr></thead>
                <tbody>
                  {data.cves.map((c,i)=>(
                    <tr key={i}>
                      <td><span className="mono" style={{color:T.orange,fontSize:12}}>{c.id}</span></td>
                      <td style={{fontSize:12}}>{c.desc}</td>
                      <td style={{fontSize:12,color:T.purple}}>{c.tech}</td>
                      <td><span className="mono" style={{color:c.cvss>=9?T.red:c.cvss>=7?T.orange:T.yellow,fontWeight:700}}>{c.cvss}</span></td>
                      <td><span className="mono" style={{color:c.epss>.5?T.red:c.epss>.2?T.orange:T.textD}}>{c.epss?(c.epss*100).toFixed(1)+"%":"—"}</span></td>
                      <td>{c.kev?<span className="badge" style={{background:T.redDim,color:T.red,border:"1px solid rgba(255,51,102,.3)"}}>🚨 KEV</span>:"—"}</td>
                      <td style={{fontSize:11,color:T.green}}>{c.patch}</td>
                      <td><span className="badge" style={{background:c.kev?T.redDim:c.cvss>=7?T.orangeDim:T.yellowDim,color:c.kev?T.red:c.cvss>=7?T.orange:T.yellow,border:"1px solid currentColor"}}>{c.kev?"IMMEDIATE":c.cvss>=7?"URGENT":"PLANNED"}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ══ API DISCOVERY ══ */}
        {tab==="api"&&(
          <div className="anim">
            <h2 style={{fontSize:18,fontWeight:800,marginBottom:5}}>API Discovery Engine</h2>
            <p style={{color:T.textD,fontSize:13,marginBottom:14}}>{data.apis.length} API endpoints discovered · {data.apis.filter(a=>!a.auth).length} unauthenticated · {data.apis.filter(a=>a.cors==="*").length} with CORS wildcard</p>
            <div className="col" style={{gap:9}}>
              {data.apis.map((api,i)=>(
                <div key={i} className="glass" style={{padding:15,borderLeft:`3px solid ${SEV.color(api.risk)}`}}>
                  <div className="row" style={{gap:9,marginBottom:8}}>
                    <span className="badge" style={{background:SEV.bg(api.risk),color:SEV.color(api.risk),border:`1px solid ${SEV.border(api.risk)}`}}>{api.risk}</span>
                    <span style={{fontFamily:T.mono,color:T.cyan,fontSize:13,fontWeight:600}}>{api.path}</span>
                    {api.method&&<span className="badge mono" style={{background:T.blueDim,color:T.blue,border:"1px solid rgba(61,127,255,.3)"}}>{api.method}</span>}
                  </div>
                  <div className="row" style={{gap:7,flexWrap:"wrap"}}>
                    {!api.auth&&<span className="badge" style={{background:T.redDim,color:T.red,border:"1px solid rgba(255,51,102,.3)"}}>🔓 NO AUTH</span>}
                    {api.cors==="*"&&<span className="badge" style={{background:T.orangeDim,color:T.orange,border:"1px solid rgba(255,140,0,.3)"}}>⚠️ CORS *</span>}
                    {api.introspection&&<span className="badge" style={{background:T.purpleDim,color:T.purple,border:"1px solid rgba(139,92,246,.3)"}}>GraphQL Introspection ON</span>}
                    {api.sensitive&&api.sensitive.map(s=><span key={s} className="badge" style={{background:T.redDim,color:T.red,border:"1px solid rgba(255,51,102,.3)"}}>EXPOSES: {s}</span>)}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ══ JS INTEL ══ */}
        {tab==="js"&&(
          <div className="anim">
            <h2 style={{fontSize:18,fontWeight:800,marginBottom:5}}>JavaScript Intelligence</h2>
            <p style={{color:T.textD,fontSize:13,marginBottom:14}}>Secrets, API endpoints, and internal IP addresses discovered in client-side JavaScript</p>
            {data.jsSources.map((js,i)=>(
              <div key={i} className="glass" style={{padding:16,marginBottom:10}}>
                <div className="row" style={{justifyContent:"space-between",marginBottom:10}}>
                  <div style={{fontSize:13,fontFamily:T.mono,color:T.cyan}}>📝 {js.file}</div>
                  <div className="row" style={{gap:6}}>
                    <span style={{fontSize:11,color:T.textDD}}>{js.size}</span>
                    <span className="badge" style={{background:T.redDim,color:T.red,border:"1px solid rgba(255,51,102,.3)"}}>{js.findings.filter(f=>f.risk==="CRITICAL").length} CRITICAL</span>
                  </div>
                </div>
                {js.findings.map((f,j)=>(
                  <div key={j} style={{padding:"8px 0",borderBottom:`1px solid ${T.border}`}}>
                    <div className="row" style={{gap:8,marginBottom:4}}>
                      <span className="badge" style={{background:SEV.bg(f.risk),color:SEV.color(f.risk),border:`1px solid ${SEV.border(f.risk)}`}}>{f.risk}</span>
                      <span style={{fontFamily:T.mono,color:T.orange,fontSize:12,fontWeight:700}}>{f.type}</span>
                      <span style={{fontSize:10,color:T.textDD}}>Line {f.line}</span>
                    </div>
                    <div style={{fontSize:11,fontFamily:T.mono,color:T.textD,background:T.bg3,padding:"4px 8px",borderRadius:4}}>{f.value}</div>
                  </div>
                ))}
              </div>
            ))}
          </div>
        )}

        {/* ══ EMAIL ══ */}
        {tab==="email"&&(
          <div className="anim">
            <h2 style={{fontSize:18,fontWeight:800,marginBottom:14}}>Email Security Analysis</h2>
            <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(200px,1fr))",gap:12,marginBottom:18}}>
              {[
                {l:"SPF",s:data.email.spf,d:"Sender Policy Framework — controls authorized sending servers"},
                {l:"DKIM",s:data.email.dkim,d:"DomainKeys Identified Mail — cryptographic email signing"},
                {l:"DMARC",s:data.email.dmarc,d:`Policy: ${data.email.dmarc} — ${data.email.dmarc==="REJECT"?"enforced":"not enforced"}`},
              ].map(e=>{
                const ok=e.s==="PASS"||e.s==="REJECT";
                return (
                  <div key={e.l} className="glass" style={{padding:18,borderTop:`3px solid ${ok?T.green:e.s==="QUARANTINE"?T.yellow:T.red}`}}>
                    <div className="row" style={{justifyContent:"space-between",marginBottom:8}}>
                      <span style={{fontSize:20,fontWeight:900,fontFamily:T.mono}}>{e.l}</span>
                      <span style={{fontWeight:700,fontSize:14,color:ok?T.green:T.red}}>{e.s}</span>
                    </div>
                    <p style={{fontSize:12,color:T.textD,lineHeight:1.5}}>{e.d}</p>
                    {!ok&&<div style={{marginTop:8,fontSize:11,color:T.red}}>⚠️ Phishing risk — domain can be spoofed</div>}
                  </div>
                );
              })}
            </div>
            <div className="glass" style={{padding:16}}>
              <div style={{fontSize:9,color:T.textDD,letterSpacing:".15em",marginBottom:10}}>PROVIDER & RISK ASSESSMENT</div>
              {[["Email Provider",data.email.provider],["Email Risk Score",`${data.email.riskScore}/100`],["MX Records","Configured and resolving"],["SMTP Security","TLS enforced on port 587"],["DMARC Reports","rua=mailto:dmarc@"+data.domain]].map(([k,v])=>(
                <div key={k} className="row" style={{justifyContent:"space-between",padding:"7px 0",borderBottom:`1px solid ${T.border}`}}>
                  <span style={{fontSize:12,color:T.textD}}>{k}</span>
                  <span style={{fontSize:12,fontFamily:T.mono,color:T.text}}>{v}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ══ TLS ══ */}
        {tab==="tls"&&(
          <div className="anim">
            <h2 style={{fontSize:18,fontWeight:800,marginBottom:14}}>TLS / SSL Configuration Analysis</h2>
            <div style={{display:"grid",gridTemplateColumns:"200px 1fr",gap:14,marginBottom:14}}>
              <div className="glass glow-c col" style={{padding:18,alignItems:"center",gap:8}}>
                <div style={{fontSize:9,color:T.textDD,letterSpacing:".15em"}}>OVERALL GRADE</div>
                <div style={{fontSize:60,fontWeight:900,fontFamily:T.mono,color:data.tls.overallGrade.startsWith("A")?T.green:data.tls.overallGrade.startsWith("B")?T.yellow:T.red,animation:"glow-pulse 3s infinite"}}>{data.tls.overallGrade}</div>
                <div style={{fontSize:11,color:T.textD}}>Across {data.totalAssets} assets</div>
              </div>
              <div className="glass" style={{padding:16}}>
                <div style={{fontSize:9,color:T.textDD,letterSpacing:".15em",marginBottom:10}}>TLS ISSUES DETECTED</div>
                {data.tls.issues.map((issue,i)=>(
                  <div key={i} style={{padding:"7px 0",borderBottom:`1px solid ${T.border}`,display:"flex",gap:8}}>
                    <span>⚠️</span><span style={{fontSize:13}}>{issue}</span>
                  </div>
                ))}
              </div>
            </div>
            <div className="glass" style={{overflow:"auto",marginBottom:14}}>
              <table>
                <thead><tr><th>Asset</th><th>TLS Version</th><th>Grade</th><th>HSTS</th><th>Issues</th></tr></thead>
                <tbody>
                  {Object.entries(data.tlsGrades).map(([host,tls],i)=>(
                    <tr key={i}>
                      <td><span className="mono" style={{color:T.cyan,fontSize:12}}>{host}</span></td>
                      <td><span className="mono" style={{fontSize:12}}>{tls.tls}</span></td>
                      <td><span className="mono" style={{fontWeight:800,color:tls.grade==="A+"||tls.grade==="A"?T.green:tls.grade==="B"?T.yellow:T.red}}>{tls.grade}</span></td>
                      <td><span style={{color:tls.hsts?T.green:T.red,fontSize:12}}>{tls.hsts?"✓":"✗"}</span></td>
                      <td style={{fontSize:11,color:T.textD}}>{tls.issues.join("; ")||"✓ No issues"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <h3 style={{fontSize:14,fontWeight:700,marginBottom:10}}>📜 Certificate Transparency Timeline</h3>
            <div className="glass" style={{overflow:"auto"}}>
              <table>
                <thead><tr><th>CT Log Date</th><th>Domain</th><th>Issuer</th><th>Expiry</th><th>Valid</th></tr></thead>
                <tbody>
                  {data.ctTimeline.map((c,i)=>(
                    <tr key={i}>
                      <td style={{fontSize:12,fontFamily:T.mono,color:T.textD}}>{c.logged}</td>
                      <td style={{fontSize:12,fontFamily:T.mono,color:T.cyan}}>{c.name}</td>
                      <td style={{fontSize:12,color:T.textD}}>{c.issuer}</td>
                      <td style={{fontSize:12,fontFamily:T.mono}}>{c.expiry}</td>
                      <td><span style={{color:c.valid?T.green:T.red,fontSize:12}}>{c.valid?"✓":"✗ Expired"}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ══ SECRETS ══ */}
        {tab==="secrets"&&(
          <div className="anim">
            <h2 style={{fontSize:18,fontWeight:800,marginBottom:14}}>Secrets Exposure & Login Detection</h2>
            <h3 style={{fontSize:12,fontWeight:700,color:T.textD,marginBottom:9,letterSpacing:".12em"}}>🔑 LOGIN PAGES DISCOVERED</h3>
            <div className="col" style={{gap:8,marginBottom:18}}>
              {data.subdomains.flatMap(s=>s.loginPages.map(l=>({...l,host:s.host}))).map((l,i)=>(
                <div key={i} className="glass" style={{padding:13,borderLeft:`3px solid ${l.defaultCredRisk?T.red:T.orange}`}}>
                  <div className="row" style={{gap:7,flexWrap:"wrap"}}>
                    {l.defaultCredRisk&&<span className="badge" style={{background:T.redDim,color:T.red,border:"1px solid rgba(255,51,102,.3)"}}>🔴 DEFAULT CRED RISK</span>}
                    <span className="badge" style={{background:T.orangeDim,color:T.orange,border:"1px solid rgba(255,140,0,.3)"}}>{l.authType.toUpperCase()}</span>
                    <span style={{fontFamily:T.mono,color:T.cyan,fontSize:12}}>{l.url}</span>
                    <span style={{marginLeft:"auto",fontSize:11,color:T.textDD}}>{l.host}</span>
                  </div>
                </div>
              ))}
            </div>
            <h3 style={{fontSize:12,fontWeight:700,color:T.textD,marginBottom:9,letterSpacing:".12em"}}>🗝️ SENSITIVE FILES & SECRETS EXPOSED</h3>
            <div className="col" style={{gap:8}}>
              {data.subdomains.flatMap(s=>s.secrets.map(sec=>({...sec,host:s.host}))).map((sec,i)=>(
                <div key={i} className="glass glow-r" style={{padding:13,borderLeft:`3px solid ${SEV.color(sec.severity)}`}}>
                  <div className="row" style={{gap:8,marginBottom:5}}>
                    <span className="badge" style={{background:SEV.bg(sec.severity),color:SEV.color(sec.severity),border:`1px solid ${SEV.border(sec.severity)}`}}>{sec.severity}</span>
                    <span style={{fontFamily:T.mono,color:T.red,fontSize:13,fontWeight:700}}>{sec.path}</span>
                    <span style={{marginLeft:"auto",fontFamily:T.mono,fontSize:10,color:T.textD}}>{sec.host}</span>
                  </div>
                  <div style={{fontSize:12}}>{sec.desc}</div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ══ COMPLIANCE ══ */}
        {tab==="comply"&&(
          <div className="anim">
            <h2 style={{fontSize:18,fontWeight:800,marginBottom:5}}>Compliance Framework Analysis</h2>
            <p style={{color:T.textD,fontSize:13,marginBottom:14}}>Findings mapped to PCI-DSS, GDPR, ISO 27001, NIST CSF, and OWASP Top 10</p>
            <ComplianceHeatmap compliance={data.compliance}/>
          </div>
        )}

        {/* ══ HISTORY ══ */}
        {tab==="history"&&(
          <div className="anim">
            <h2 style={{fontSize:18,fontWeight:800,marginBottom:14}}>Historical Scan Comparison</h2>
            <div className="glass glow-c" style={{padding:18,marginBottom:14}}>
              <div style={{fontSize:9,color:T.textDD,letterSpacing:".15em",marginBottom:12}}>RISK SCORE TREND — 5 SCANS</div>
              <div className="row" style={{gap:20,alignItems:"flex-end",flexWrap:"wrap"}}>
                <Sparkline data={data.riskHistory.map(r=>r.score)} color={sevColor} w={360} h={80}/>
                <div>
                  <div style={{fontSize:11,color:T.textDD}}>Current: <span style={{color:sevColor,fontWeight:800,fontFamily:T.mono,fontSize:20}}>{data.riskScore}</span></div>
                  <div style={{fontSize:11,color:T.textDD,marginTop:4}}>Trend: <span style={{color:data.riskScore>data.riskHistory[3].score?T.red:T.green,fontWeight:700}}>{data.riskScore>data.riskHistory[3].score?"↑ Worsening":"↓ Improving"}</span></div>
                </div>
              </div>
              <div className="row" style={{gap:14,marginTop:12}}>
                {data.riskHistory.map((r,i)=>(
                  <div key={i} style={{textAlign:"center"}}>
                    <div style={{fontSize:14,fontWeight:700,fontFamily:T.mono,color:r.score>=80?T.red:r.score>=60?T.orange:T.yellow}}>{r.score}</div>
                    <div style={{fontSize:9,color:T.textDD,marginTop:2}}>{r.date}</div>
                  </div>
                ))}
              </div>
            </div>
            <div className="glass" style={{padding:16,marginBottom:10}}>
              <div style={{fontSize:9,color:T.textDD,letterSpacing:".15em",marginBottom:10}}>📡 PASSIVE DNS — HISTORICAL SUBDOMAINS</div>
              <div className="row" style={{flexWrap:"wrap",gap:7}}>
                {data.passiveDns.historicalSubdomains.map(s=>(
                  <span key={s} className="badge mono" style={{background:T.orangeDim,color:T.orange,border:"1px solid rgba(255,140,0,.3)"}}>{s}</span>
                ))}
              </div>
              <div style={{fontSize:11,color:T.textD,marginTop:10}}>⚠️ These previously active subdomains may still resolve or have cached credentials</div>
            </div>
            <div className="glass" style={{overflow:"auto"}}>
              <div style={{padding:"10px 14px",fontSize:9,color:T.textDD,letterSpacing:".15em"}}>IP ADDRESS HISTORY — INFRASTRUCTURE CHANGES</div>
              <table>
                <thead><tr><th>IP Address</th><th>Provider</th><th>First Seen</th><th>Last Seen</th><th>Status</th></tr></thead>
                <tbody>
                  {data.passiveDns.ipHistory.map((ip,i)=>(
                    <tr key={i}>
                      <td><span className="mono" style={{color:T.cyan,fontSize:12}}>{ip.ip}</span></td>
                      <td style={{fontSize:12,color:T.blue}}>{ip.provider}</td>
                      <td style={{fontSize:12,fontFamily:T.mono,color:T.textD}}>{ip.firstSeen}</td>
                      <td style={{fontSize:12,fontFamily:T.mono,color:ip.lastSeen==="present"?T.green:T.textD}}>{ip.lastSeen}</td>
                      <td><span className="badge" style={{background:ip.lastSeen==="present"?T.greenDim:T.bg3,color:ip.lastSeen==="present"?T.green:T.textDD,border:`1px solid ${ip.lastSeen==="present"?T.greenD:T.border}`}}>{ip.lastSeen==="present"?"ACTIVE":"HISTORICAL"}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ══ REMEDIATION ══ */}
        {tab==="remediate"&&(
          <div className="anim">
            <h2 style={{fontSize:18,fontWeight:800,marginBottom:5}}>Prioritized Remediation Plan</h2>
            <p style={{color:T.textD,fontSize:13,marginBottom:14}}>Completing all actions reduces risk score by ~{data.remediations.reduce((a,r)=>a+r.reduction,0)} points. Sorted by risk reduction impact.</p>
            <div className="col" style={{gap:9}}>
              {data.remediations.map((r,i)=>(
                <div key={i} className="glass" style={{padding:16,borderLeft:`3px solid ${SEV.color(r.severity)}`,animation:`appear .3s ease-out ${i*.05}s both`}}>
                  <div className="row" style={{gap:10,marginBottom:9,flexWrap:"wrap"}}>
                    <div style={{width:28,height:28,borderRadius:6,background:SEV.bg(r.severity),border:`1px solid ${SEV.border(r.severity)}`,display:"flex",alignItems:"center",justifyContent:"center",fontSize:13,fontWeight:800,color:SEV.color(r.severity),fontFamily:T.mono,flexShrink:0}}>#{r.rank}</div>
                    <div style={{flex:1}}>
                      <div style={{fontSize:14,fontWeight:700,marginBottom:2}}>{r.title}</div>
                      <div className="row" style={{gap:12}}>
                        <span style={{fontSize:12,color:T.textD}}>⏱ {r.effort}</span>
                        <span style={{fontSize:12,color:T.green}}>📉 −{r.reduction} pts risk</span>
                      </div>
                    </div>
                    <div style={{width:100,flexShrink:0}}>
                      <div style={{height:4,background:T.bg3,borderRadius:2}}>
                        <div style={{height:"100%",width:`${(r.reduction/22)*100}%`,background:`linear-gradient(90deg,${T.green}88,${T.green})`,borderRadius:2}}/>
                      </div>
                    </div>
                  </div>
                  {r.steps.map((step,j)=>(
                    <div key={j} style={{fontSize:12,color:T.textD,display:"flex",gap:8,padding:"2px 0"}}>
                      <span style={{color:T.cyan,flexShrink:0}}>{j+1}.</span>{step}
                    </div>
                  ))}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ══ EXEC REPORT ══ */}
        {tab==="report"&&(
          <div className="anim">
            <div className="row" style={{justifyContent:"space-between",marginBottom:14,flexWrap:"wrap",gap:8}}>
              <h2 style={{fontSize:18,fontWeight:800}}>Executive Security Report</h2>
              <div className="row" style={{gap:7}}>
                <button onClick={()=>{setCopilot(true);setAssetPanel(null)}} className="btn btn-p" style={{padding:"6px 12px",fontSize:12}}>🤖 AI Report</button>
                <button className="btn btn-g" style={{padding:"6px 12px",fontSize:12}}>⬇ Export PDF</button>
              </div>
            </div>
            <div className="glass glow-c" style={{padding:22,marginBottom:14,border:`1px solid ${T.borderHi}`}}>
              <div style={{fontSize:9,color:T.textDD,letterSpacing:".2em",marginBottom:12}}>EXECUTIVE SUMMARY</div>
              <p style={{fontSize:14,lineHeight:1.75,color:T.text}}>{data.exec}</p>
            </div>
            <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(190px,1fr))",gap:10,marginBottom:14}}>
              {[
                {l:"Overall Risk",v:data.riskScore+"/100",s:data.severity,c:SEV.color(data.severity)},
                {l:"Critical Findings",v:data.findings.filter(f=>f.severity==="CRITICAL").length,s:"Require immediate action",c:T.red},
                {l:"Attack Paths",v:data.attackPaths.length,s:`${data.attackPaths[0].likelihood}% top likelihood`,c:T.orange},
                {l:"KEV Matches",v:data.cves.filter(c=>c.kev).length,s:"Actively exploited CVEs",c:T.red},
              ].map((k,i)=>(
                <div key={i} className="glass" style={{padding:16}}>
                  <div style={{fontSize:9,color:T.textDD,letterSpacing:".12em",marginBottom:7}}>{k.l}</div>
                  <div style={{fontSize:30,fontWeight:900,fontFamily:T.mono,color:k.c,marginBottom:4}}>{k.v}</div>
                  <div style={{fontSize:11,color:T.textD}}>{k.s}</div>
                </div>
              ))}
            </div>
            <div className="glass" style={{padding:18,marginBottom:12}}>
              <div style={{fontSize:9,color:T.textDD,letterSpacing:".15em",marginBottom:12}}>TOP 3 BUSINESS RISKS</div>
              {data.attackPaths.slice(0,3).map((p,i)=>(
                <div key={i} style={{padding:"10px 0",borderBottom:`1px solid ${T.border}`}}>
                  <div className="row" style={{gap:9,marginBottom:5}}>
                    <span style={{fontSize:18,fontWeight:900,color:T.red,fontFamily:T.mono}}>#{i+1}</span>
                    <div style={{fontSize:14,fontWeight:700}}>{p.name}</div>
                    {p.kev&&<span className="badge" style={{background:T.redDim,color:T.red,border:"1px solid rgba(255,51,102,.3)",fontSize:9}}>🚨 CISA KEV</span>}
                  </div>
                  <div style={{fontSize:12,color:T.textD,lineHeight:1.5}}>{p.bizImpact}</div>
                </div>
              ))}
            </div>
            <div className="glass" style={{padding:18}}>
              <div style={{fontSize:9,color:T.textDD,letterSpacing:".15em",marginBottom:12}}>COMPLIANCE EXPOSURE SUMMARY</div>
              <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(150px,1fr))",gap:9}}>
                {Object.entries(data.compliance).map(([fw,issues])=>(
                  <div key={fw} style={{padding:12,background:T.bg3,borderRadius:8,borderTop:`2px solid ${issues.length>2?T.red:T.orange}`}}>
                    <div style={{fontWeight:700,fontSize:13,marginBottom:4}}>{fw}</div>
                    <div style={{fontSize:24,fontWeight:900,fontFamily:T.mono,color:issues.length>2?T.red:T.orange,marginBottom:2}}>{issues.length}</div>
                    <div style={{fontSize:10,color:T.textDD}}>violations</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

      </div>

      {/* Panels */}
      <Copilot data={data} visible={copilot} onClose={()=>setCopilot(false)}/>
      {assetPanel&&!copilot&&<AssetPanel asset={assetPanel} data={data} onClose={()=>setAssetPanel(null)}/>}

      {/* Floating copilot */}
      {!copilot&&(
        <button onClick={()=>{setCopilot(true);setAssetPanel(null)}} className="btn btn-p"
          style={{position:"fixed",bottom:22,right:22,width:50,height:50,borderRadius:"50%",fontSize:20,zIndex:500,boxShadow:"0 4px 24px rgba(61,127,255,.5)",animation:"pulse-ring 3s ease-in-out infinite",display:"flex",alignItems:"center",justifyContent:"center"}}>
          🤖
        </button>
      )}
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════
// LANDING
// ════════════════════════════════════════════════════════════════════
function Landing({onScan}) {
  const [domain,setDomain]=useState("");
  const [focused,setFocused]=useState(false);
  const examples=["google.com","tesla.com","github.com","stripe.com","netflix.com"];
  return (
    <div style={{minHeight:"100vh",display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",padding:24,position:"relative",zIndex:1}}>
      <div className="row" style={{gap:14,marginBottom:48}}>
        <div style={{width:52,height:52,background:`linear-gradient(135deg,${T.blueD},${T.purpleD})`,borderRadius:14,display:"flex",alignItems:"center",justifyContent:"center",fontSize:26,boxShadow:`0 0 36px rgba(139,92,246,.5)`}}>🛡️</div>
        <div><div style={{fontSize:32,fontWeight:900,letterSpacing:"-.03em"}}>SentinelX</div><div style={{fontSize:10,color:T.textDD,letterSpacing:".3em",marginTop:1}}>ATTACK SURFACE MANAGEMENT V5</div></div>
      </div>
      <Globe size={270} radar={focused}/>
      <div style={{marginTop:44,textAlign:"center",maxWidth:580}}>
        <h1 style={{fontSize:36,fontWeight:900,lineHeight:1.15,marginBottom:14,letterSpacing:"-.025em"}}>
          Your entire attack surface,<br/>
          <span style={{color:T.cyan,animation:"glow-pulse 3s infinite"}}>analyzed in seconds</span>
        </h1>
        <p style={{color:T.textD,fontSize:15,marginBottom:34,lineHeight:1.65}}>
          Discover subdomains · Detect secrets · Map APIs · Simulate attacks<br/>
          Grade TLS · Check compliance · Generate AI intelligence reports
        </p>
        <div className="row" style={{gap:9,maxWidth:500,margin:"0 auto"}}>
          <input value={domain} onChange={e=>setDomain(e.target.value)}
            onFocus={()=>setFocused(true)} onBlur={()=>setFocused(false)}
            onKeyDown={e=>e.key==="Enter"&&domain.trim()&&onScan(domain.trim())}
            placeholder="Enter target domain — e.g. example.com"
            style={{flex:1,padding:"14px 18px",fontSize:14,background:T.bg2,border:`1px solid ${focused?T.cyan:T.border}`,borderRadius:10,color:T.text,fontFamily:T.mono,boxShadow:focused?"0 0 0 3px rgba(0,212,255,.1)":undefined,transition:"all .2s"}}/>
          <button onClick={()=>domain.trim()&&onScan(domain.trim())} className="btn btn-p" style={{padding:"14px 22px",fontSize:14,borderRadius:10}}>🔍 Scan</button>
        </div>
        <div className="row" style={{gap:5,justifyContent:"center",marginTop:12,flexWrap:"wrap"}}>
          <span style={{fontSize:12,color:T.textDD}}>Try:</span>
          {examples.map(ex=>(
            <button key={ex} onClick={()=>{setDomain(ex);onScan(ex)}}
              style={{background:"none",border:`1px solid ${T.border}`,color:T.textD,padding:"4px 10px",borderRadius:16,cursor:"pointer",fontSize:12,transition:"all .15s"}}
              onMouseEnter={e=>{e.target.style.borderColor=T.cyan;e.target.style.color=T.cyan}}
              onMouseLeave={e=>{e.target.style.borderColor=T.border;e.target.style.color=T.textD}}>
              {ex}
            </button>
          ))}
        </div>
      </div>
      {/* Feature grid */}
      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(165px,1fr))",gap:7,marginTop:52,maxWidth:900,width:"100%"}}>
        {[
          {i:"🔍",l:"Subdomain Discovery",d:"crt.sh, OTX, bruteforce, permutation"},
          {i:"🕸️",l:"Knowledge Graph",d:"Asset correlation & Neo4j-style relationships"},
          {i:"🎯",l:"Attack Simulation",d:"MITRE ATT&CK mapped adversary path replay"},
          {i:"💀",l:"CVE Intelligence",d:"NVD + CISA KEV + EPSS scoring"},
          {i:"🤖",l:"AI Copilot",d:"Claude-powered threat analysis & reporting"},
          {i:"🗝️",l:"Secrets Detection",d:"Exposed .env, keys, configs, Git repos"},
          {i:"🔌",l:"API Discovery",d:"REST, GraphQL, Swagger endpoint mapping"},
          {i:"⚖️",l:"Compliance Mapper",d:"PCI-DSS, GDPR, ISO 27001, NIST, OWASP"},
          {i:"📡",l:"Passive DNS",d:"Historical infrastructure & IP changes"},
          {i:"🔐",l:"TLS Grading (A+-F)",d:"SSL Labs-style configuration analysis"},
          {i:"👑",l:"Crown Jewel ID",d:"Business-critical asset identification"},
          {i:"📊",l:"Executive Reports",d:"AI-powered non-technical risk briefings"},
        ].map(f=>(
          <div key={f.l} className="glass" style={{padding:"13px 14px",textAlign:"center"}}>
            <div style={{fontSize:20,marginBottom:5}}>{f.i}</div>
            <div style={{fontSize:11,fontWeight:700,marginBottom:3}}>{f.l}</div>
            <div style={{fontSize:9,color:T.textDD,lineHeight:1.4}}>{f.d}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── APP ROOT ──────────────────────────────────────────────────────
export default function App() {
  const [phase,setPhase]=useState("land");
  const [target,setTarget]=useState("");
  const [data,setData]=useState(null);
  return (
    <>
      <style>{CSS}</style>
      <div style={{minHeight:"100vh",background:T.bg0,position:"relative"}}>
        <Grid/>
        <div style={{position:"relative",zIndex:1}}>
          {phase==="land"&&<Landing onScan={d=>{setTarget(d);setPhase("scan")}}/>}
          {phase==="scan"&&<ScanView domain={target} onComplete={d=>{setData(d);setPhase("dash")}}/>}
          {phase==="dash"&&data&&<Dashboard data={data} onNewScan={()=>{setPhase("land");setData(null)}}/>}
        </div>
      </div>
    </>
  );
}
