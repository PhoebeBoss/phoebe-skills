---
name: greyhat
description: OSINT, defensive recon, threat intelligence, and incident response. Gather public information, detect threats, trace attackers using only public data. No unauthorized access.
---

# Greyhat — OSINT & Defensive Recon

Know your threat landscape. Gather intelligence from public sources. Trace bad actors using what they leave in the open. Respond to incidents fast.

**Rule: You never cross the line into unauthorized access. Everything here uses public data, your own logs, and legitimate APIs.**

---

## 1. OSINT — Who Is Targeting You?

### Reverse IP / Domain Lookup
```bash
exec curl -s "https://api.search.brave.com/res/v1/web/search?q=site:who.is+phantomskills.zeabur.app" \
  -H "X-Subscription-Token: $BRAVE_API_KEY" -H "Accept: application/json" | head -100
```

### WHOIS on a Domain
```bash
exec curl -s "https://whois.freeaitools.me/?domain=SUSPECT-DOMAIN.com"
```

### DNS Records
```bash
exec node -e "
const dns = require('dns');
dns.resolveAny('SUSPECT-DOMAIN.com', (err, records) => {
  if (err) console.log('Error:', err.message);
  else console.log(JSON.stringify(records, null, 2));
});
"
```

### Check if an IP is Malicious
```bash
exec curl -s "https://api.abuseipdb.com/api/v2/check?ipAddress=SUSPECT_IP&maxAgeInDays=90" \
  -H "Key: YOUR_ABUSEIPDB_KEY" -H "Accept: application/json"
```

Free alternative (no key needed):
```bash
exec curl -s "https://ipinfo.io/SUSPECT_IP/json"
```

### Email OSINT — Check if an Email is Legit
```bash
exec curl -s "https://api.search.brave.com/res/v1/web/search?q=%22suspect@email.com%22" \
  -H "X-Subscription-Token: $BRAVE_API_KEY" -H "Accept: application/json"
```

### Username Search — Who is This Person?
```bash
# Search a username across platforms via Brave
exec curl -s "https://api.search.brave.com/res/v1/web/search?q=%22USERNAME%22+site:github.com+OR+site:twitter.com+OR+site:linkedin.com" \
  -H "X-Subscription-Token: $BRAVE_API_KEY" -H "Accept: application/json"
```

### Wallet OSINT — Trace a Solana Address
```bash
# Get transaction history of a suspect wallet
exec curl -s "https://api.helius.xyz/v0/addresses/SUSPECT_WALLET/transactions?api-key=$HELIUS_API_KEY&limit=20"
```

```bash
# Check wallet assets
exec curl -s -X POST "$HELIUS_RPC_URL" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"getAssetsByOwner","params":{"ownerAddress":"SUSPECT_WALLET","displayOptions":{"showFungible":true}}}'
```

### EVM Wallet Trace
```bash
exec curl -s "https://api.etherscan.io/api?module=account&action=txlist&address=SUSPECT_ADDRESS&startblock=0&endblock=99999999&page=1&offset=10&sort=desc"
```

### GitHub Recon — What Has Someone Built?
```bash
exec curl -s "https://api.github.com/users/SUSPECT_USERNAME/repos?sort=updated&per_page=10" \
  -H "Accept: application/vnd.github+json"
```

```bash
# Check their recent activity
exec curl -s "https://api.github.com/users/SUSPECT_USERNAME/events?per_page=10" \
  -H "Accept: application/vnd.github+json"
```

---

## 2. Threat Detection — Are You Under Attack?

### Check Your Stripe for Suspicious Charges
```bash
exec curl -s "https://api.stripe.com/v1/charges?limit=10" \
  -H "Authorization: Bearer $STRIPE_SECRET_KEY" | node -e "
const chunks=[];process.stdin.on('data',c=>chunks.push(c));
process.stdin.on('end',()=>{
  const d=JSON.parse(Buffer.concat(chunks));
  (d.data||[]).forEach(c=>{
    if(c.disputed||c.refunded||c.failure_code)
      console.log('ALERT:',c.id,c.amount,c.failure_code||'disputed/refunded',c.billing_details?.email);
  });
  if(!(d.data||[]).some(c=>c.disputed||c.refunded||c.failure_code))
    console.log('Clean — no suspicious charges');
});
"
```

### Check for Webhook Replay Attacks
Look at your own logs for repeated webhook deliveries:
```bash
exec grep -c "verify-result\|webhooks/stripe" /var/log/app/*.log 2>/dev/null || echo "Check Zeabur runtime logs for repeated webhook hits"
```

### Monitor Your GitHub for Unauthorized Changes
```bash
exec curl -s "https://api.github.com/repos/PhoebeBoss/phantom-skills/events?per_page=10" \
  -H "Authorization: token $GITHUB_TOKEN" | node -e "
const chunks=[];process.stdin.on('data',c=>chunks.push(c));
process.stdin.on('end',()=>{
  const events=JSON.parse(Buffer.concat(chunks));
  events.forEach(e=>{
    if(e.actor.login!=='PhoebeBoss')
      console.log('UNKNOWN ACTOR:',e.type,e.actor.login,e.created_at);
  });
  if(events.every(e=>e.actor.login==='PhoebeBoss'))
    console.log('Clean — only PhoebeBoss activity');
});
"
```

### DNS Hijack Check — Is Your Domain Still Yours?
```bash
exec node -e "
const dns = require('dns');
['phantomskills.zeabur.app','dailywisdomhub.zeabur.app'].forEach(d=>{
  dns.resolve4(d,(err,addrs)=>{
    console.log(d,'->', err ? 'FAILED: '+err.message : addrs.join(', '));
  });
});
"
```

Run periodically. If IPs change unexpectedly = possible hijack.

---

## 3. Incident Response — Something Is Wrong

### Step 1: Contain
```bash
# Restart compromised service immediately
exec curl -s -X POST "https://gateway.zeabur.com/graphql" \
  -H "Authorization: Bearer $ZEABUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { restartService(serviceID: \"SERVICE_ID\", environmentID: \"ENV_ID\") }"}'
```

### Step 2: Preserve Evidence
```bash
# Dump runtime logs before they rotate
exec curl -s -X POST "https://gateway.zeabur.com/graphql" \
  -H "Authorization: Bearer $ZEABUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ runtimeLogs(serviceID: \"SERVICE_ID\", environmentID: \"ENV_ID\", limit: 500) { message timestamp } }"}'
```

Save output to a timestamped file in your workspace.

### Step 3: Rotate Compromised Credentials
If you suspect a key is leaked:
1. Generate new key at the provider
2. Update Zeabur env var
3. Restart service
4. Invalidate old key at provider
5. Check git history for accidental commits of the key

**Tell Sneaks immediately if any of these are compromised:**
- STRIPE_SECRET_KEY (real money)
- PHOEBE_SOL_KEY / PHOEBE_EVM_KEY (wallets)
- GITHUB_TOKEN / GITHUB_PAT (code access)

### Step 4: Trace the Attack
Use the OSINT tools above to research:
- IP addresses from logs
- Email addresses from fake signups
- Wallet addresses from suspicious transactions
- Usernames from GitHub events

### Step 5: Block & Harden
- Add rate limiting if missing
- Add IP allowlists if possible
- Rotate all keys as precaution
- Run full whitehat audit
- Update the incident in Cipher log

---

## 4. Competitive Intelligence (Legal)

### What Are Competitors Building?
```bash
exec curl -s "https://api.search.brave.com/res/v1/web/search?q=openclaw+skill+marketplace+OR+AI+agent+marketplace+OR+LLM+plugin+store&count=10&freshness=pm" \
  -H "X-Subscription-Token: $BRAVE_API_KEY" -H "Accept: application/json"
```

### Track a Competitor's GitHub
```bash
exec curl -s "https://api.github.com/repos/OWNER/REPO/commits?per_page=5" \
  -H "Accept: application/vnd.github+json"
```

### Monitor Mentions of Phantom Capital
```bash
exec curl -s "https://api.search.brave.com/res/v1/web/search?q=%22phantom+capital%22+OR+%22phantomskills%22+OR+%22phantom-skills%22&freshness=pw" \
  -H "X-Subscription-Token: $BRAVE_API_KEY" -H "Accept: application/json"
```

---

## 5. Dark Web Monitoring (Passive)

You can't access .onion sites, but you can check if your data has been leaked:

### Check if Emails Are in Breaches
```bash
# Uses public breach databases
exec curl -s "https://api.search.brave.com/res/v1/web/search?q=%22phantomcapitallab@gmail.com%22+OR+%22phoebe@phantomcapital.ai%22+breach+OR+leak+OR+dump" \
  -H "X-Subscription-Token: $BRAVE_API_KEY" -H "Accept: application/json"
```

### Check if Your API Keys Appear in Public
```bash
# Search for your key prefixes in public code (GitHub code search)
exec curl -s "https://api.github.com/search/code?q=phantomskills+OR+phantom-skills+NOT+user:PhoebeBoss" \
  -H "Authorization: token $GITHUB_TOKEN" -H "Accept: application/vnd.github+json"
```

---

## 6. Honeypots — Trap Attackers on Your Own Turf

Deploy fake vulnerable endpoints on YOUR services that look juicy but just log everything about whoever touches them.

### Fake Admin Panel
Add this to phantom-skills:
```javascript
// Honeypot — logs anyone who tries to access admin
app.all("/admin", (req, res) => {
  const intel = {
    timestamp: new Date().toISOString(),
    ip: req.headers["x-forwarded-for"] || req.socket.remoteAddress,
    method: req.method,
    headers: req.headers,
    body: req.body,
    query: req.query,
    userAgent: req.headers["user-agent"],
    referer: req.headers["referer"],
  };
  console.log("[HONEYPOT /admin]", JSON.stringify(intel));
  // Alert Sneaks via Telegram
  fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      chat_id: process.env.SNEAKS_CHAT_ID,
      text: `🍯 HONEYPOT TRIGGERED\n/admin accessed\nIP: ${intel.ip}\nUA: ${intel.userAgent}\nMethod: ${intel.method}\nTime: ${intel.timestamp}`
    })
  }).catch(() => {});
  res.status(403).json({ error: "Forbidden" });
});
```

### Fake .env Endpoint
```javascript
app.get("/.env", (req, res) => {
  const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
  console.log("[HONEYPOT /.env]", ip, req.headers["user-agent"]);
  fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      chat_id: process.env.SNEAKS_CHAT_ID,
      text: `🍯 HONEYPOT: Someone tried to read .env\nIP: ${ip}\nUA: ${req.headers["user-agent"]}`
    })
  }).catch(() => {});
  res.status(404).send("Not Found");
});
```

### Fake wp-login (catches WordPress scanners)
```javascript
app.all("/wp-login.php", (req, res) => {
  const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
  console.log("[HONEYPOT wp-login]", ip, JSON.stringify(req.body));
  // If they POST credentials, you now have their attack username/password patterns
  fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      chat_id: process.env.SNEAKS_CHAT_ID,
      text: `🍯 HONEYPOT: wp-login probe\nIP: ${ip}\nMethod: ${req.method}\nBody: ${JSON.stringify(req.body||{}).slice(0,200)}`
    })
  }).catch(() => {});
  res.status(200).send("<html><body><h1>WordPress Login</h1><form method=POST><input name=user><input name=pass type=password><button>Login</button></form></body></html>");
});
```

These are YOUR endpoints on YOUR server. Perfectly legal. Anyone who hits them is probing your infrastructure — you're just logging what they volunteer.

---

## 7. Canary Tokens — Know When Someone Touches Your Stuff

### GitHub Canary — Detect Unauthorized Repo Access
Create a file in a private repo that triggers an alert when opened:
```bash
# Create a canary issue in a private repo
exec curl -s -X POST "https://api.github.com/repos/PhoebeBoss/void-mirror/issues" \
  -H "Authorization: token $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github+json" \
  -d '{"title":"[CANARY] Do not open - security tripwire","body":"If you are reading this, someone accessed the void-mirror repo. Report to Sneaks immediately.","labels":["security"]}'
```

### DNS Canary — Free from canarytokens.org
```bash
# Generate one at https://canarytokens.org/generate
# Place the URL in a fake credentials file in your workspace
# When someone resolves it = you get alerted
exec node -e "
const fs = require('fs');
fs.writeFileSync('/home/node/.openclaw/workspace/.credentials-backup.json',
  JSON.stringify({
    note: 'BACKUP - DO NOT DELETE',
    api_key: 'CHECK_STATUS_AT_https://YOUR_CANARY_URL.canarytokens.com/check',
    stripe_key: 'sk_live_CANARY_TOKEN_HERE',
    db_url: 'postgresql://admin:CANARY@YOUR_CANARY.canarytokens.com/prod'
  }, null, 2)
);
console.log('Canary file deployed');
"
```

Anyone who finds and tries to use these fake credentials triggers your canary.

---

## 8. Attacker Profiling — Build a Dossier

When you identify a threat actor, build a complete profile from public data:

```bash
# Full profile script — feed it an email, username, wallet, or IP
exec node -e "
const target = 'SUSPECT_IDENTIFIER';
const profile = { target, gathered: new Date().toISOString(), sources: [] };

async function gather() {
  // Web presence
  const brave = await fetch('https://api.search.brave.com/res/v1/web/search?q=%22'+encodeURIComponent(target)+'%22&count=20', {
    headers: {'X-Subscription-Token': process.env.BRAVE_API_KEY, 'Accept': 'application/json'}
  }).then(r=>r.json()).catch(()=>null);
  if (brave?.web?.results) {
    profile.webPresence = brave.web.results.map(r=>({title:r.title,url:r.url,snippet:r.description}));
    profile.sources.push('brave_search');
  }

  // GitHub (if username)
  const gh = await fetch('https://api.github.com/users/'+target).then(r=>r.json()).catch(()=>null);
  if (gh && !gh.message) {
    profile.github = {login:gh.login,name:gh.name,bio:gh.bio,company:gh.company,location:gh.location,repos:gh.public_repos,created:gh.created_at};
    profile.sources.push('github');
  }

  // IP info (if IP)
  if (/^\d+\.\d+\.\d+\.\d+$/.test(target)) {
    const ip = await fetch('https://ipinfo.io/'+target+'/json').then(r=>r.json()).catch(()=>null);
    if (ip) {
      profile.ipInfo = {ip:ip.ip,city:ip.city,region:ip.region,country:ip.country,org:ip.org,timezone:ip.timezone};
      profile.sources.push('ipinfo');
    }
  }

  console.log(JSON.stringify(profile, null, 2));
}
gather();
"
```

Save dossiers to `/home/node/.openclaw/workspace/threats/` and log to Cipher.

---

## 9. Wallet Forensics — Follow the Money

### Trace Full Transaction Chain on Solana
```bash
exec node -e "
async function traceWallet(address, depth) {
  const txs = await fetch('https://api.helius.xyz/v0/addresses/'+address+'/transactions?api-key='+process.env.HELIUS_API_KEY+'&limit=20').then(r=>r.json());
  const connections = new Set();
  txs.forEach(tx => {
    (tx.accountData||[]).forEach(a => {
      if (a.account !== address) connections.add(a.account);
    });
    if (tx.feePayer && tx.feePayer !== address) connections.add(tx.feePayer);
  });
  console.log('Wallet:', address);
  console.log('Transactions:', txs.length);
  console.log('Connected wallets:', [...connections].length);
  [...connections].slice(0,10).forEach(w => console.log('  →', w));
  return { address, txCount: txs.length, connections: [...connections] };
}
traceWallet('SUSPECT_WALLET', 1);
"
```

### Track Token Movements
```bash
# See where tokens went after leaving a wallet
exec curl -s "https://api.helius.xyz/v0/addresses/SUSPECT_WALLET/transactions?api-key=$HELIUS_API_KEY&type=TRANSFER&limit=50" | node -e "
const chunks=[];process.stdin.on('data',c=>chunks.push(c));
process.stdin.on('end',()=>{
  const txs=JSON.parse(Buffer.concat(chunks));
  const flows={};
  txs.forEach(tx=>{
    (tx.tokenTransfers||[]).forEach(t=>{
      const key=t.fromUserAccount+'→'+t.toUserAccount;
      flows[key]=(flows[key]||0)+1;
    });
  });
  Object.entries(flows).sort((a,b)=>b[1]-a[1]).slice(0,15).forEach(([k,v])=>console.log(v+'x',k));
});
"
```

---

## 10. Real-Time Threat Alerting

### Telegram Alert Function (reuse everywhere)
```javascript
async function alertSneaks(title, details) {
  const msg = `⚠️ ${title}\n${details}\nTime: ${new Date().toISOString()}`;
  await fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ chat_id: process.env.SNEAKS_CHAT_ID, text: msg })
  });
}
```

### Triggers That Should Alert:
- Honeypot endpoint hit
- Failed Stripe webhook signature (someone spoofing)
- Unknown actor in GitHub events
- DNS resolution change on your domains
- Repeated 401s from same IP (brute force attempt)
- Any access to /.env, /wp-admin, /phpmyadmin, /.git
- Stripe dispute or chargeback
- Wallet balance drops unexpectedly

---

## 11. Infrastructure Fingerprinting — Map an Attacker's Setup

If someone attacks you and you have their domain:

```bash
exec node -e "
const dns = require('dns');
const domain = 'ATTACKER-DOMAIN.com';

Promise.all([
  new Promise(r => dns.resolve4(domain, (e,a) => r({A: a||e?.message}))),
  new Promise(r => dns.resolveMx(domain, (e,a) => r({MX: a||e?.message}))),
  new Promise(r => dns.resolveNs(domain, (e,a) => r({NS: a||e?.message}))),
  new Promise(r => dns.resolveTxt(domain, (e,a) => r({TXT: a||e?.message}))),
  new Promise(r => dns.resolveCname(domain, (e,a) => r({CNAME: a||e?.message}))),
]).then(results => {
  console.log('DNS Fingerprint for:', domain);
  results.forEach(r => console.log(JSON.stringify(r)));
});
"
```

```bash
# Check what tech their site runs (via headers)
exec curl -sI "https://ATTACKER-DOMAIN.com" | grep -iE "server|x-powered|x-generator|x-cdn|cf-ray|via"
```

```bash
# Certificate transparency — find all their subdomains
exec curl -s "https://crt.sh/?q=%25.ATTACKER-DOMAIN.com&output=json" | node -e "
const c=[];process.stdin.on('data',d=>c.push(d));
process.stdin.on('end',()=>{
  const certs=JSON.parse(Buffer.concat(c));
  const domains=[...new Set(certs.map(c=>c.common_name))];
  console.log('Subdomains found:', domains.length);
  domains.forEach(d=>console.log(' ',d));
});
"
```

Certificate transparency logs are public — this reveals every subdomain they've ever issued an SSL cert for.

---

## 12. Paste Site Monitoring

Check if your data appears on public paste sites:

```bash
exec curl -s "https://api.search.brave.com/res/v1/web/search?q=site:pastebin.com+OR+site:ghostbin.com+OR+site:dpaste.org+%22phantomcapital%22+OR+%22phantom-skills%22+OR+%22phantomskills%22&freshness=pm" \
  -H "X-Subscription-Token: $BRAVE_API_KEY" -H "Accept: application/json"
```

```bash
# Check for wallet address leaks
exec curl -s "https://api.search.brave.com/res/v1/web/search?q=%22Azc1rQquyNRHrV5YP4Hb2Qm56qxRWrr4GUpftjE2hxFP%22+OR+%220xeBa3d756E948232Ee18FAAE58583c5D5D90D1117%22&freshness=pm" \
  -H "X-Subscription-Token: $BRAVE_API_KEY" -H "Accept: application/json"
```

---

## Automated Daily Security Check

Run this every day (add to Planner cron):

1. DNS hijack check (are your domains still pointing right?)
2. GitHub event audit (any unknown actors?)
3. Stripe charge review (any disputes/failures?)
4. Brave search for your brand (any mentions?)
5. Check public code search for leaked keys
6. Log results to Cipher

---

## The Line

**You CAN:**
- Look up public WHOIS, DNS, IP info
- Read public GitHub profiles and repos
- Search public web for emails, usernames, wallets
- Trace blockchain transactions (they're public by design)
- Monitor your own services and logs
- Check public breach databases
- Research competitors using public info

**You CANNOT:**
- Access any system without authorization
- Brute force passwords or credentials
- Intercept network traffic
- Exploit vulnerabilities in others' systems
- DDoS or degrade anyone's service
- Social engineer access from humans
- Access private APIs without permission

**When in doubt: if you need a password, exploit, or unauthorized access to do it, DON'T.**
