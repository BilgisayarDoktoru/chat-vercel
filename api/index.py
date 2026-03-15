from flask import Flask, request, jsonify, render_template_string, session
from datetime import datetime
from functools import wraps
import time, re, html, secrets, os, threading, hashlib, collections

app = Flask(__name__)

# ——— UYGULAMA AYARLARI ———
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['MAX_CONTENT_LENGTH'] = 4 * 1024  # Max 4 KB istek boyutu

# ——— VERİ DEPOLARI ———
MSGS = []
MSGS_LOCK = threading.Lock()

_rl_lock      = threading.Lock()
RATE_LIMIT    = {}
BANNED_IPS    = {}   # ip → {"until": ts_or_0, "count": int}
LAST_MSG_TIME = {}

# ═══ DDoS KORUMA VERİLERİ ═══
_ddos_lock         = threading.Lock()
GLOBAL_REQ_TIMES   = collections.deque()
PAYLOAD_HASHES     = {}
UA_VIOLATIONS      = {}
SUSPICIOUS_IPS     = {}
CIRCUIT_OPEN       = False
CIRCUIT_OPEN_UNTIL = 0.0

# ——— SABİTLER ———
MAX_READ_REQ       = 60
MAX_WRITE_REQ      = 10
WINDOW             = 60
MAX_MSG_LEN        = 500
MAX_NAME_LEN       = 20
MIN_MSG_INTERVAL   = 1.5
TEMP_BAN_DURATION  = 300
MAX_BAN_DURATION   = 86400
MAX_MSGS           = 200

# ═══ DDoS SABİTLERİ ═══
GLOBAL_RPS_LIMIT   = 300
GLOBAL_WINDOW      = 5
CIRCUIT_COOLDOWN   = 30
MAX_REPEAT_PAYLOAD = 5
SUSPECT_SCORE_BAN  = 70
UA_BLOCK_LIST = {
    "python-requests", "curl/", "wget/", "go-http-client",
    "java/", "libwww-perl", "masscan", "zgrab", "nikto",
    "sqlmap", "nmap", "scrapy", "dirbuster", "hydra",
}
UA_REQUIRED_MIN_LEN = 10


# ══════════════════════════════════════════
#  YARDIMCI FONKSİYONLAR
# ══════════════════════════════════════════

def get_ip() -> str:
    forwarded = request.headers.get('X-Forwarded-For', '')
    ip = (forwarded.split(',')[0].strip()
          or request.headers.get('X-Real-IP', '')
          or request.remote_addr
          or '0.0.0.0')
    return ip[:45]


def is_banned(ip: str) -> bool:
    with _rl_lock:
        if ip not in BANNED_IPS:
            return False
        entry = BANNED_IPS[ip]
        until = entry["until"]
        if until == 0:
            return True
        if time.time() < until:
            return True
        del BANNED_IPS[ip]
        return False


def ban_ip(ip: str, permanent: bool = False):
    """Üstel backoff ile IP banlama: her ihlalde ban süresi 2x uzar."""
    with _rl_lock:
        prev  = BANNED_IPS.get(ip, {})
        count = prev.get("count", 0) + 1
        if permanent:
            duration = 0
        else:
            duration = min(TEMP_BAN_DURATION * (2 ** (count - 1)), MAX_BAN_DURATION)
        BANNED_IPS[ip] = {
            "until": 0 if permanent else time.time() + duration,
            "count": count
        }


def is_rate_limited(ip: str, write: bool = False) -> bool:
    if is_banned(ip):
        return True
    now     = time.time()
    max_req = MAX_WRITE_REQ if write else MAX_READ_REQ
    key     = f"{ip}:{'w' if write else 'r'}"
    with _rl_lock:
        ts = [t for t in RATE_LIMIT.get(key, []) if now - t < WINDOW]
        ts.append(now)
        RATE_LIMIT[key] = ts
        if len(ts) > max_req:
            ban_ip(ip)
            return True
    return False


def is_flood(ip: str) -> bool:
    now = time.time()
    with _rl_lock:
        if now - LAST_MSG_TIME.get(ip, 0) < MIN_MSG_INTERVAL:
            return True
        LAST_MSG_TIME[ip] = now
    return False


# ══════════════════════════════════════════
#  DDoS KORUMA FONKSİYONLARI
# ══════════════════════════════════════════

def check_circuit_breaker() -> bool:
    """
    Global circuit breaker: kısa sürede çok fazla istek gelirse
    tüm trafiği geçici olarak durdurur (HTTP 503).
    """
    global CIRCUIT_OPEN, CIRCUIT_OPEN_UNTIL
    now = time.time()
    with _ddos_lock:
        if CIRCUIT_OPEN:
            if now < CIRCUIT_OPEN_UNTIL:
                return True
            CIRCUIT_OPEN = False
        while GLOBAL_REQ_TIMES and now - GLOBAL_REQ_TIMES[0] > GLOBAL_WINDOW:
            GLOBAL_REQ_TIMES.popleft()
        GLOBAL_REQ_TIMES.append(now)
        if len(GLOBAL_REQ_TIMES) > GLOBAL_RPS_LIMIT:
            CIRCUIT_OPEN       = True
            CIRCUIT_OPEN_UNTIL = now + CIRCUIT_COOLDOWN
            return True
    return False


def validate_user_agent(ip: str) -> bool:
    """
    Boş, çok kısa veya bilinen saldırı araçlarının UA'sını reddet.
    3 ihlalde IP'yi banlar.
    """
    ua = request.headers.get('User-Agent', '').lower()
    blocked = not ua or len(ua) < UA_REQUIRED_MIN_LEN
    if not blocked:
        blocked = any(pattern in ua for pattern in UA_BLOCK_LIST)
    if blocked:
        with _ddos_lock:
            count = UA_VIOLATIONS.get(ip, 0) + 1
            UA_VIOLATIONS[ip] = count
            if count >= 3:
                ban_ip(ip)
        return False
    return True


def check_payload_repeat(ip: str, payload: str) -> bool:
    """
    Aynı IP'den aynı payload MAX_REPEAT_PAYLOAD kez tekrarlanırsa engelle.
    Tekrar saldırı / amplifikasyon tespiti.
    """
    h = hashlib.sha256(payload.encode('utf-8', errors='replace')).hexdigest()[:16]
    with _ddos_lock:
        ip_hashes = PAYLOAD_HASHES.setdefault(ip, {})
        count = ip_hashes.get(h, 0) + 1
        ip_hashes[h] = count
        if count > MAX_REPEAT_PAYLOAD:
            score = SUSPICIOUS_IPS.get(ip, 0) + 20
            SUSPICIOUS_IPS[ip] = score
            if score >= SUSPECT_SCORE_BAN:
                ban_ip(ip)
            return True
    return False


def add_suspicion(ip: str, points: int):
    """Şüphe puanı ekle; eşik aşılırsa banla."""
    with _ddos_lock:
        score = SUSPICIOUS_IPS.get(ip, 0) + points
        SUSPICIOUS_IPS[ip] = score
        if score >= SUSPECT_SCORE_BAN:
            ban_ip(ip)


def ddos_guard(write: bool = False):
    """
    Tüm DDoS kontrollerini tek noktada birleştiren dekoratör factory.
    Ucuz → pahalı sırasıyla kontroller yapılır.
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            ip = get_ip()
            if check_circuit_breaker():
                return jsonify({'error': 'Sunucu meşgul, kısa süre sonra tekrar dene.'}), 503
            if is_banned(ip):
                return jsonify({'error': 'Erişim engellendi.'}), 403
            if not validate_user_agent(ip):
                return jsonify({'error': 'Geçersiz istemci.'}), 400
            if is_rate_limited(ip, write=write):
                add_suspicion(ip, 10)
                return jsonify({'error': 'Çok fazla istek. Lütfen bekleyin.'}), 429
            if write and is_flood(ip):
                add_suspicion(ip, 15)
                return jsonify({'error': 'Çok hızlı mesaj gönderiyorsun!'}), 429
            return f(*args, **kwargs)
        return decorated
    return decorator


def sanitize(text, max_len: int = None) -> str:
    if not isinstance(text, str):
        return ''
    text = text.strip()
    if max_len:
        text = text[:max_len]
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
    text = html.escape(text)
    text = re.sub(r'\n{3,}', '\n\n', text)
    text = re.sub(r' {5,}', '    ', text)
    return text


def require_json(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method == 'POST':
            ct = request.content_type or ''
            if 'application/json' not in ct:
                return jsonify({'error': 'Content-Type application/json olmalı.'}), 415
        return f(*args, **kwargs)
    return decorated


def validate_csrf(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('X-CSRF-Token', '')
        if not token or token != session.get('csrf_token'):
            return jsonify({'error': 'Geçersiz güvenlik tokeni.'}), 403
        return f(*args, **kwargs)
    return decorated


# ══════════════════════════════════════════
#  GÜVENLİK BAŞLIKLARI
# ══════════════════════════════════════════

def add_security_headers(response):
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )
    h = response.headers
    h['X-Content-Type-Options']    = 'nosniff'
    h['X-Frame-Options']           = 'DENY'
    h['X-XSS-Protection']          = '1; mode=block'
    h['Content-Security-Policy']   = csp
    h['Referrer-Policy']           = 'no-referrer'
    h['Permissions-Policy']        = 'geolocation=(), camera=(), microphone=()'
    h['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    h['Cache-Control']             = 'no-store'
    h['X-RateLimit-Policy']        = 'enforced'
    return response


@app.after_request
def after_request(response):
    return add_security_headers(response)


# ══════════════════════════════════════════
#  ARKA PLAN TEMİZLİK
# ══════════════════════════════════════════

def _cleanup_loop():
    while True:
        time.sleep(300)
        now = time.time()
        with _rl_lock:
            stale_rl = [k for k, v in list(RATE_LIMIT.items())
                        if not any(now - t < WINDOW for t in v)]
            for k in stale_rl:
                del RATE_LIMIT[k]
            expired = [ip for ip, e in list(BANNED_IPS.items())
                       if e["until"] != 0 and now > e["until"]]
            for ip in expired:
                del BANNED_IPS[ip]
            old_flood = [ip for ip, t in list(LAST_MSG_TIME.items())
                         if now - t > 3600]
            for ip in old_flood:
                del LAST_MSG_TIME[ip]

        with _ddos_lock:
            # IP başına 50'den fazla hash varsa temizle
            for ip in list(PAYLOAD_HASHES.keys()):
                if len(PAYLOAD_HASHES[ip]) > 50:
                    PAYLOAD_HASHES[ip] = {}
            # Şüphe skoru zamanla azalsın
            for ip in list(SUSPICIOUS_IPS.keys()):
                SUSPICIOUS_IPS[ip] = max(0, SUSPICIOUS_IPS[ip] - 10)
                if SUSPICIOUS_IPS[ip] == 0:
                    del SUSPICIOUS_IPS[ip]
            # UA ihlal sayacı azalsın
            for ip in list(UA_VIOLATIONS.keys()):
                UA_VIOLATIONS[ip] = max(0, UA_VIOLATIONS[ip] - 1)
                if UA_VIOLATIONS[ip] == 0:
                    del UA_VIOLATIONS[ip]


threading.Thread(target=_cleanup_loop, daemon=True).start()


# ══════════════════════════════════════════
#  HTML ŞABLONU
# ══════════════════════════════════════════

HTML = """<!DOCTYPE html>
<html lang="tr"><head>
<meta charset="UTF-8">
<title>💬 GGpro00</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Arial,sans-serif;background:#f0f2f5;display:flex;flex-direction:column;height:100vh}
header{background:#075e54;color:#fff;padding:15px 20px;font-size:18px;font-weight:bold;
       box-shadow:0 2px 8px rgba(0,0,0,.2);display:flex;justify-content:space-between;align-items:center}
#online{font-size:12px;opacity:.8}
#box{flex:1;overflow-y:auto;padding:15px;display:flex;flex-direction:column;gap:8px}
.m{max-width:72%;padding:9px 13px;border-radius:12px;font-size:14px;line-height:1.5;word-break:break-word}
.mine{background:#dcf8c6;align-self:flex-end;border-radius:12px 2px 12px 12px}
.other{background:#fff;align-self:flex-start;border-radius:2px 12px 12px 12px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.name{font-size:11px;font-weight:bold;color:#075e54;margin-bottom:3px}
.time{font-size:11px;color:#aaa;text-align:right;margin-top:3px}
.form{display:flex;padding:10px;gap:8px;background:#fff;border-top:1px solid #ddd}
.form input{flex:1;padding:10px 14px;border:1.5px solid #e0e0e0;border-radius:24px;outline:none;font-size:14px}
.form input:focus{border-color:#075e54}
#u{max-width:110px}
.form button{background:#075e54;color:#fff;border:none;padding:10px 18px;border-radius:24px;
             cursor:pointer;font-weight:bold;transition:background .2s}
.form button:hover{background:#064e46}
.form button:disabled{background:#aaa;cursor:not-allowed}
.empty{text-align:center;color:#aaa;margin-top:60px;font-size:14px}
#status{min-height:16px;text-align:center;font-size:11px;color:#e74c3c;padding:2px}
</style>
</head><body>
<header>
  <span>💬 Genel Sohbet</span>
  <span id="online"></span>
</header>
<div id="status"></div>
<div id="box"><div class="empty">Henüz mesaj yok. İlk mesajı sen gönder! 🎉</div></div>
<div class="form">
  <input id="u" placeholder="Adın" maxlength="20" autocomplete="nickname">
  <input id="t" placeholder="Mesaj yaz…" maxlength="500" autocomplete="off">
  <button id="btn" onclick="send()">Gönder</button>
</div>
<script>
let CSRF_TOKEN = '';
let lastCount  = 0;
let sending    = false;
let retryDelay = 3000;

async function initCsrf(){
  try{
    const r = await fetch('/api/csrf');
    if(r.ok){ const d = await r.json(); CSRF_TOKEN = d.token || ''; }
  }catch(_){}
}

function makeMsg(m, isMe){
  const wrap = document.createElement('div');
  wrap.className = 'm ' + (isMe ? 'mine' : 'other');
  if(!isMe){
    const nd = document.createElement('div');
    nd.className = 'name';
    nd.textContent = m.user;
    wrap.appendChild(nd);
  }
  const td = document.createElement('div');
  td.innerHTML = m.text;
  wrap.appendChild(td);
  const ts = document.createElement('div');
  ts.className = 'time';
  ts.textContent = m.time;
  wrap.appendChild(ts);
  return wrap;
}

async function load(){
  try{
    const r = await fetch('/api/messages');
    if(r.status === 503){
      document.getElementById('status').textContent = 'Sunucu meşgul, bekleniyor…';
      retryDelay = Math.min(retryDelay * 2, 30000);
      return;
    }
    if(!r.ok) return;
    retryDelay = 3000;
    const msgs = await r.json();
    if(msgs.length === lastCount) return;
    lastCount = msgs.length;
    const box = document.getElementById('box');
    const me  = localStorage.getItem('chatname') || '';
    if(msgs.length === 0){
      box.innerHTML = '<div class="empty">Henüz mesaj yok. İlk mesajı sen gönder! 🎉</div>';
      return;
    }
    const atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 60;
    box.innerHTML  = '';
    msgs.forEach(m => box.appendChild(makeMsg(m, m.user === me)));
    if(atBottom) box.scrollTop = box.scrollHeight;
    document.getElementById('status').textContent = '';
  }catch(_){
    document.getElementById('status').textContent = 'Bağlantı sorunu…';
  }
}

async function send(){
  if(sending) return;
  const uEl = document.getElementById('u');
  const tEl = document.getElementById('t');
  const btn = document.getElementById('btn');
  const u   = uEl.value.trim() || 'Anonim';
  const t   = tEl.value.trim();
  if(!t) return;
  sending = true;
  btn.disabled = true;
  localStorage.setItem('chatname', u);
  tEl.value = '';
  try{
    const r = await fetch('/api/send', {
      method : 'POST',
      headers: {'Content-Type':'application/json','X-CSRF-Token':CSRF_TOKEN},
      body: JSON.stringify({user: u, text: t})
    });
    const data = await r.json();
    if(data.error){ document.getElementById('status').textContent = data.error; tEl.value = t; }
    else { load(); }
  }catch(_){
    document.getElementById('status').textContent = 'Gönderilemedi, tekrar dene.';
    tEl.value = t;
  }
  sending = false;
  btn.disabled = false;
  tEl.focus();
}

document.getElementById('u').value = localStorage.getItem('chatname') || '';
document.getElementById('t').addEventListener('keydown', e => {
  if(e.key === 'Enter' && !e.shiftKey){ e.preventDefault(); send(); }
});

function scheduleLoad(){
  setTimeout(() => { load().then(() => scheduleLoad()); }, retryDelay);
}
initCsrf().then(() => { load(); scheduleLoad(); });
</script>
</body></html>"""


# ══════════════════════════════════════════
#  ROUTE'LAR
# ══════════════════════════════════════════

@app.route('/')
def index():
    ip = get_ip()
    if check_circuit_breaker():
        return "Sunucu meşgul, kısa süre sonra tekrar dene.", 503
    if is_banned(ip):
        return "Erişim engellendi.", 403
    if not validate_user_agent(ip):
        return "Geçersiz istemci.", 400
    if is_rate_limited(ip, write=False):
        return "Çok fazla istek. Lütfen bekleyin.", 429
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return render_template_string(HTML)


@app.route('/api/csrf')
@ddos_guard(write=False)
def csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return jsonify({'token': session['csrf_token']})


@app.route('/api/messages')
@ddos_guard(write=False)
def messages():
    with MSGS_LOCK:
        return jsonify(list(MSGS))


@app.route('/api/send', methods=['POST'])
@require_json
@validate_csrf
@ddos_guard(write=True)
def send_msg():
    ip   = get_ip()
    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({'error': 'Geçersiz istek.'}), 400
    text = sanitize(data.get('text', ''), max_len=MAX_MSG_LEN)
    user = sanitize(data.get('user', 'Anonim'), max_len=MAX_NAME_LEN)
    if not text:
        return jsonify({'error': 'Mesaj boş olamaz.'}), 400
    if check_payload_repeat(ip, f"{user}:{text}"):
        return jsonify({'error': 'Aynı mesajı tekrar gönderemezsin.'}), 429
    msg = {'user': user or 'Anonim', 'text': text, 'time': datetime.now().strftime('%H:%M')}
    with MSGS_LOCK:
        MSGS.append(msg)
        if len(MSGS) > MAX_MSGS:
            MSGS.pop(0)
    return jsonify({'ok': True})


@app.route('/api/send_raw', methods=['POST'])
@require_json
@ddos_guard(write=True)
def send_raw():
    ip   = get_ip()
    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({'ok': False, 'error': 'No data'}), 400
    text = sanitize(data.get('text', ''), max_len=MAX_MSG_LEN)
    user = sanitize(data.get('user', 'Anonim'), max_len=MAX_NAME_LEN)
    if not text:
        return jsonify({'ok': False, 'error': 'Empty message'}), 400
    if check_payload_repeat(ip, f"{user}:{text}"):
        return jsonify({'ok': False, 'error': 'Duplicate payload'}), 429
    msg = {'user': user or 'Anonim', 'text': text, 'time': datetime.now().strftime('%H:%M')}
    with MSGS_LOCK:
        MSGS.append(msg)
        if len(MSGS) > MAX_MSGS:
            MSGS.pop(0)
        total = len(MSGS)
    return jsonify({'ok': True, 'total': total})


@app.route('/api/health')
@ddos_guard(write=False)
def health():
    with MSGS_LOCK:
        msg_count = len(MSGS)
    with _ddos_lock:
        circuit_status = "open" if CIRCUIT_OPEN else "closed"
        banned_count   = len(BANNED_IPS)
        suspect_count  = len(SUSPICIOUS_IPS)
    return jsonify({
        'status'     : 'ok',
        'messages'   : msg_count,
        'circuit'    : circuit_status,
        'banned_ips' : banned_count,
        'suspect_ips': suspect_count,
        'time'       : datetime.now().isoformat()
    })


# ══════════════════════════════════════════
#  HATA YÖNETİCİLERİ
# ══════════════════════════════════════════

@app.errorhandler(413)
def too_large(_):    return jsonify({'error': 'İstek boyutu çok büyük.'}), 413

@app.errorhandler(404)
def not_found(_):    return jsonify({'error': 'Sayfa bulunamadı.'}), 404

@app.errorhandler(405)
def method_not_allowed(_): return jsonify({'error': 'Bu method izinli değil.'}), 405

@app.errorhandler(500)
def server_error(_): return jsonify({'error': 'Sunucu hatası.'}), 500


if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(host='0.0.0.0', port=5000, debug=debug_mode)
