from flask import Flask, request, jsonify, render_template_string, session
from datetime import datetime
from functools import wraps
import time, re, html, secrets, os, threading

app = Flask(__name__)

# ——— UYGULAMA AYARLARI ———
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['MAX_CONTENT_LENGTH'] = 4 * 1024  # Max 4 KB istek boyutu

# ——— VERİ DEPOLARI ———
MSGS = []
MSGS_LOCK = threading.Lock()

# Rate limit verileri
_rl_lock      = threading.Lock()
RATE_LIMIT    = {}   # "{ip}:{r|w}" → [timestamp listesi]
BANNED_IPS    = {}   # ip → ban_until (0 = kalıcı)
LAST_MSG_TIME = {}   # ip → son mesaj zamanı (flood kontrolü)

# ——— SABİTLER ———
MAX_READ_REQ      = 60    # WINDOW saniyede max okuma isteği
MAX_WRITE_REQ     = 10    # WINDOW saniyede max yazma isteği
WINDOW            = 60    # saniye
MAX_MSG_LEN       = 500
MAX_NAME_LEN      = 20
MIN_MSG_INTERVAL  = 1.5   # aynı IP'den min süre (saniye)
TEMP_BAN_DURATION = 300   # geçici ban süresi (5 dakika)
MAX_MSGS          = 200   # bellekte tutulacak max mesaj


# ══════════════════════════════════════════
#  YARDIMCI FONKSİYONLAR
# ══════════════════════════════════════════

def get_ip() -> str:
    """Proxy arkasındaki gerçek IP'yi güvenli şekilde al."""
    forwarded = request.headers.get('X-Forwarded-For', '')
    ip = (forwarded.split(',')[0].strip()
          or request.headers.get('X-Real-IP', '')
          or request.remote_addr
          or '0.0.0.0')
    return ip[:45]  # IPv6 max uzunluğu


def is_banned(ip: str) -> bool:
    """IP banını kontrol et; süresi dolmuş geçici banları temizle."""
    with _rl_lock:
        if ip not in BANNED_IPS:
            return False
        ban_until = BANNED_IPS[ip]
        if ban_until == 0:             # kalıcı ban
            return True
        if time.time() < ban_until:    # geçici ban devam ediyor
            return True
        del BANNED_IPS[ip]             # ban süresi doldu → sil
        return False


def is_rate_limited(ip: str, write: bool = False) -> bool:
    """
    write=True  → yazma limiti (daha sıkı)
    write=False → okuma limiti
    Limit aşılırsa ilk seferinde geçici, tekrarda kalıcı ban.
    """
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
            # Zaten geçici banlıysa kalıcı bana yükselt
            prev = BANNED_IPS.get(ip)
            BANNED_IPS[ip] = 0 if prev is not None else now + TEMP_BAN_DURATION
            return True
    return False


def is_flood(ip: str) -> bool:
    """Aynı IP'den çok hızlı mesaj gönderimini engelle."""
    now = time.time()
    with _rl_lock:
        if now - LAST_MSG_TIME.get(ip, 0) < MIN_MSG_INTERVAL:
            return True
        LAST_MSG_TIME[ip] = now
    return False


def sanitize(text, max_len: int = None) -> str:
    """Girdiyi temizle: XSS, null byte, kontrol karakterleri."""
    if not isinstance(text, str):
        return ''
    text = text.strip()
    if max_len:
        text = text[:max_len]
    # Null byte ve zararlı kontrol karakterlerini sil
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
    # HTML özel karakterlerini kaçır (XSS koruması)
    text = html.escape(text)
    # Aşırı boşluk / satır sıkıştır
    text = re.sub(r'\n{3,}', '\n\n', text)
    text = re.sub(r' {5,}', '    ', text)
    return text


def require_json(f):
    """POST isteklerinde Content-Type: application/json zorunlu kıl."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method == 'POST':
            ct = request.content_type or ''
            if 'application/json' not in ct:
                return jsonify({'error': 'Content-Type application/json olmalı.'}), 415
        return f(*args, **kwargs)
    return decorated


def validate_csrf(f):
    """
    Basit CSRF token doğrulaması.
    Token ilk sayfa yüklemesinde session'a atanır;
    her POST isteğinde X-CSRF-Token başlığı ile doğrulanır.
    """
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
    return response


@app.after_request
def after_request(response):
    return add_security_headers(response)


# ══════════════════════════════════════════
#  ARKA PLAN TEMİZLİK (Memory Leak Önleme)
# ══════════════════════════════════════════

def _cleanup_loop():
    while True:
        time.sleep(300)  # 5 dakikada bir temizle
        now = time.time()
        with _rl_lock:
            # Süresi dolmuş rate-limit kayıtları
            stale_rl = [k for k, v in list(RATE_LIMIT.items())
                        if not any(now - t < WINDOW for t in v)]
            for k in stale_rl:
                del RATE_LIMIT[k]

            # Süresi dolmuş geçici banlar
            expired_bans = [ip for ip, until in list(BANNED_IPS.items())
                            if until != 0 and now > until]
            for ip in expired_bans:
                del BANNED_IPS[ip]

            # Eski flood kayıtları (1 saattir mesaj yok)
            old_flood = [ip for ip, t in list(LAST_MSG_TIME.items())
                         if now - t > 3600]
            for ip in old_flood:
                del LAST_MSG_TIME[ip]


threading.Thread(target=_cleanup_loop, daemon=True).start()


# ══════════════════════════════════════════
#  HTML ŞABLONU
# ══════════════════════════════════════════

HTML = """<!DOCTYPE html>
<html lang="tr"><head>
<meta charset="UTF-8">
<title>💬 GGpro0320</title>
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

/* CSRF tokenini sunucudan al */
async function initCsrf(){
  try{
    const r = await fetch('/api/csrf');
    if(r.ok){ const d = await r.json(); CSRF_TOKEN = d.token || ''; }
  }catch(_){}
}

/* Mesaj DOM elemanı güvenli şekilde oluştur (innerHTML yerine DOM API) */
function makeMsg(m, isMe){
  const wrap = document.createElement('div');
  wrap.className = 'm ' + (isMe ? 'mine' : 'other');

  if(!isMe){
    const nd = document.createElement('div');
    nd.className = 'name';
    nd.textContent = m.user;   // textContent → XSS yok
    wrap.appendChild(nd);
  }

  const td = document.createElement('div');
  // Sunucu html.escape() yaptığı için innerHTML ile gösterim güvenli.
  // Kaçırılmış karakterler (&lt; vb.) doğru render edilir.
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
    if(!r.ok) return;
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
      headers: {
        'Content-Type' : 'application/json',
        'X-CSRF-Token' : CSRF_TOKEN
      },
      body: JSON.stringify({user: u, text: t})
    });
    const data = await r.json();
    if(data.error){
      document.getElementById('status').textContent = data.error;
      tEl.value = t;
    } else {
      load();
    }
  }catch(_){
    document.getElementById('status').textContent = 'Gönderilemedi, tekrar dene.';
    tEl.value = t;
  }

  sending = false;
  btn.disabled = false;
  tEl.focus();
}

document.getElementById('u').value =
  localStorage.getItem('chatname') || '';
document.getElementById('t').addEventListener('keydown', e => {
  if(e.key === 'Enter' && !e.shiftKey){ e.preventDefault(); send(); }
});

initCsrf().then(() => { load(); setInterval(load, 3000); });
</script>
</body></html>"""


# ══════════════════════════════════════════
#  ROUTE'LAR
# ══════════════════════════════════════════

@app.route('/')
def index():
    ip = get_ip()
    if is_rate_limited(ip, write=False):
        return "Çok fazla istek. Lütfen bekleyin.", 429
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return render_template_string(HTML)


@app.route('/api/csrf')
def csrf_token():
    """İstemciye mevcut CSRF tokenini döndür."""
    ip = get_ip()
    if is_rate_limited(ip, write=False):
        return jsonify({'error': 'Rate limit'}), 429
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return jsonify({'token': session['csrf_token']})


@app.route('/api/messages')
def messages():
    ip = get_ip()
    if is_rate_limited(ip, write=False):
        return jsonify({'error': 'Rate limit'}), 429
    with MSGS_LOCK:
        return jsonify(list(MSGS))


@app.route('/api/send', methods=['POST'])
@require_json
@validate_csrf
def send_msg():
    ip = get_ip()
    if is_banned(ip):
        return jsonify({'error': 'Erişim engellendi.'}), 403
    if is_rate_limited(ip, write=True):
        return jsonify({'error': 'Çok hızlı! Biraz bekle.'}), 429
    if is_flood(ip):
        return jsonify({'error': 'Çok hızlı mesaj gönderiyorsun!'}), 429

    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({'error': 'Geçersiz istek.'}), 400

    text = sanitize(data.get('text', ''), max_len=MAX_MSG_LEN)
    user = sanitize(data.get('user', 'Anonim'), max_len=MAX_NAME_LEN)

    if not text:
        return jsonify({'error': 'Mesaj boş olamaz.'}), 400
    if len(text) > MAX_MSG_LEN:
        return jsonify({'error': 'Mesaj çok uzun.'}), 400

    msg = {
        'user': user or 'Anonim',
        'text': text,
        'time': datetime.now().strftime('%H:%M')
    }
    with MSGS_LOCK:
        MSGS.append(msg)
        if len(MSGS) > MAX_MSGS:
            MSGS.pop(0)

    return jsonify({'ok': True})


@app.route('/api/send_raw', methods=['POST'])
@require_json
def send_raw():
    """C# / harici istemci için JSON API endpoint — CSRF muaf, kendi doğrulamasıyla."""
    ip = get_ip()
    if is_banned(ip):
        return jsonify({'ok': False, 'error': 'Banned'}), 403
    if is_rate_limited(ip, write=True):
        return jsonify({'ok': False, 'error': 'Rate limited'}), 429
    if is_flood(ip):
        return jsonify({'ok': False, 'error': 'Flood'}), 429

    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({'ok': False, 'error': 'No data'}), 400

    text = sanitize(data.get('text', ''), max_len=MAX_MSG_LEN)
    user = sanitize(data.get('user', 'Anonim'), max_len=MAX_NAME_LEN)

    if not text:
        return jsonify({'ok': False, 'error': 'Empty message'}), 400

    msg = {
        'user': user or 'Anonim',
        'text': text,
        'time': datetime.now().strftime('%H:%M')
    }
    with MSGS_LOCK:
        MSGS.append(msg)
        if len(MSGS) > MAX_MSGS:
            MSGS.pop(0)
        total = len(MSGS)

    return jsonify({'ok': True, 'total': total})


@app.route('/api/health')
def health():
    ip = get_ip()
    if is_rate_limited(ip, write=False):
        return jsonify({'error': 'Rate limit'}), 429
    with MSGS_LOCK:
        msg_count = len(MSGS)
    return jsonify({
        'status'  : 'ok',
        'messages': msg_count,
        'time'    : datetime.now().isoformat()
    })


# ══════════════════════════════════════════
#  HATA YÖNETİCİLERİ
# ══════════════════════════════════════════

@app.errorhandler(413)
def too_large(_):
    return jsonify({'error': 'İstek boyutu çok büyük.'}), 413

@app.errorhandler(404)
def not_found(_):
    return jsonify({'error': 'Sayfa bulunamadı.'}), 404

@app.errorhandler(405)
def method_not_allowed(_):
    return jsonify({'error': 'Bu method izinli değil.'}), 405

@app.errorhandler(500)
def server_error(_):
    return jsonify({'error': 'Sunucu hatası.'}), 500


# ══════════════════════════════════════════
#  BAŞLATMA
# ══════════════════════════════════════════

if __name__ == '__main__':
    # Üretim ortamında debug=False ve güvenilir bir WSGI sunucusu kullan
    # Örn: gunicorn -w 4 app:app
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(host='0.0.0.0', port=5000, debug=debug_mode)
