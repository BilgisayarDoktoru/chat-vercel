from flask import Flask, request, jsonify, render_template_string, session
from datetime import datetime
from functools import wraps
import time, re, html, secrets, os, threading, hashlib, collections

app = Flask(__name__)

# ——— UYGULAMA AYARLARI ———
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['MAX_CONTENT_LENGTH'] = 4 * 1024  # Max 4 KB istek boyutu
app.config['SESSION_COOKIE_SECURE'] = not os.environ.get('FLASK_DEBUG')
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'

# ——— VERİ DEPOLARI ———
MSGS = []
MSGS_LOCK = threading.Lock()

_rl_lock      = threading.Lock()
RATE_LIMIT    = {}
BANNED_IPS    = {}
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
UA_REQUIRED_MIN_LEN = 8


# ══════════════════════════════════════════
#  YARDIMCI FONKSİYONLAR
# ══════════════════════════════════════════

def get_ip() -> str:
    """IP adresini güvenli bir şekilde al."""
    forwarded = request.headers.get('X-Forwarded-For', '')
    ip = (forwarded.split(',')[0].strip()
          or request.headers.get('X-Real-IP', '')
          or request.remote_addr
          or '0.0.0.0')
    return ip[:45]


def is_banned(ip: str) -> bool:
    """IP banlanmış mı kontrol et."""
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
    """Üstel backoff ile IP banlama."""
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
    """Rate limiting kontrol et."""
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
    """Mesaj flood'u kontrol et."""
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
    """Global circuit breaker kontrolü."""
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
    """User-Agent doğrulama (daha toleranslı)."""
    ua = request.headers.get('User-Agent', '').lower()
    
    # Boş veya çok kısa UA'yı reddet
    if not ua or len(ua) < UA_REQUIRED_MIN_LEN:
        with _ddos_lock:
            count = UA_VIOLATIONS.get(ip, 0) + 1
            UA_VIOLATIONS[ip] = count
            if count >= 3:
                ban_ip(ip)
        return False
    
    # Bilinen kötü amaçlı araçları kontrol et
    if any(pattern in ua for pattern in UA_BLOCK_LIST):
        with _ddos_lock:
            count = UA_VIOLATIONS.get(ip, 0) + 1
            UA_VIOLATIONS[ip] = count
            if count >= 3:
                ban_ip(ip)
        return False
    
    return True


def check_payload_repeat(ip: str, payload: str) -> bool:
    """Aynı payload tekrarı kontrolü."""
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
    """Şüphe puanı ekle."""
    with _ddos_lock:
        score = SUSPICIOUS_IPS.get(ip, 0) + points
        SUSPICIOUS_IPS[ip] = score
        if score >= SUSPECT_SCORE_BAN:
            ban_ip(ip)


def ddos_guard(write: bool = False):
    """DDoS koruması dekoratörü."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            ip = get_ip()
            if check_circuit_breaker():
                return jsonify({'error': 'Sunucu meşgul, tekrar dene.'}), 503
            if is_banned(ip):
                return jsonify({'error': 'Erişim engellendi.'}), 403
            if not validate_user_agent(ip):
                return jsonify({'error': 'Geçersiz istemci.'}), 400
            if is_rate_limited(ip, write=write):
                add_suspicion(ip, 10)
                return jsonify({'error': 'Çok fazla istek.'}), 429
            if write and is_flood(ip):
                add_suspicion(ip, 15)
                return jsonify({'error': 'Çok hızlı!'}), 429
            return f(*args, **kwargs)
        return decorated
    return decorator


def sanitize(text, max_len: int = None) -> str:
    """Metni temizle ve güvenli hale getir."""
    if not isinstance(text, str):
        return ''
    text = text.strip()
    if max_len:
        text = text[:max_len]
    # Kontrol karakterlerini kaldır
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
    # HTML escape
    text = html.escape(text)
    # Aşırı satır ve boşluk kısıt
    text = re.sub(r'\n{3,}', '\n\n', text)
    text = re.sub(r' {5,}', '    ', text)
    return text


def require_json(f):
    """JSON Content-Type gerekli."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method == 'POST':
            ct = request.content_type or ''
            if 'application/json' not in ct:
                return jsonify({'error': 'Content-Type application/json olmalı.'}), 415
        return f(*args, **kwargs)
    return decorated


def validate_csrf(f):
    """CSRF token doğrulama."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('X-CSRF-Token', '')
        if not token or token != session.get('csrf_token'):
            return jsonify({'error': 'Geçersiz token.'}), 403
        return f(*args, **kwargs)
    return decorated


# ══════════════════════════════════════════
#  GÜVENLİK BAŞLIKLARI
# ══════════════════════════════════════════

def add_security_headers(response):
    """Güvenlik başlıkları ekle."""
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
#  ARKA PLAN TEMİZLİK
# ══════════════════════════════════════════

def _cleanup_loop():
    """Periyodik veri temizleme."""
    while True:
        time.sleep(300)
        now = time.time()
        
        with _rl_lock:
            # Eski rate limit verileri sil
            stale_rl = [k for k, v in list(RATE_LIMIT.items())
                        if not any(now - t < WINDOW for t in v)]
            for k in stale_rl:
                del RATE_LIMIT[k]
            
            # Süresi dolmuş banları sil
            expired = [ip for ip, e in list(BANNED_IPS.items())
                       if e["until"] != 0 and now > e["until"]]
            for ip in expired:
                del BANNED_IPS[ip]
            
            # Eski flood kayıtlarını sil
            old_flood = [ip for ip, t in list(LAST_MSG_TIME.items())
                         if now - t > 3600]
            for ip in old_flood:
                del LAST_MSG_TIME[ip]

        with _ddos_lock:
            # IP başına 50'den fazla hash'i sıfırla
            for ip in list(PAYLOAD_HASHES.keys()):
                if len(PAYLOAD_HASHES[ip]) > 50:
                    PAYLOAD_HASHES[ip] = {}
            
            # Şüphe skorunu azalt
            for ip in list(SUSPICIOUS_IPS.keys()):
                SUSPICIOUS_IPS[ip] = max(0, SUSPICIOUS_IPS[ip] - 10)
                if SUSPICIOUS_IPS[ip] == 0:
                    del SUSPICIOUS_IPS[ip]
            
            # UA ihlal sayacını azalt
            for ip in list(UA_VIOLATIONS.keys()):
                UA_VIOLATIONS[ip] = max(0, UA_VIOLATIONS[ip] - 1)
                if UA_VIOLATIONS[ip] == 0:
                    del UA_VIOLATIONS[ip]


threading.Thread(target=_cleanup_loop, daemon=True).start()


# ══════════════════════════════════════════
#  HTML ŞABLONU (MOBİL OPTİMİZE)
# ══════════════════════════════════════════

HTML = """<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
  <meta name="description" content="Güvenli Genel Sohbet">
  <meta name="theme-color" content="#075e54">
  <title>💬 Sohbet</title>
  <style>
    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
      -webkit-touch-callout: none;
      -webkit-user-select: none;
      user-select: none;
    }
    
    html, body {
      width: 100%;
      height: 100%;
      display: flex;
      flex-direction: column;
    }
    
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #f0f2f5;
      color: #1a1a1a;
    }
    
    header {
      background: linear-gradient(135deg, #075e54 0%, #064e46 100%);
      color: white;
      padding: 12px 16px;
      font-size: 16px;
      font-weight: 600;
      display: flex;
      justify-content: space-between;
      align-items: center;
      box-shadow: 0 2px 8px rgba(0,0,0,.12);
      flex-shrink: 0;
      gap: 8px;
    }
    
    #online {
      font-size: 12px;
      opacity: 0.85;
      font-weight: 500;
    }
    
    #status {
      min-height: 18px;
      padding: 6px 12px;
      text-align: center;
      font-size: 12px;
      color: #d32f2f;
      background: #ffebee;
      flex-shrink: 0;
      display: none;
    }
    
    #status.show {
      display: block;
    }
    
    #box {
      flex: 1;
      overflow-y: auto;
      padding: 12px;
      display: flex;
      flex-direction: column;
      gap: 6px;
      -webkit-overflow-scrolling: touch;
    }
    
    #box.empty::after {
      content: '📭 Henüz mesaj yok';
      text-align: center;
      color: #999;
      margin: auto;
      font-size: 14px;
    }
    
    .msg {
      max-width: 85%;
      padding: 10px 14px;
      border-radius: 16px;
      font-size: 14px;
      line-height: 1.4;
      word-break: break-word;
      animation: slideIn 0.2s ease-out;
    }
    
    @keyframes slideIn {
      from {
        opacity: 0;
        transform: translateY(8px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }
    
    .msg.mine {
      background: #dcf8c6;
      align-self: flex-end;
      border-bottom-right-radius: 4px;
      margin-right: 8px;
    }
    
    .msg.other {
      background: white;
      align-self: flex-start;
      border-bottom-left-radius: 4px;
      margin-left: 8px;
      box-shadow: 0 1px 2px rgba(0,0,0,.08);
    }
    
    .msg-name {
      font-size: 11px;
      font-weight: 600;
      color: #075e54;
      margin-bottom: 4px;
      opacity: 0.9;
    }
    
    .msg-text {
      word-break: break-word;
      white-space: pre-wrap;
    }
    
    .msg-time {
      font-size: 11px;
      color: #888;
      margin-top: 4px;
      opacity: 0.8;
    }
    
    .form {
      display: flex;
      padding: 10px;
      gap: 8px;
      background: white;
      border-top: 1px solid #ddd;
      flex-shrink: 0;
      align-items: flex-end;
    }
    
    .form input {
      font-size: 16px;
      padding: 11px 14px;
      border: 1.5px solid #ddd;
      border-radius: 20px;
      outline: none;
      font-family: inherit;
      transition: border-color 0.2s;
      -webkit-appearance: none;
      appearance: none;
    }
    
    .form input:focus {
      border-color: #075e54;
      background: #f9f9f9;
    }
    
    #name {
      width: 100px;
      flex-shrink: 0;
    }
    
    #text {
      flex: 1;
      min-height: 40px;
      max-height: 100px;
      resize: none;
      border: 1.5px solid #ddd;
      border-radius: 20px;
    }
    
    .form button {
      background: #075e54;
      color: white;
      border: none;
      padding: 11px 22px;
      border-radius: 20px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      transition: background 0.2s, transform 0.1s;
      flex-shrink: 0;
      -webkit-appearance: none;
      appearance: none;
      active: transparent;
    }
    
    .form button:active {
      transform: scale(0.95);
    }
    
    .form button:disabled {
      background: #ccc;
      cursor: not-allowed;
      opacity: 0.6;
    }
    
    @media (max-width: 480px) {
      header {
        padding: 10px 12px;
        font-size: 15px;
      }
      
      #name {
        width: 85px;
        font-size: 13px;
      }
      
      .form {
        padding: 8px;
        gap: 6px;
      }
      
      .form input {
        padding: 10px 12px;
        font-size: 15px;
      }
      
      .msg {
        max-width: 90%;
        padding: 9px 12px;
        font-size: 13px;
      }
    }
    
    /* Scroll göstergesi */
    #box::-webkit-scrollbar {
      width: 6px;
    }
    
    #box::-webkit-scrollbar-track {
      background: transparent;
    }
    
    #box::-webkit-scrollbar-thumb {
      background: #ccc;
      border-radius: 3px;
    }
    
    #box::-webkit-scrollbar-thumb:active {
      background: #999;
    }
  </style>
</head>
<body>
<header>
  <span>💬 Sohbet</span>
  <span id="online">0 online</span>
</header>
<div id="status"></div>
<div id="box" class="empty"></div>
<div class="form">
  <input 
    id="name" 
    type="text" 
    placeholder="Adın"
    maxlength="20"
    autocomplete="off"
    inputmode="text"
  >
  <input 
    id="text" 
    type="text" 
    placeholder="Mesaj…"
    maxlength="500"
    autocomplete="off"
    inputmode="text"
  >
  <button id="btn" type="button">Gönder</button>
</div>

<script>
const app = {
  csrfToken: '',
  lastMsgHash: '',
  sending: false,
  pollDelay: 3000,
  pollId: null,
  
  async initCsrf() {
    try {
      const res = await fetch('/api/csrf');
      if (res.ok) {
        const data = await res.json();
        this.csrfToken = data.token || '';
      }
    } catch (e) {
      console.error('CSRF yükleme hatası:', e);
    }
  },
  
  showStatus(msg, isError = true) {
    const el = document.getElementById('status');
    el.textContent = msg;
    el.classList.toggle('show', !!msg);
    if (isError) {
      el.style.color = '#d32f2f';
      el.style.background = '#ffebee';
    } else {
      el.style.color = '#f57c00';
      el.style.background = '#ffe0b2';
    }
  },
  
  makeMsg(m, isMine) {
    const div = document.createElement('div');
    div.className = 'msg ' + (isMine ? 'mine' : 'other');
    
    if (!isMine) {
      const nameEl = document.createElement('div');
      nameEl.className = 'msg-name';
      nameEl.textContent = m.user;
      div.appendChild(nameEl);
    }
    
    const textEl = document.createElement('div');
    textEl.className = 'msg-text';
    textEl.innerHTML = m.text;
    div.appendChild(textEl);
    
    const timeEl = document.createElement('div');
    timeEl.className = 'msg-time';
    timeEl.textContent = m.time;
    div.appendChild(timeEl);
    
    return div;
  },
  
  async loadMessages() {
    try {
      const res = await fetch('/api/messages');
      
      if (res.status === 503) {
        this.showStatus('Sunucu meşgul…');
        this.pollDelay = Math.min(this.pollDelay * 1.5, 30000);
        return;
      }
      
      if (!res.ok) return;
      
      const msgs = await res.json();
      const newHash = JSON.stringify(msgs);
      
      if (newHash === this.lastMsgHash) return;
      
      this.lastMsgHash = newHash;
      this.pollDelay = 3000;
      this.showStatus('');
      
      const box = document.getElementById('box');
      const userName = localStorage.getItem('chatName') || '';
      
      if (!msgs.length) {
        box.innerHTML = '';
        box.classList.add('empty');
        return;
      }
      
      const wasAtBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 60;
      box.classList.remove('empty');
      box.innerHTML = '';
      
      msgs.forEach(m => {
        box.appendChild(this.makeMsg(m, m.user === userName));
      });
      
      if (wasAtBottom) {
        setTimeout(() => box.scrollTop = box.scrollHeight, 0);
      }
    } catch (e) {
      this.showStatus('Bağlantı sorunu');
      console.error('Load hatası:', e);
    }
  },
  
  async send() {
    if (this.sending) return;
    
    const nameEl = document.getElementById('name');
    const textEl = document.getElementById('text');
    const btn = document.getElementById('btn');
    
    const name = nameEl.value.trim() || 'Anonim';
    const text = textEl.value.trim();
    
    if (!text) {
      textEl.focus();
      return;
    }
    
    this.sending = true;
    btn.disabled = true;
    
    localStorage.setItem('chatName', name);
    const originalText = text;
    textEl.value = '';
    textEl.style.height = 'auto';
    
    try {
      const res = await fetch('/api/send', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': this.csrfToken
        },
        body: JSON.stringify({ user: name, text })
      });
      
      const data = await res.json();
      
      if (data.error) {
        this.showStatus(data.error);
        textEl.value = originalText;
      } else {
        await this.loadMessages();
      }
    } catch (e) {
      this.showStatus('Gönderilemedi');
      textEl.value = originalText;
      console.error('Send hatası:', e);
    }
    
    this.sending = false;
    btn.disabled = false;
    textEl.focus();
  },
  
  setupEventHandlers() {
    const textEl = document.getElementById('text');
    const btn = document.getElementById('btn');
    
    // Enter tuşu (Shift+Enter = yeni satır)
    textEl.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        this.send();
      }
    });
    
    // Auto-resize textarea
    textEl.addEventListener('input', () => {
      textEl.style.height = 'auto';
      textEl.style.height = Math.min(textEl.scrollHeight, 100) + 'px';
    });
    
    btn.addEventListener('click', () => this.send());
    
    // Giriş işlemi (localStorage'dan ismi geri yükle)
    document.getElementById('name').value = localStorage.getItem('chatName') || '';
  },
  
  schedulePoll() {
    this.pollId = setTimeout(() => {
      this.loadMessages().then(() => this.schedulePoll());
    }, this.pollDelay);
  },
  
  async init() {
    await this.initCsrf();
    this.setupEventHandlers();
    await this.loadMessages();
    this.schedulePoll();
  }
};

// Başlat
app.init();
  </script>
</body>
</html>"""


# ══════════════════════════════════════════
#  ROUTE'LAR
# ══════════════════════════════════════════

@app.route('/')
def index():
    """Ana sayfa."""
    ip = get_ip()
    
    if check_circuit_breaker():
        return "Sunucu meşgul.", 503
    if is_banned(ip):
        return "Erişim engellendi.", 403
    if not validate_user_agent(ip):
        return "Geçersiz istemci.", 400
    if is_rate_limited(ip, write=False):
        return "Çok fazla istek.", 429
    
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    
    return render_template_string(HTML)


@app.route('/api/csrf')
@ddos_guard(write=False)
def csrf_token():
    """CSRF token oluştur."""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return jsonify({'token': session['csrf_token']})


@app.route('/api/messages')
@ddos_guard(write=False)
def messages():
    """Tüm mesajları döndür."""
    with MSGS_LOCK:
        return jsonify(list(MSGS))


@app.route('/api/send', methods=['POST'])
@require_json
@validate_csrf
@ddos_guard(write=True)
def send_msg():
    """Mesaj gönder."""
    ip   = get_ip()
    data = request.get_json(silent=True)
    
    if not data or not isinstance(data, dict):
        return jsonify({'error': 'Hatalı istek.'}), 400
    
    text = sanitize(data.get('text', ''), max_len=MAX_MSG_LEN)
    user = sanitize(data.get('user', 'Anonim'), max_len=MAX_NAME_LEN)
    
    if not text:
        return jsonify({'error': 'Mesaj boş olamaz.'}), 400
    
    if check_payload_repeat(ip, f"{user}:{text}"):
        return jsonify({'error': 'Tekrar gönderemezsin.'}), 429
    
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


@app.route('/api/health')
@ddos_guard(write=False)
def health():
    """Sağlık durumu."""
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
        'suspect_ips': suspect_count
    })


# ══════════════════════════════════════════
#  HATA YÖNETİCİLERİ
# ══════════════════════════════════════════

@app.errorhandler(413)
def too_large(_):
    return jsonify({'error': 'İstek çok büyük.'}), 413

@app.errorhandler(404)
def not_found(_):
    return jsonify({'error': 'Bulunamadı.'}), 404

@app.errorhandler(405)
def method_not_allowed(_):
    return jsonify({'error': 'Method izinli değil.'}), 405

@app.errorhandler(500)
def server_error(_):
    return jsonify({'error': 'Sunucu hatası.'}), 500


if __name__ == '__main__':
    debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(host='0.0.0.0', port=5000, debug=debug, threaded=True)
