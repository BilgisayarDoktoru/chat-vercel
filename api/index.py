from flask import Flask, request, jsonify, render_template_string
from datetime import datetime, timedelta
from collections import defaultdict
import time, re, html

app = Flask(__name__)
MSGS = []

# ——— GÜVENLİK ———
RATE_LIMIT = {}          # IP → [timestamp listesi]
BANNED_IPS = set()       # Kalıcı banlı IP'ler
MAX_REQ = 20             # 10 saniyede max istek
WINDOW = 10              # saniye
MAX_MSG_LEN = 500
MAX_NAME_LEN = 20
MIN_MSG_INTERVAL = 1.0   # aynı IP'den min 1 sn arayla mesaj

last_msg_time = {}       # IP → son mesaj zamanı

def get_ip():
    # Vercel proxy arkasından gerçek IP
    return (request.headers.get('X-Forwarded-For','').split(',')[0].strip()
            or request.headers.get('X-Real-IP','')
            or request.remote_addr
            or '0.0.0.0')

def is_rate_limited(ip):
    now = time.time()
    if ip in BANNED_IPS:
        return True
    timestamps = RATE_LIMIT.get(ip, [])
    # Pencere dışındakileri temizle
    timestamps = [t for t in timestamps if now - t < WINDOW]
    timestamps.append(now)
    RATE_LIMIT[ip] = timestamps
    if len(timestamps) > MAX_REQ:
        BANNED_IPS.add(ip)  # Çok fazla istek → ban
        return True
    return False

def is_flood(ip):
    now = time.time()
    last = last_msg_time.get(ip, 0)
    if now - last < MIN_MSG_INTERVAL:
        return True
    last_msg_time[ip] = now
    return False

def sanitize(text):
    # XSS koruması
    text = html.escape(text.strip())
    # Çok fazla boşluk/satır temizle
    text = re.sub(r'\n{3,}', '\n\n', text)
    text = re.sub(r' {5,}', '    ', text)
    return text

def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'"
    response.headers['Referrer-Policy'] = 'no-referrer'
    return response

@app.after_request
def after_request(response):
    return add_security_headers(response)

# ——— HTML ———
HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>💬 GGpro00</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Arial;background:#f0f2f5;display:flex;flex-direction:column;height:100vh}
header{background:#075e54;color:white;padding:15px 20px;font-size:18px;font-weight:bold;box-shadow:0 2px 8px rgba(0,0,0,0.2);display:flex;justify-content:space-between;align-items:center}
#online{font-size:12px;opacity:0.8}
#box{flex:1;overflow-y:auto;padding:15px;display:flex;flex-direction:column;gap:8px}
.m{max-width:72%;padding:9px 13px;border-radius:12px;font-size:14px;line-height:1.5;word-break:break-word}
.mine{background:#dcf8c6;align-self:flex-end;border-radius:12px 2px 12px 12px}
.other{background:white;align-self:flex-start;border-radius:2px 12px 12px 12px;box-shadow:0 1px 3px rgba(0,0,0,0.08)}
.name{font-size:11px;font-weight:bold;color:#075e54;margin-bottom:3px}
.time{font-size:11px;color:#aaa;text-align:right;margin-top:3px}
.form{display:flex;padding:10px;gap:8px;background:white;border-top:1px solid #ddd}
.form input{flex:1;padding:10px 14px;border:1.5px solid #e0e0e0;border-radius:24px;outline:none;font-size:14px}
.form input:focus{border-color:#075e54}
#u{max-width:110px}
.form button{background:#075e54;color:white;border:none;padding:10px 18px;border-radius:24px;cursor:pointer;font-weight:bold;transition:background 0.2s}
.form button:hover{background:#064e46}
.form button:disabled{background:#aaa;cursor:not-allowed}
.empty{text-align:center;color:#aaa;margin-top:60px;font-size:14px}
.error{color:#e74c3c;font-size:12px;text-align:center;padding:4px}
#status{height:16px;text-align:center;font-size:11px;color:#aaa;padding:2px}
</style></head>
<body>
<header>
  <span>💬 Genel Sohbet</span>
  <span id="online"></span>
</header>
<div id="status"></div>
<div id="box"><div class="empty">Henüz mesaj yok. İlk mesajı sen gönder! 🎉</div></div>
<div class="form">
  <input id="u" placeholder="Adın" maxlength="20">
  <input id="t" placeholder="Mesaj yaz..." maxlength="500" autocomplete="off">
  <button id="btn" onclick="send()">Gönder</button>
</div>
<script>
let last=0, sending=false, errorCount=0;

async function load(){
  try{
    const r=await fetch('/api/messages');
    if(!r.ok)return;
    const msgs=await r.json();
    if(msgs.length===last)return;
    last=msgs.length;
    const box=document.getElementById('box');
    const me=localStorage.getItem('chatname')||'';
    if(msgs.length===0){box.innerHTML='<div class="empty">Henüz mesaj yok. İlk mesajı sen gönder! 🎉</div>';return;}
    const atBottom=box.scrollHeight-box.scrollTop-box.clientHeight<60;
    box.innerHTML=msgs.map(m=>`<div class="m ${m.user===me?'mine':'other'}">
      ${m.user!==me?`<div class="name">${m.user}</div>`:''}
      ${m.text}
      <div class="time">${m.time}</div>
    </div>`).join('');
    if(atBottom)box.scrollTop=box.scrollHeight;
    errorCount=0;
    document.getElementById('status').textContent='';
  }catch(e){
    errorCount++;
    if(errorCount>3)document.getElementById('status').textContent='Bağlantı sorunu...';
  }
}

async function send(){
  if(sending)return;
  const uEl=document.getElementById('u');
  const tEl=document.getElementById('t');
  const btn=document.getElementById('btn');
  const u=uEl.value.trim()||'Anonim';
  const t=tEl.value.trim();
  if(!t)return;
  sending=true;
  btn.disabled=true;
  localStorage.setItem('chatname',u);
  tEl.value='';
  try{
    const r=await fetch('/api/send',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({user:u,text:t})
    });
    const data=await r.json();
    if(data.error){
      document.getElementById('status').textContent=data.error;
      tEl.value=t;
    } else {
      load();
    }
  }catch(e){
    document.getElementById('status').textContent='Gönderilemedi, tekrar dene.';
    tEl.value=t;
  }
  sending=false;
  btn.disabled=false;
  tEl.focus();
}

document.getElementById('u').value=localStorage.getItem('chatname')||'';
document.getElementById('t').addEventListener('keydown',e=>{if(e.key==='Enter'&&!e.shiftKey)send();});
setInterval(load,3000);
load();
</script>
</body></html>"""

# ——— ROUTES ———
@app.route('/')
def index():
    ip = get_ip()
    if is_rate_limited(ip):
        return "Çok fazla istek. Lütfen bekleyin.", 429
    return render_template_string(HTML)

@app.route('/api/messages')
def messages():
    ip = get_ip()
    if is_rate_limited(ip):
        return jsonify({'error': 'Rate limit'}), 429
    return jsonify(MSGS)

@app.route('/api/send', methods=['POST'])
def send():
    ip = get_ip()
    if ip in BANNED_IPS:
        return jsonify({'error': 'Erişim engellendi.'}), 403
    if is_rate_limited(ip):
        return jsonify({'error': 'Çok hızlı! Biraz bekle.'}), 429
    if is_flood(ip):
        return jsonify({'error': 'Çok hızlı mesaj gönderiyorsun!'}), 429

    data = request.json
    if not data:
        return jsonify({'error': 'Geçersiz istek.'}), 400

    text = sanitize(data.get('text', ''))
    user = sanitize(data.get('user', 'Anonim'))

    if not text or len(text) > MAX_MSG_LEN:
        return jsonify({'error': 'Geçersiz mesaj.'}), 400
    if len(user) > MAX_NAME_LEN:
        return jsonify({'error': 'İsim çok uzun.'}), 400

    MSGS.append({
        'user': user,
        'text': text,
        'time': datetime.now().strftime('%H:%M')
    })
    if len(MSGS) > 200:
        MSGS.pop(0)
    return jsonify({'ok': True})

# C# / harici istemci için ek endpoint
@app.route('/api/send_raw', methods=['POST'])
def send_raw():
    """C# WinForms için JSON API endpoint"""
    ip = get_ip()
    if ip in BANNED_IPS:
        return jsonify({'ok': False, 'error': 'Banned'}), 403
    if is_rate_limited(ip):
        return jsonify({'ok': False, 'error': 'Rate limited'}), 429
    if is_flood(ip):
        return jsonify({'ok': False, 'error': 'Flood'}), 429

    data = request.json
    if not data:
        return jsonify({'ok': False, 'error': 'No data'}), 400

    text = sanitize(data.get('text', ''))
    user = sanitize(data.get('user', 'Anonim'))

    if not text:
        return jsonify({'ok': False, 'error': 'Empty message'}), 400

    MSGS.append({
        'user': user[:MAX_NAME_LEN],
        'text': text[:MAX_MSG_LEN],
        'time': datetime.now().strftime('%H:%M')
    })
    if len(MSGS) > 200:
        MSGS.pop(0)
    return jsonify({'ok': True, 'total': len(MSGS)})

@app.route('/api/health')
def health():
    return jsonify({'status': 'ok', 'messages': len(MSGS), 'time': datetime.now().isoformat()})
