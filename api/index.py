from flask import Flask, request, jsonify, render_template_string
from datetime import datetime

app = Flask(__name__)
MSGS = []

HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>💬 Chat</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Arial;background:#f0f2f5;display:flex;flex-direction:column;height:100vh}
header{background:#075e54;color:white;padding:15px 20px;font-size:18px;font-weight:bold;box-shadow:0 2px 8px rgba(0,0,0,0.2)}
#box{flex:1;overflow-y:auto;padding:15px;display:flex;flex-direction:column;gap:8px}
.m{max-width:72%;padding:9px 13px;border-radius:12px;font-size:14px;line-height:1.5}
.mine{background:#dcf8c6;align-self:flex-end;border-radius:12px 2px 12px 12px}
.other{background:white;align-self:flex-start;border-radius:2px 12px 12px 12px;box-shadow:0 1px 3px rgba(0,0,0,0.08)}
.name{font-size:11px;font-weight:bold;color:#075e54;margin-bottom:3px}
.time{font-size:11px;color:#aaa;text-align:right;margin-top:3px}
.form{display:flex;padding:10px;gap:8px;background:white;border-top:1px solid #ddd}
.form input{flex:1;padding:10px 14px;border:1.5px solid #e0e0e0;border-radius:24px;outline:none;font-size:14px}
.form input:focus{border-color:#075e54}
#u{max-width:110px}
.form button{background:#075e54;color:white;border:none;padding:10px 18px;border-radius:24px;cursor:pointer;font-weight:bold}
.form button:hover{background:#064e46}
.empty{text-align:center;color:#aaa;margin-top:60px;font-size:14px}
</style></head>
<body>
<header>💬 Genel Sohbet</header>
<div id="box"><div class="empty" id="empty">Henüz mesaj yok. İlk mesajı sen gönder! 🎉</div></div>
<div class="form">
  <input id="u" placeholder="Adın" maxlength="20">
  <input id="t" placeholder="Mesaj yaz..." maxlength="500" autocomplete="off">
  <button onclick="send()">Gönder</button>
</div>
<script>
let last=0;
async function load(){
  try{
    const r=await fetch('/api/messages');
    const msgs=await r.json();
    if(msgs.length===last)return;
    last=msgs.length;
    const box=document.getElementById('box');
    const me=localStorage.getItem('chatname')||'';
    if(msgs.length===0){box.innerHTML='<div class="empty">Henüz mesaj yok. İlk mesajı sen gönder! 🎉</div>';return;}
    box.innerHTML=msgs.map(m=>`<div class="m ${m.user===me?'mine':'other'}">
      ${m.user!==me?`<div class="name">${m.user}</div>`:''}
      ${m.text}
      <div class="time">${m.time}</div>
    </div>`).join('');
    box.scrollTop=box.scrollHeight;
  }catch(e){}
}
async function send(){
  const uEl=document.getElementById('u');
  const tEl=document.getElementById('t');
  const u=uEl.value.trim()||'Anonim';
  const t=tEl.value.trim();
  if(!t)return;
  localStorage.setItem('chatname',u);
  tEl.value='';
  await fetch('/api/send',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({user:u,text:t})});
  load();
}
document.getElementById('u').value=localStorage.getItem('chatname')||'';
document.getElementById('t').addEventListener('keydown',e=>{if(e.key==='Enter')send();});
setInterval(load,3000);
load();
</script>
</body></html>"""

@app.route('/')
def index():
    return render_template_string(HTML)

@app.route('/api/messages')
def messages():
    return jsonify(MSGS)

@app.route('/api/send', methods=['POST'])
def send():
    data = request.json
    if not data or not data.get('text','').strip():
        return jsonify({'ok': False}), 400
    MSGS.append({
        'user': data.get('user','Anonim')[:20],
        'text': data.get('text','')[:500],
        'time': datetime.now().strftime('%H:%M')
    })
    if len(MSGS) > 100:
        MSGS.pop(0)
    return jsonify({'ok': True})
