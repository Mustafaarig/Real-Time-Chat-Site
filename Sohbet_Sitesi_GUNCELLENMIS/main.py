from flask import Flask, render_template, request, session, redirect, url_for
from flask_socketio import SocketIO, join_room, leave_room, send, emit
from database import get_db_connection, create_tables
import random
import string
import uuid
import bcrypt
import sqlite3
from flask_jwt_extended import JWTManager, create_access_token
from werkzeug.security import generate_password_hash, check_password_hash

aktif_kullanicilar = set()

app = Flask(__name__)
app.secret_key = "secret"
app.config['JWT_SECRET_KEY'] = 'super-secret-jwt-key'
jwt = JWTManager(app)
socketio = SocketIO(app)

create_tables()
rooms = {}

import uuid  # Dosyanın en üstüne ekle (zaten varsa tekrar ekleme)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # 🔒 Şifreyi hashle
        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # 🆔 UUID oluştur
        user_uuid = str(uuid.uuid4())

        # 🔄 Veritabanına ekle (uuid dahil!)
        conn = sqlite3.connect('messages.db')
        c = conn.cursor()
        try:
            c.execute(
                "INSERT INTO users (uuid, username, password) VALUES (?, ?, ?)",
                (user_uuid, username, hashed_pw)
            )
            conn.commit()
            return redirect('/login')
        except sqlite3.IntegrityError:
            error = "Bu kullanıcı adı zaten mevcut."
        finally:
            conn.close()
    return render_template("register.html", error=error)


@app.route("/", methods=["POST", "GET"])
def home():
    name = session.get("name")
    if not name:
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("code")
        join = request.form.get("join", False)
        create = request.form.get("create", False)

        if join and not code:
            return render_template("home.html", error="Lütfen oda kodunu giriniz.", code=code)

        room = code
        if create:
            room = generate_room_code(6, list(rooms.keys()))
            rooms[room] = {
                'members': 0,
                'messages': [],
                'usernames': [],
                'voice_active': set()
            }
        elif code not in rooms:
            return render_template("home.html", error="Böyle bir oda yok.", code=code)

        session["room"] = room
        return redirect(url_for("room"))

    return render_template("home.html", username=name)

@app.route("/room")
def room():
    name = session.get("name")
    room = session.get("room")
    if not name or room not in rooms:
        return redirect(url_for("home"))

    conn = get_db_connection()
    db_messages = conn.execute(
        'SELECT id, sender, message, timestamp FROM messages WHERE room = ? ORDER BY timestamp ASC',
        (room,)
    ).fetchall()
    conn.close()

    messages = []
    for i, msg in enumerate(db_messages):
        msg_id = msg["id"] if "id" in msg.keys() and msg["id"] else f"msg-{i}"
        messages.append({
            "id": msg_id,
            "sender": msg["sender"],
            "message": msg["message"],
            "timestamp": msg["timestamp"]
        })

    return render_template("room.html", code=room, messages=messages, user=name, room=room)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('messages.db')  # veya 'veritabani.db'
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()

        if user:
            db_password = user[0]
            if bcrypt.checkpw(password.encode('utf-8'), db_password.encode('utf-8')):
                session['name'] = username

                # ✅ JWT TOKEN üret ve session'a kaydet
                access_token = create_access_token(identity=username)
                session['token'] = access_token  # JWT token artık oturumda

                return redirect('/')
            else:
                error = "Şifre yanlış"
        else:
            error = "Kullanıcı bulunamadı"

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    aktif_kullanicilar.discard(session.get("name"))
    session.clear()
    return redirect(url_for("login"))

@socketio.on("connect")
def connect(auth):
    name = session.get("name")
    room = session.get("room")
    if name:
        aktif_kullanicilar.add(name)
    if not room or not name or room not in rooms:
        return
    join_room(room)
    rooms[room]["members"] += 1
    if name not in rooms[room]["usernames"]:
        rooms[room]["usernames"].append(name)
    emit("user-list", rooms[room]["usernames"], to=room)
   
    emit("voice-users", list(rooms[room]["voice_active"]), to=room)

@socketio.on("disconnect")
def disconnect():
    name = session.get("name")
    room = session.get("room")
    aktif_kullanicilar.discard(name)
    leave_room(room)
    if room in rooms:
        rooms[room]["members"] -= 1
        rooms[room]["usernames"] = [u for u in rooms[room]["usernames"] if u != name]
        rooms[room]["voice_active"].discard(name)
        emit("user-list", rooms[room]["usernames"], to=room)
        emit("voice-users", list(rooms[room]["voice_active"]), to=room)
        send({"message": f"{name} odadan çıktı", "sender": ""}, to=room)

import uuid

@socketio.on("message")
def handle_message(data):
    room = session.get("room")
    sender = session.get("name")
    message_id = data.get("id") or f"msg-{int(time.time() * 1000)}"

    if room not in rooms:
        return

    # ✅ 1. Veritabanına mesajı ekle
    try:
        conn = get_db_connection()
        conn.execute(
            'INSERT INTO messages (id, room, sender, message) VALUES (?, ?, ?, ?)',
            (message_id, room, sender, data["message"])
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print("DB HATASI:", e)
        return

    # ✅ 2. Mesajı herkese gönder
    msg = {
        "sender": sender,
        "message": data["message"],
        "id": message_id
    }
    send(msg, to=room)

    # ✅ 3. Tik bilgisi yayınla
    for user in rooms[room]["usernames"]:
        if user == sender:
            continue
        status = "read" if user in aktif_kullanicilar else "sent"
        emit("update-message-status", {
            "messageId": message_id,
            "status": status
        }, to=room)


@socketio.on("message-status-check")
def message_status_check(data):
    room = session.get("room")
    reader = session.get("name")
    message_id = data.get("messageId")

    # Tüm kullanıcılar görebilsin diye yay
    emit("update-message-status", {
        "messageId": message_id,
        "status": "read"
    }, to=room)

@socketio.on("voice-offer")
def handle_voice_offer(data):
    emit("voice-offer", {
        "offer": data.get("offer"),
        "sender": session.get("name")
    }, to=data.get("room"), include_self=False)

@socketio.on("voice-answer")
def handle_voice_answer(data):
    emit("voice-answer", {
        "answer": data.get("answer"),
        "sender": session.get("name")
    }, to=data.get("room"), include_self=False)

@socketio.on("ice-candidate")
def handle_ice_candidate(data):
    emit("ice-candidate", {
        "candidate": data.get("candidate"),
        "sender": session.get("name")
    }, to=data.get("room"), include_self=False)

@socketio.on("voice-start")
def voice_start():
    room = session.get("room")
    name = session.get("name")
    if room and name:
        rooms[room]["voice_active"].add(name)
        emit("voice-users", list(rooms[room]["voice_active"]), to=room)

@socketio.on("voice-stop")
def voice_stop():
    room = session.get("room")
    name = session.get("name")
    if room and name:
        rooms[room]["voice_active"].discard(name)
        emit("voice-users", list(rooms[room]["voice_active"]), to=room)

@socketio.on("voice-toggle")
def voice_toggle():
    room = session.get("room")
    name = session.get("name")
    if room and name:
        if name in rooms[room]["voice_active"]:
            rooms[room]["voice_active"].remove(name)
        else:
            rooms[room]["voice_active"].add(name)
        emit("voice-users", list(rooms[room]["voice_active"]), to=room)
@socketio.on("join-room")
def handle_join_room(data):
    name = data.get("name")
    room = data.get("room")
    if not name or not room:
        return

    session["name"] = name
    session["room"] = room

    join_room(room)
    if room not in rooms:
        rooms[room] = {
            'members': 0,
            'messages': [],
            'usernames': [],
            'voice_active': set()
        }
    

    rooms[room]["members"] += 1
    if name not in rooms[room]["usernames"]:
        rooms[room]["usernames"].append(name)

    aktif_kullanicilar.add(name)

    emit("user-list", rooms[room]["usernames"], to=room)
    send({"message": f"{name} odaya katıldı", "sender": ""}, to=room)
def generate_room_code(length, existing_codes):
    while True:
        code = ''.join(random.choices(string.ascii_uppercase, k=length))
        if code not in existing_codes:
            return code

if __name__ == '__main__':
    import eventlet
    socketio.run(app, debug=True, host='127.0.0.1', port=5000)