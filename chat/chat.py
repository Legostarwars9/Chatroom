from flask import Flask, request, send_from_directory
from flask_sock import Sock
from simple_websocket.errors import ConnectionClosed
import bcrypt, os, time, threading, uuid, csv, logging, re, json

app = Flask(__name__)
sock = Sock(app)

BASE = os.path.dirname(__file__)
MSG_DIR = os.path.join(BASE, "messages")
ROOM_DIR = os.path.join(MSG_DIR, "rooms")
USERS_FILE = os.path.join(BASE, "users.txt")
BANS_FILE = os.path.join(BASE, "bans.txt")
BANNED_WORDS = os.path.join(BASE, "banned_words.csv")

os.makedirs(MSG_DIR, exist_ok=True)
os.makedirs(ROOM_DIR, exist_ok=True)

RATE_LIMIT = 5
RATE_WINDOW = 5
MESSAGE_EXPIRY = 60 * 60 * 24 * 180

online_users = {}
user_sessions = {}
muted_users = set()
msg_times = {}
ws_connections = {}
ws_lock = threading.Lock()

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S", handlers=[logging.FileHandler("app.log"), logging.StreamHandler()])
logging.getLogger("werkzeug").setLevel(logging.ERROR)

def load_users():
    users = {}
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, encoding="utf-8") as f:
            for line in f:
                if ":" not in line:
                    continue
                try:
                    username, password_hash, role = line.strip().split(":", 2)
                except ValueError:
                    continue
                users[username] = {"hash": password_hash.encode(), "role": role}
    return users

def save_user(username, password, role="user"):
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    with open(USERS_FILE, "a", encoding="utf-8") as f:
        f.write(f"\n{username}:{hashed}:{role}")

def create_token(username, ip):
    token = uuid.uuid4().hex + uuid.uuid4().hex
    user_sessions[username] = {"token": token, "ip": ip, "last_seen": time.time()}
    return token

def get_user_from_token(token):
    if not token:
        return None
    for username, info in list(user_sessions.items()):
        if info.get("token") == token:
            info["last_seen"] = time.time()
            online_users[username] = time.time()
            return username
    return None

def remove_token(username, token=None):
    info = user_sessions.get(username)
    if not info:
        return
    if token is not None and info.get("token") != token:
        return
    del user_sessions[username]
    with ws_lock:
        if not ws_connections.get(username):
            online_users.pop(username, None)

def ban_status(username=None, ip=None, token=None):
    if not os.path.exists(BANS_FILE):
        return None
    with open(BANS_FILE, encoding="utf-8") as f:
        bans = f.read().splitlines()
    if ip and f"ip:{ip}" in bans:
        return "ip_banned"
    if token and f"token:{token}" in bans:
        return "banned"
    if username and f"user:{username}" in bans:
        return "banned"
    return None

def ratelimit(user):
    now = time.time()
    times = [t for t in msg_times.get(user, []) if now - t < RATE_WINDOW]
    times.append(now)
    msg_times[user] = times
    return len(times) > RATE_LIMIT

def msg_path(room):
    return os.path.join(MSG_DIR, "public.txt" if room == "public" else f"{room}.txt")

def write_msg(path, user, msg):
    banned_set = set()
    try:
        with open(BANNED_WORDS, encoding="utf-8") as f:
            for row in csv.reader(f):
                if row:
                    banned_set.add(row[0].strip().lower())
    except FileNotFoundError:
        pass

    filtered = []
    for word in msg.split():
        clean = re.sub(r"[^a-zA-Z]", "", word).lower()
        filtered.append("*" * len(word) if clean in banned_set else word)

    msg = " ".join(filtered)
    ts = time.strftime("[%H:%M:%S]", time.localtime())
    mid = uuid.uuid4().hex[:8]

    with open(path, "a", encoding="utf-8") as f:
        f.write(f"{ts}|{user}: {msg}|{mid}\n")

    logging.info(f"{user} sent message: {msg}; With Message ID: {mid}")
    return {"id": mid, "text": f"{ts}|{user}: {msg}"}

def read_msgs(path):
    msgs = []
    if not os.path.exists(path):
        return msgs
    with open(path, encoding="utf-8") as f:
        for line in f:
            try:
                ts_user_msg, mid = line.rsplit("|", 1)
                ts, rest = ts_user_msg.split("|", 1)
                msgs.append({"id": mid.strip(), "text": ts + "|" + rest})
            except Exception:
                continue
    return msgs

def send_ws(ws, data):
    try:
        ws.send(json.dumps(data))
        return True
    except Exception:
        return False

def add_connection(username, ws):
    with ws_lock:
        ws_connections.setdefault(username, []).append(ws)
        online_users[username] = time.time()

def remove_connection(username, ws):
    with ws_lock:
        sockets = ws_connections.get(username, [])
        if ws in sockets:
            sockets.remove(ws)
        if not sockets:
            ws_connections.pop(username, None)
            online_users.pop(username, None)

def all_sockets():
    with ws_lock:
        return [ws for sockets in ws_connections.values() for ws in sockets]

def broadcast(data):
    dead = []
    for ws in all_sockets():
        if not send_ws(ws, data):
            dead.append(ws)
    return dead

def broadcast_users():
    broadcast({"type": "users", "users": sorted(online_users.keys())})

def broadcast_room(room, data):
    with ws_lock:
        targets = []
        for sockets in ws_connections.values():
            for ws in sockets:
                if getattr(ws, "_chat_room", "public") == room:
                    targets.append(ws)
    dead = []
    for ws in targets:
        if not send_ws(ws, data):
            dead.append(ws)
    return dead

def execute_command(username, cmd_line):
    users = load_users()

    if not username:
        return {"status": "forbidden", "message": "Not logged in"}, 403

    if cmd_line == "/checkrole":
        return {"status": "ok", "role": users.get(username, {}).get("role", "user")}, 200

    if users.get(username, {}).get("role") != "admin":
        logging.warning(f"{username} tried using an admin command but is not admin")
        return {"status": "forbidden", "message": "Admin only"}, 403

    parts = cmd_line.strip().split(maxsplit=1)
    if not parts:
        return {"status": "bad", "message": "Missing command"}, 400

    cmd = parts[0]
    arg = parts[1] if len(parts) > 1 else ""

    if cmd == "/mute":
        if not arg:
            return {"status": "bad", "message": "Missing username"}, 400
        muted_users.add(arg)
        return {"status": "ok", "message": f"Muted {arg}"}, 200

    if cmd == "/unmute":
        if not arg:
            return {"status": "bad", "message": "Missing username"}, 400
        muted_users.discard(arg)
        return {"status": "ok", "message": f"Unmuted {arg}"}, 200

    if cmd == "/ban":
        if not arg:
            return {"status": "bad", "message": "Missing username"}, 400
        target = user_sessions.get(arg)
        if not target:
            return {"status": "not_found", "message": "User not found"}, 404
        with open(BANS_FILE, "a", encoding="utf-8") as f:
            f.write(f"user:{arg}\n")
            if target.get("token"):
                f.write(f"token:{target['token']}\n")
        return {"status": "ok", "message": f"Banned {arg}"}, 200

    if cmd == "/ipban":
        if not arg:
            return {"status": "bad", "message": "Missing username"}, 400
        target = user_sessions.get(arg)
        if not target or not target.get("ip"):
            return {"status": "not_found", "message": "User not found"}, 404
        with open(BANS_FILE, "a", encoding="utf-8") as f:
            f.write(f"ip:{target['ip']}\n")
        return {"status": "ok", "message": f"IP banned {arg}"}, 200

    if cmd == "/unban":
        targets = []
        if arg:
            if arg.startswith("token:") or arg.startswith("ip:") or arg.startswith("user:"):
                targets.append(arg)
            else:
                targets.append(f"user:{arg}")
                target = user_sessions.get(arg)
                if target:
                    if target.get("token"):
                        targets.append(f"token:{target['token']}")
                    if target.get("ip"):
                        targets.append(f"ip:{target['ip']}")

        if not os.path.exists(BANS_FILE):
            return {"status": "ok", "message": "No bans file"}, 200

        with open(BANS_FILE, encoding="utf-8") as f:
            lines = f.readlines()

        with open(BANS_FILE, "w", encoding="utf-8") as f:
            for line in lines:
                if line.strip() not in targets:
                    f.write(line)

        return {"status": "ok", "message": "Unbanned"}, 200

    if cmd == "/delete":
        if not arg:
            return {"status": "bad", "message": "Missing message id"}, 400

        message_files = []
        if os.path.isdir(MSG_DIR):
            message_files.extend(os.path.join(MSG_DIR, n) for n in os.listdir(MSG_DIR) if os.path.isfile(os.path.join(MSG_DIR, n)) and n.endswith(".txt"))
        if os.path.isdir(ROOM_DIR):
            message_files.extend(os.path.join(ROOM_DIR, n) for n in os.listdir(ROOM_DIR) if os.path.isfile(os.path.join(ROOM_DIR, n)))

        for file in message_files:
            with open(file, encoding="utf-8") as f:
                lines = f.readlines()
            with open(file, "w", encoding="utf-8") as f:
                for line in lines:
                    if not line.strip().endswith(arg):
                        f.write(line)

        return {"status": "ok", "message": "Deleted"}, 200

    return {"status": "bad", "message": "Unknown command"}, 400

def send_connected(ws, username, room):
    role = load_users().get(username, {}).get("role", "user")
    send_ws(ws, {
        "type": "connected",
        "user": username,
        "username": username,
        "room": room,
        "is_admin": role == "admin",
        "messages": read_msgs(msg_path(room)),
        "users": sorted(online_users.keys())
    })

@sock.route("/ws")
def websocket(ws):
    username = None
    token = None
    room = "public"

    try:
        while True:
            raw = ws.receive()
            if raw is None:
                break

            try:
                data = json.loads(raw)
            except Exception:
                send_ws(ws, {"type": "error", "message": "Invalid JSON"})
                continue

            msg_type = data.get("type")

            if msg_type == "login":
                login_user = data.get("username", "").strip()
                password = data.get("password", "")
                users = load_users()
                client_ip = request.remote_addr or "unknown"
                status = ban_status(username=login_user, ip=client_ip)

                if status:
                    send_ws(ws, {"type": "login", "status": status})
                    continue

                if login_user in users and bcrypt.checkpw(password.encode(), users[login_user]["hash"]):
                    username = login_user
                    token = create_token(username, client_ip)
                    add_connection(username, ws)
                    room = "public"
                    ws._chat_room = room
                    send_ws(ws, {"type": "login", "status": "ok", "user": username, "username": username, "token": token})
                    send_connected(ws, username, room)
                    broadcast_users()
                else:
                    send_ws(ws, {"type": "login", "status": "fail"})
                continue

            if msg_type == "token_login":
                login_token = data.get("token", "")
                login_user = get_user_from_token(login_token)
                client_ip = request.remote_addr or "unknown"
                status = ban_status(username=login_user, ip=client_ip, token=login_token)

                if not login_user or status:
                    send_ws(ws, {"type": "token_login", "status": "fail"})
                    continue

                username = login_user
                token = login_token
                add_connection(username, ws)
                room = "public"
                ws._chat_room = room
                send_ws(ws, {"type": "token_login", "status": "ok", "user": username, "username": username, "token": token})
                send_connected(ws, username, room)
                broadcast_users()
                continue

            if msg_type == "register":
                register_user = data.get("username", "").strip()
                password = data.get("password", "")

                if not register_user or not password:
                    send_ws(ws, {"type": "register", "status": "invalid"})
                    continue

                users = load_users()

                if register_user in users:
                    send_ws(ws, {"type": "register", "status": "exists"})
                    continue

                if ":" in register_user:
                    send_ws(ws, {"type": "register", "status": "invalid_characters"})
                    continue

                save_user(register_user, password)
                logging.info(f"New User Registered: {register_user}")
                send_ws(ws, {"type": "register", "status": "ok"})
                continue

            if not username:
                send_ws(ws, {"type": "error", "message": "Not logged in"})
                continue

            if msg_type == "ping":
                if username in user_sessions:
                    user_sessions[username]["last_seen"] = time.time()
                online_users[username] = time.time()
                send_ws(ws, {"type": "pong"})
                continue

            if msg_type == "logout":
                send_ws(ws, {"type": "logout", "status": "ok"})
                remove_token(username, token)
                break

            if msg_type == "send":
                message = data.get("message", "").strip()
                requested_room = data.get("room", room)

                if not message:
                    continue

                status = ban_status(username=username, ip=request.remote_addr, token=token)
                if status:
                    send_ws(ws, {"type": "error", "message": status})
                    continue

                if username in muted_users:
                    send_ws(ws, {"type": "error", "message": "muted"})
                    continue

                if ratelimit(username):
                    send_ws(ws, {"type": "error", "message": "rate"})
                    continue

                if not requested_room or not requested_room.isalnum():
                    send_ws(ws, {"type": "error", "message": "Invalid room"})
                    continue

                path = msg_path(requested_room)

                if not os.path.exists(path):
                    send_ws(ws, {"type": "error", "message": "Room does not exist"})
                    continue

                room = requested_room
                ws._chat_room = room

                message_data = write_msg(path, username, message)
                broadcast_room(room, {"type": "message", "message": message_data})
                continue

            if msg_type == "join":
                requested_room = data.get("room", "public")

                if not requested_room or not requested_room.isalnum():
                    send_ws(ws, {"type": "error", "message": "Invalid room"})
                    continue

                path = msg_path(requested_room)

                if not os.path.exists(path):
                    send_ws(ws, {"type": "error", "message": "Room does not exist"})
                    continue

                room = requested_room
                ws._chat_room = room
                send_ws(ws, {"type": "room", "room": room, "messages": read_msgs(path)})
                continue

            if msg_type == "new_room":
                new_room = uuid.uuid4().hex[:6]
                open(msg_path(new_room), "a").close()
                room = new_room
                ws._chat_room = room
                send_ws(ws, {"type": "new_room", "status": "ok", "room": room, "messages": []})
                continue

            if msg_type == "command":
                command = data.get("command", "").strip()
                result, status_code = execute_command(username, command)
                send_ws(ws, {"type": "command", "status_code": status_code, **result})
                if command.startswith("/delete "):
                    broadcast({"type": "refresh"})
                continue

            send_ws(ws, {"type": "error", "message": "Unknown request type"})

    except ConnectionClosed:
        logging.info("WebSocket client disconnected")
    except Exception:
        logging.exception("WebSocket error")
    finally:
        if username:
            remove_connection(username, ws)
            broadcast_users()

def cleanup():
    while True:
        for filename in os.listdir(MSG_DIR):
            path = os.path.join(MSG_DIR, filename)
            if not os.path.isfile(path):
                continue
            with open(path, encoding="utf-8") as f:
                lines = f.readlines()
            with open(path, "w", encoding="utf-8") as f:
                f.writelines(lines)
        time.sleep(3600)

def prune():
    while True:
        now = time.time()
        for username in list(online_users):
            if now - online_users[username] > 15 and username not in ws_connections:
                online_users.pop(username, None)
        time.sleep(5)

threading.Thread(target=cleanup, daemon=True).start()
threading.Thread(target=prune, daemon=True).start()

@app.route("/")
def index():
    return send_from_directory("templates", "chat.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
