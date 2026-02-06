import socket
import threading
import json
import time
import os
import re
import hashlib
import base64
import random
import struct
import queue
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
except ImportError:
    try:
        from Cryptodome.Cipher import AES
        from Cryptodome.Random import get_random_bytes
    except ImportError:
        import sys
        sys.stderr.write(
            "You need to install pycryptodome module: pip install pycryptodome\n"
        )
        sys.exit(1)

def load_users():
    if os.path.exists(users_file):
        with open(users_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(users_file, 'w', encoding='utf-8') as f:
        json.dump(users, f, ensure_ascii=False, indent=4)

def load_servers():
    if not os.path.exists(servers_dir):
        os.makedirs(servers_dir)
    
    servers = {}

    for filename in os.listdir(servers_dir):
        if filename.endswith('.json'):
            server_name = filename[:-5]
            with open(os.path.join(servers_dir, filename), 'r', encoding='utf-8') as f:
                servers[server_name] = json.load(f)
    return servers

def save_server(server_name, server_data):
    with open(os.path.join(servers_dir, f'{server_name}.json'), 'w', encoding='utf-8') as f:
        json.dump(server_data, f, ensure_ascii=False, indent=4)

def load_bans():
    if os.path.exists(bans_file):
        with open(bans_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def save_bans(bans):
    with open(bans_file, 'w', encoding='utf-8') as f:
        json.dump(bans, f, ensure_ascii=False, indent=4)

# Change this!
MY_SERVER_HOST = "example.com"
TCP_PORT = 42439
ENCRYPTED_PORT = 42440
ADMIN_USERNAME = "ADMIN"

IV_SIZE = 16
MAX_PACKET_SIZE = 32 * 1024

DH_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF", 16)
DH_G = 2

users_file = 'users.json'
bans_file = 'bans.json'
servers_dir = 'servers'

clients_by_user = {}
clients_by_server = {}
socket_to_session = {}
client_keys = {}

members_by_room = {}
remote_subscribers_by_room = {}
user_remote_counters = {}

dialback_cache = {}
pending_dialback = {}

session_lock = threading.RLock()

SEND_DELAY_SECONDS = 0.15
_send_queues = {}
_send_workers = {}
_send_state_lock = threading.RLock()

DELAYED_MESSAGE_TYPES = {
    'chat_message',
    'private_message',
    'action_message',
    'broadcast_message',
    'room_event'
}

DIALBACK_CACHE_TTL = 3600
MAX_RETRIES = 2
RETRY_DELAY = 1

default_server = 'general'

commands = {
    "/login": "<username> <password> - Login with username and password.",
    "/register": "<username> <password> - Register a new user.",
    "/create_server": "<server name> - Create a new communication server.",
    "/join_server": "<server name > - Log in to the communication server.",
    "/list_servers": "- Get a list of all available servers for communication.",
    "/members": "- Get list of users on server.",
    "/pm": "<username> <message> - Send a private message to the specified user.",
    "/act": "<action> - Chat action, set your status.",
    "/list_capabilities": "- Get a list of all available capabilities.",
    "/help": "- Shows this message."
}

users = load_users()
bans = load_bans()
servers = load_servers()

from caps.caps import CapabilitiesManager
capabilities_manager = CapabilitiesManager()

if default_server not in servers:
    servers[default_server] = []
    save_server(default_server, servers[default_server])

def _send_worker(sock, q):
    last_sent_at = 0.0
    while True:
        try:
            item = q.get()
            if item is None:
                break
            message, client_key = item
            now = time.time()
            delta = now - last_sent_at
            if SEND_DELAY_SECONDS > 0 and delta < SEND_DELAY_SECONDS:
                time.sleep(SEND_DELAY_SECONDS - delta)

            try:
                if client_key:
                    if isinstance(client_key, tuple):
                        enc_key, mac_key = client_key
                    else:
                        enc_key, mac_key = client_key, None
                    send_encrypted_message(sock, message, enc_key, mac_key)
                else:
                    if not message.endswith('\n'):
                        message_to_send = message + '\n'
                    else:
                        message_to_send = message
                    sock.send(message_to_send.encode('utf-8'))
            except Exception as e:
                log_message(f"Error sending to client: {e}.")
                break

            last_sent_at = time.time()
            
        except Exception:
            break

    with _send_state_lock:
        _send_workers.pop(sock, None)
        q_local = _send_queues.pop(sock, None)
        if q_local is not None:
            try:
                while not q_local.empty():
                    q_local.get_nowait()
            except Exception:
                pass

def _send_immediate(sock, message, client_key=None):
    try:
        if client_key:
            if isinstance(client_key, tuple):
                enc_key, mac_key = client_key
            else:
                enc_key, mac_key = client_key, None
            return send_encrypted_message(sock, message, enc_key, mac_key)
        else:
            if not message.endswith('\n'):
                message += '\n'
            sock.send(message.encode('utf-8'))
            return True
    except Exception as e:
        log_message(f"Error sending to client: {e}.")
        return False

def enqueue_send(sock, message, client_key=None, message_type='system'):
    try:
        if message_type not in DELAYED_MESSAGE_TYPES:
            return _send_immediate(sock, message, client_key)
        with _send_state_lock:
            q = _send_queues.get(sock)
            if q is None:
                q = queue.Queue()
                _send_queues[sock] = q
            worker = _send_workers.get(sock)
            if worker is None or not worker.is_alive():
                worker = threading.Thread(target=_send_worker, args=(sock, q), daemon=True)
                _send_workers[sock] = worker
                worker.start()
        q.put((message, client_key))
        return True
    except Exception:
        return False

os.makedirs(servers_dir, exist_ok=True)

def log_message(message):
    current_time = time.strftime("%H:%M:%S", time.localtime())
    print(f"[{current_time}] {message}")

def derive_session_keys(shared_bytes):
    try:
        import hashlib
        enc_key = hashlib.sha256(shared_bytes + b"|KEY").digest()
        mac_key = hashlib.sha256(shared_bytes + b"|MAC").digest()
        return enc_key, mac_key
    except Exception as e:
        log_message(f"Key derivation error: {e}.")
        return None, None

def encrypt_message(message, key):
    try:
        iv = get_random_bytes(IV_SIZE)
        
        message_bytes = message.encode('utf-8')
        padding_length = 16 - (len(message_bytes) % 16)
        padded_message = message_bytes + bytes([padding_length] * padding_length)
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(padded_message)
        
        return iv + encrypted
    except Exception as e:
        log_message(f"Encryption error: {e}.")
        return None

def decrypt_message(encrypted_data, key):
    try:
        if len(encrypted_data) < IV_SIZE:
            return None
            
        iv = encrypted_data[:IV_SIZE]
        encrypted = encrypted_data[IV_SIZE:]
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        
        padding_length = decrypted[-1]
        if padding_length > 16 or padding_length == 0:
            return None
            
        message_bytes = decrypted[:-padding_length]
        return message_bytes.decode('utf-8')
    except Exception as e:
        log_message(f"Decryption error: {e}.")
        return None

def send_encrypted_message(socket, message, key, mac_key=None):
    try:
        encrypted = encrypt_message(message, key)
        if encrypted:
            payload = encrypted
            if mac_key is not None:
                import hmac, hashlib
                mac = hmac.new(mac_key, payload, hashlib.sha256).digest()
                payload = payload + mac
            length = struct.pack('>I', len(payload))
            socket.send(length + payload)
            return True
    except Exception as e:
        log_message(f"Error sending encrypted message: {e}.")
    return False

def receive_encrypted_message(socket, key, mac_key=None):
    try:
        length_data = socket.recv(4)
        if len(length_data) != 4:
            return None
            
        length = struct.unpack('>I', length_data)[0]
        
        encrypted_data = b''
        while len(encrypted_data) < length:
            chunk = socket.recv(length - len(encrypted_data))
            if not chunk:
                return None
            encrypted_data += chunk

        if mac_key is not None and length >= 32:
            data_part = encrypted_data[:-32]
            mac_part = encrypted_data[-32:]
            import hmac, hashlib
            expected = hmac.new(mac_key, data_part, hashlib.sha256).digest()
            if not hmac.compare_digest(mac_part, expected):
                log_message("HMAC verification failed.")
                return None
            encrypted_payload = data_part
        else:
            encrypted_payload = encrypted_data

        decrypted = decrypt_message(encrypted_payload, key)
        return decrypted.strip() if decrypted else None
    except Exception as e:
        log_message(f"Error receiving encrypted message: {e}.")
        return None

def handle_key_exchange(client_socket, client_address):
    try:
        a = random.getrandbits(256)
        A = pow(DH_G, a, DH_P)
        A_bytes_len = (DH_P.bit_length() + 7) // 8
        A_bytes = A.to_bytes(A_bytes_len, byteorder='big')
        A_bytes = A_bytes.lstrip(b"\x00") or b"\x00"

        client_socket.send(struct.pack('>H', len(A_bytes)) + A_bytes)

        len_data = client_socket.recv(2)
        if len(len_data) != 2:
            raise Exception("Failed to receive DH B length.")
        blen = struct.unpack('>H', len_data)[0]
        B_bytes = b''
        while len(B_bytes) < blen:
            chunk = client_socket.recv(blen - len(B_bytes))
            if not chunk:
                raise Exception("Failed to receive DH B.")
            B_bytes += chunk
        try:
            B = int.from_bytes(B_bytes, byteorder='big')
        except Exception:
            import binascii
            B = int(binascii.hexlify(B_bytes), 16)

        shared = pow(B, a, DH_P)
        shared_len = (DH_P.bit_length() + 7) // 8
        try:
            shared_bytes = shared.to_bytes(shared_len, byteorder='big')
        except Exception:
            import binascii
            hex_s = hex(shared)[2:].rstrip('L')
            if len(hex_s) % 2:
                hex_s = '0' + hex_s
            shared_bytes = binascii.unhexlify(hex_s)
        shared_bytes = shared_bytes.lstrip(b"\x00") or b"\x00"
        import hashlib
        enc_key, mac_key = derive_session_keys(shared_bytes)
        aes_key = enc_key
        
        client_keys[client_address] = (aes_key, mac_key)
        
        
        
        handle_client(client_socket, client_address)
        
    except Exception as e:
        log_message(f"Key exchange error for {client_address}: {e}.")
    finally:
        try:
            client_socket.close()
        except:
            pass

        client_keys.pop(client_address, None)

def start_key_exchange_server(host='0.0.0.0', port=ENCRYPTED_PORT):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"TCP encrypted server started on {host}:{port}")

    while True:
        client_socket, client_address = server_socket.accept()
        client_thread = threading.Thread(target=handle_key_exchange, args=(client_socket, client_address))
        client_thread.start()

def is_valid_base64(s):
    try:
        if not re.match(r'^[A-Za-z0-9+/]*={0,2}$', s):
            return False

        decoded = base64.b64decode(s)
        decoded.decode('utf-8')
        return True
    except Exception:
        return False

def decode_base64_password(encoded_password):
    try:
        if not is_valid_base64(encoded_password):
            return None
        decoded = base64.b64decode(encoded_password)
        return decoded.decode('utf-8')
    except Exception:
        return None

def is_md5_hash(s):
    return len(s) == 32 and re.match(r'^[a-fA-F0-9]{32}$', s)

def is_sha256_hash(s):
    return len(s) == 64 and re.match(r'^[a-fA-F0-9]{64}$', s)

def is_sha512_hash(s):
    return len(s) == 128 and re.match(r'^[a-fA-F0-9]{128}$', s)

def verify_password_hash(password, hash_value, hash_type):
    try:
        if hash_type == 'md5':
            return hashlib.md5(password.encode('utf-8')).hexdigest() == hash_value
        elif hash_type == 'sha256':
            return hashlib.sha256(password.encode('utf-8')).hexdigest() == hash_value
        elif hash_type == 'sha512':
            return hashlib.sha512(password.encode('utf-8')).hexdigest() == hash_value
        return False
    except Exception:
        return False

def check_password_format(password):
    if is_valid_base64(password):
        decoded = decode_base64_password(password)
        if decoded is not None:
            return 'base64', decoded
    
    if is_md5_hash(password):
        return 'md5', password
    
    if is_sha256_hash(password):
        return 'sha256', password
    
    if is_sha512_hash(password):
        return 'sha512', password
    
    return 'plain', password

def authenticate_user(username, password, stored_users):    
    if username not in stored_users:
        return False
    
    stored_password = stored_users[username]
    
    if stored_password == password:
        return True
    
    password_format, password_value = check_password_format(password)
    
    if password_format == 'base64':
        return stored_password == password_value
    
    elif password_format in ['md5', 'sha256', 'sha512']:
        return verify_password_hash(stored_password, password_value, password_format)
    
    return False

def _room_members(room):
    return members_by_room.setdefault(room, {})

def _remote_subscribers(room):
    return remote_subscribers_by_room.setdefault(room, set())

def parse_room_and_host(name):
    if '@' in name:
        idx = name.rfind('@')
        return name[:idx], name[idx+1:]
    return name, None

def display_name_for(viewer_host, username, origin_host):
    return username if origin_host == viewer_host else f"{username}@{origin_host}"

def get_advertised_host() -> str:
    return MY_SERVER_HOST

def format_room_event_text(viewer_host, event, username, origin_host, payload=None):
    disp = display_name_for(viewer_host, username, origin_host)
    if event == 'joined':
        return f"*** {disp} has joined the server."
    if event == 'left':
        return f"*** {disp} has left the server."
    if event == 'message':
        text = payload.get('text') if payload else ''
        return f"{disp}: {text}"
    if event == 'act':
        act = payload.get('act') if payload else ''
        return f"*** {disp} {act}"
    return ''

def _authoritative_room_add_member(room, username, origin_host):
    room_map = _room_members(room)
    key = (username, origin_host)
    prev = room_map.get(key, 0)
    room_map[key] = prev + 1

    return prev == 0

def _authoritative_room_remove_member(room, username, origin_host):
    room_map = _room_members(room)
    key = (username, origin_host)
    prev = room_map.get(key, 0)
    if prev <= 1:
        room_map.pop(key, None)
        return prev == 1
    else:
        room_map[key] = prev - 1
        return False

def _update_remote_subscriber_count(room, origin_host):
    room_map = _room_members(room)
    hosts_present = any(h == origin_host for (_, h) in room_map.keys())
    subs = _remote_subscribers(room)
    if hosts_present:
        subs.add(origin_host)
    else:
        subs.discard(origin_host)

def get_cached_dialback_result(host, msg_type):
    cache_key = f"{host}:{msg_type}"
    if cache_key in dialback_cache:
        timestamp, result = dialback_cache[cache_key]
        if time.time() - timestamp < DIALBACK_CACHE_TTL:
            return result
        else:
            del dialback_cache[cache_key]
    return None

def cache_dialback_result(host, msg_type, result):
    cache_key = f"{host}:{msg_type}"
    dialback_cache[cache_key] = (time.time(), result)

def send_with_retry(func, *args, **kwargs):
    try:
        result = func(*args, **kwargs)
        if result is not None:
            return result
    except Exception as e:
        if "timed out" in str(e) or "timeout" in str(e):
            log_message(f"[retry] Timeout: {e}.")
        else:
            log_message(f"[retry] Error: {e}.")
            return None
    
    def _retry_worker():
        for attempt in range(1, MAX_RETRIES):
            try:
                time.sleep(RETRY_DELAY)
                result = func(*args, **kwargs)
                if result is not None:
                    log_message(f"[retry] Successfully after {attempt + 1} attempts.")
                    return
            except Exception as e:
                if "timed out" in str(e) or "timeout" in str(e):
                    log_message(f"[retry] Attempt {attempt + 1}/{MAX_RETRIES} timeout: {e}.")
                else:
                    log_message(f"[retry] Error: {e}.")
                    break
    
    threading.Thread(target=_retry_worker, daemon=True).start()
    return None

def send_dialback_check(from_host, msg_id, msg_type, **kwargs):
    cached_result = get_cached_dialback_result(from_host, msg_type)

    if cached_result:
        return True
    
    def _send_dialback():
        try:
            with socket.create_connection((from_host, 42439), timeout=5) as s:
                data = {
                    'type': 'dialback_check',
                    'msg_id': msg_id,
                    'msg_type': msg_type,
                    'from_host': MY_SERVER_HOST,
                    **kwargs
                }
                s.sendall((json.dumps(data) + '\n').encode('utf-8'))
                s.settimeout(5)
                response = b''
                while not response.endswith(b'\n'):
                    chunk = s.recv(MAX_PACKET_SIZE)
                    if not chunk:
                        break
                    response += chunk
                try:
                    resp_json = json.loads(response.decode('utf-8').strip())
                    result = resp_json.get('result') == 'ok'

                    if result:
                        cache_dialback_result(from_host, msg_type, True)
                    return result
                except Exception as e:
                    log_message(f"[dialback_check] Error parsing response: {e}.")
                    return False
        except Exception as e:
            log_message(f"[dialback_check] Connection error: {e}.")
            raise
    
    return send_with_retry(_send_dialback)

def send_remote_room_message(host, room, payload):
    if host is None:
        return None
    data = {
        'msg_id': generate_msg_id(payload.get('sender', ''), room, payload.get('event', payload.get('type',''))),
        'from_host': get_advertised_host(),
        **payload
    }
    return _send_remote_room_sync(host, 42439, data)

def _broadcast_room_event_locally(room, event, username, origin_host, payload=None, room_key=None):
    try:
        text = format_room_event_text(MY_SERVER_HOST, event, username, origin_host, payload)
        target_key = room_key or room
        message_type = 'room_event' if event in ['message', 'act'] else 'system'
        sender = f"{username}@{origin_host}" if (origin_host and origin_host != MY_SERVER_HOST) else username
        broadcast_message(text, target_key, message_type=message_type, sender=sender)
    except Exception:
        pass

def _send_room_event_to_remotes(room, event, username, origin_host, payload=None):
    subs = list(_remote_subscribers(room))
    for host in subs:
        if host == MY_SERVER_HOST:
            continue
        data = {
            'type': 'room_event',
            'room': room,
            'event': event,
            'sender': username,
            'sender_origin': origin_host,
            'msg_id': generate_msg_id(username, room, event),
            'from_host': MY_SERVER_HOST,
            'payload': payload or {}
        }
        try:
            send_remote_room_message(host, room, data)
        except Exception:
            pass

class Session:
    def __init__(self, client_socket):
        self.client_socket = client_socket
        self.username = None
        self.server_name = None
        self.created_at = time.time()

    def send_text(self, message, message_type='system'):
        return enqueue_send(self.client_socket, message, None, message_type)
    
def broadcast_message(message, server_name, sender_session=None, message_type='broadcast_message', sender=None):
    try:
        with session_lock:
            sessions = list(clients_by_server.get(server_name, set()))

        for sess in sessions:
            if sender_session is not None and sess is sender_session:
                continue
            if sender and getattr(sess, 'username', None) and capabilities_manager.should_filter_message(sess.username, sender, 'server'):
                continue

            client_key = get_client_encryption_key(sess)
            if client_key:
                send_to_client(sess.client_socket, message, client_key, message_type)
            else:
                sess.send_text(message, message_type)
    except Exception as e:
        log_message(f"broadcast_message error: {e}.")


def send_private_message(sender_username, recipient_username, message):
    if capabilities_manager.should_filter_message(recipient_username, sender_username, 'pm'):
        return True
    delivered_any = False
    with session_lock:
        recipient_sessions = list(clients_by_user.get(recipient_username, set()))
    pm_text = f"(Private) {sender_username}: {message}"
    for sess in recipient_sessions:
        client_key = get_client_encryption_key(sess)
        if client_key:
            ok = send_to_client(sess.client_socket, pm_text, client_key, 'private_message')
        else:
            ok = sess.send_text(pm_text, 'private_message')
        delivered_any = delivered_any or ok
    return delivered_any

def get_safe_server_path(server_name):
    safe_name = os.path.basename(server_name)
    return safe_name

def get_client_encryption_key(session):
    if not hasattr(session, 'client_socket') or not session.client_socket:
        return None
    
    try:
        client_address = session.client_socket.getpeername()
        return client_keys.get(client_address)
    except:
        return None

def generate_msg_id(sender, recipient, message):
    base = f"{sender}:{recipient}:{message}:{int(time.time())}"
    return hashlib.sha256(base.encode()).hexdigest()

def _send_remote_private_message_sync(sender, recipient, host, message):
    try:
        msg_id = generate_msg_id(sender, recipient, message)
        with socket.create_connection((host, 42439), timeout=5) as s:
            data = {
                'type': 'remote_pm',
                'sender': sender,
                'recipient': recipient,
                'message': message,
                'from_host': MY_SERVER_HOST,
                'msg_id': msg_id
            }
            s.sendall((json.dumps(data) + '\n').encode('utf-8'))
            s.settimeout(5)
            response = b''
            while not response.endswith(b'\n'):
                chunk = s.recv(MAX_PACKET_SIZE)
                if not chunk:
                    break
                response += chunk
            try:
                resp_json = json.loads(response.decode('utf-8').strip())
                return resp_json
            except Exception:
                return {'status': 'error', 'reason': 'parse_error'}
    except Exception:
        return {'status': 'error', 'reason': 'network_error'}

 

def deliver_remote_pm(sender, recipient, message, server_host=None, from_host=None):
    filter_sender = sender
    if from_host and from_host != MY_SERVER_HOST:
        filter_sender = f"{sender}@{from_host}"
    elif server_host and server_host != MY_SERVER_HOST:
        filter_sender = f"{sender}@{server_host}"
    if capabilities_manager.should_filter_message(recipient, filter_sender, 'pm'):
        return True
    sender_display = sender
    if from_host and from_host != MY_SERVER_HOST:
        sender_display = f"{sender}@{from_host}"
    elif server_host and server_host != MY_SERVER_HOST:
        sender_display = f"{sender}@{server_host}"
    pm_text = f"(Private) {sender_display}: {message}"
    with session_lock:
        recipient_sessions = list(clients_by_user.get(recipient, set()))
    if not recipient_sessions:
        log_message(f"[remote_pm] User {recipient} not found")
        return False
    delivered_any = False
    for sess in recipient_sessions:
        client_key = get_client_encryption_key(sess)
        if client_key:
            ok = send_to_client(sess.client_socket, pm_text, client_key, 'private_message')
        else:
            ok = sess.send_text(pm_text, 'private_message')
        delivered_any = delivered_any or ok
    if delivered_any:
        log_message(f"[remote_pm] Successfully sent to {recipient} ({len(recipient_sessions)} sessions)")
    else:
        log_message(f"[remote_pm] Failed to send remote_pm to {recipient}")
    return delivered_any

def notify_tcp_result(client_socket, result, recipient, client_key=None):
    try:
        if result:
            send_to_client(client_socket, f"Private message sent to {recipient}.", client_key)
        else:
            send_to_client(client_socket, f"Failed to send private message to {recipient}.", client_key)
    except Exception:
        pass

def handle_remote_pm_tcp(sender, recipient, host, private_message, client_socket, recipient_display, client_key=None):
    resp = _send_remote_private_message_sync(sender, recipient, host, private_message)
    status = False
    if isinstance(resp, dict):
        if resp.get('status') == 'ok':
            status = True
        elif resp.get('status') == 'error' and resp.get('reason') == 'user_not_found':
            try:
                send_to_client(client_socket, "User does not exist.", client_key)
            except Exception:
                pass
                
            _kick_user(recipient)
            return
    notify_tcp_result(client_socket, status, recipient_display, client_key)

def send_to_client(client_socket, message, client_key=None, message_type='system'):
    return enqueue_send(client_socket, message, client_key, message_type)

def receive_from_client(client_socket, client_key=None):
    try:
        if client_key:
            if isinstance(client_key, tuple):
                enc_key, mac_key = client_key
            else:
                enc_key, mac_key = client_key, None
            return receive_encrypted_message(client_socket, enc_key, mac_key)
        else:
            data = client_socket.recv(MAX_PACKET_SIZE).decode('utf-8').strip()
            return data if data else None
    except Exception as e:
        log_message(f"Error receiving from client: {e}.")
        return None

def handle_client(client_socket, client_address):
    global last_cmd

    logged_in_user = None
    user_server = None
    session = Session(client_socket)
    last_cmd = ""
    
    client_key = client_keys.get(client_address)
    use_encryption = client_key is not None

    log_message(f"TCP client {client_address} connected {'(encrypted)' if use_encryption else '(unencrypted)'}.")

    try:
        client_socket.settimeout(0.5)
        try:
            peek = client_socket.recv(MAX_PACKET_SIZE, socket.MSG_PEEK)
            if peek:
                try:
                    msg = json.loads(peek.decode('utf-8').strip())
                    if msg.get('type') == 'remote_pm':
                        data = client_socket.recv(MAX_PACKET_SIZE)
                        msg = json.loads(data.decode('utf-8').strip())
                        from_host = msg.get('from_host')
                        msg_id = msg.get('msg_id')
                        client_addr = client_address[0]
                        pending_dialback[msg_id] = (msg.get('sender'), msg.get('recipient'), msg.get('message'), client_socket)
                        
                        def async_dialback_check():
                            try:
                                dialback_ok = send_dialback_check(
                                    from_host, msg_id, 'remote_pm',
                                    sender=msg.get('sender'),
                                    recipient=msg.get('recipient'),
                                    message=msg.get('message')
                                )
                                
                                if msg_id in pending_dialback:
                                    sender, recipient, message, sock = pending_dialback.pop(msg_id)
                                    
                                    if dialback_ok:
                                        if recipient not in users:
                                            sock.send((json.dumps({'status': 'error', 'reason': 'user_not_found'}) + '\n').encode('utf-8'))
                                        else:
                                            def _deliver_pm():
                                                return deliver_remote_pm(sender, recipient, message, server_host=client_addr, from_host=from_host)

                                            delivered = _deliver_pm()
                                            if delivered:
                                                sock.send((json.dumps({'status': 'ok'}) + '\n').encode('utf-8'))
                                            else:
                                                sock.send((json.dumps({'status': 'error', 'reason': 'failed'}) + '\n').encode('utf-8'))
                                    else:
                                        sock.send((json.dumps({'status': 'error', 'reason': 'Dialback failed'}) + '\n').encode('utf-8'))
                                        
                                    sock.close()
                            except Exception:
                                if msg_id in pending_dialback:
                                    _, _, _, sock = pending_dialback.pop(msg_id)
                                    try:
                                        sock.send((json.dumps({'status': 'error', 'reason': 'Internal error'}) + '\n').encode('utf-8'))
                                        sock.close()
                                    except:
                                        pass
                        
                        threading.Thread(target=async_dialback_check, daemon=True).start()
                        return
                    elif msg.get('type') == 'dialback_check':
                        data = client_socket.recv(MAX_PACKET_SIZE)
                        msg = json.loads(data.decode('utf-8').strip())
                        resp = handle_dialback_check(msg)
                        client_socket.send((json.dumps(resp) + '\n').encode('utf-8'))
                        client_socket.close()
                        return
                    elif msg.get('type') in ('room_join','room_leave','room_message','room_act','room_members_request','room_event'):
                        data = client_socket.recv(MAX_PACKET_SIZE)
                        msg = json.loads(data.decode('utf-8').strip())
                        msg_type = msg.get('type')
                        from_host = msg.get('from_host')
                        msg_id = msg.get('msg_id')
                        room = msg.get('room')
                        
                        def async_room_dialback_check():
                            try:
                                
                                dialback_ok = False
                                if msg_type in ('room_join', 'room_leave', 'room_message', 'room_act'):
                                    dialback_ok = send_dialback_check(
                                        from_host, msg_id, msg_type,
                                        sender=msg.get('sender', ''),
                                        room=room
                                    )
                                elif msg_type == 'room_event':
                                    dialback_ok = send_dialback_check(
                                        from_host, msg_id, msg_type,
                                        sender=msg.get('sender', ''),
                                        room=room,
                                        event=msg.get('event', '')
                                    )
                                elif msg_type == 'room_members_request':
                                    dialback_ok = send_dialback_check(
                                        from_host, msg_id, msg_type,
                                        room=room
                                    )
                                
                                
                                if not dialback_ok:
                                    client_socket.send((json.dumps({'status':'error','reason':'Dialback failed'}) + '\n').encode('utf-8'))
                                    client_socket.close()
                                    return
                                
                                
                                if msg_type == 'room_event':
                                    event = msg.get('event')
                                    sender = msg.get('sender')
                                    sender_origin = msg.get('sender_origin') or from_host
                                    payload = msg.get('payload') or {}
                                    room_key = f"{room}@{from_host}"
                                    _broadcast_room_event_locally(room, event, sender, sender_origin, payload, room_key=room_key)
                                    client_socket.send((json.dumps({'status':'ok'}) + '\n').encode('utf-8'))
                                    client_socket.close()
                                    return
                                    
                                elif msg_type == 'room_members_request':
                                    room_map = _room_members(room)
                                    members = [{'username': u, 'origin': h} for (u,h) in room_map.keys()]
                                    resp = {'status':'ok','type':'room_members_response','room':room,'members':members}
                                    client_socket.send((json.dumps(resp) + '\n').encode('utf-8'))
                                    client_socket.close()
                                    return
                                    
                                elif msg_type == 'room_join':
                                    sender = msg.get('sender')
                                    origin_host = from_host
                                    first = _authoritative_room_add_member(room, sender, origin_host)
                                    _update_remote_subscriber_count(room, origin_host)
                                    if first:
                                        _broadcast_room_event_locally(room, 'joined', sender, origin_host)
                                        try:
                                            threading.Thread(target=_send_room_event_to_remotes, args=(room, 'joined', sender, origin_host, None), daemon=True).start()
                                        except Exception:
                                            pass
                                    client_socket.send((json.dumps({'status':'ok'}) + '\n').encode('utf-8'))
                                    client_socket.close()
                                    return
                                    
                                elif msg_type == 'room_leave':
                                    sender = msg.get('sender')
                                    origin_host = from_host
                                    last = _authoritative_room_remove_member(room, sender, origin_host)
                                    _update_remote_subscriber_count(room, origin_host)
                                    if last:
                                        _broadcast_room_event_locally(room, 'left', sender, origin_host)
                                        try:
                                            threading.Thread(target=_send_room_event_to_remotes, args=(room, 'left', sender, origin_host, None), daemon=True).start()
                                        except Exception:
                                            pass
                                    client_socket.send((json.dumps({'status':'ok'}) + '\n').encode('utf-8'))
                                    client_socket.close()
                                    return
                                    
                                elif msg_type == 'room_message':
                                    sender = msg.get('sender')
                                    origin_host = from_host
                                    payload = msg.get('payload') or {}
                                    _broadcast_room_event_locally(room, 'message', sender, origin_host, payload)
                                    
                                    def _send_to_federation():
                                        _send_room_event_to_remotes(room, 'message', sender, origin_host, payload)
                                        return True
                                    
                                    send_with_retry(_send_to_federation)
                                    client_socket.send((json.dumps({'status':'ok'}) + '\n').encode('utf-8'))
                                    client_socket.close()
                                    return
                                    
                                elif msg_type == 'room_act':
                                    sender = msg.get('sender')
                                    origin_host = from_host
                                    payload = msg.get('payload') or {}
                                    _broadcast_room_event_locally(room, 'act', sender, origin_host, payload)
                                    try:
                                        threading.Thread(target=_send_room_event_to_remotes, args=(room, 'act', sender, origin_host, payload), daemon=True).start()
                                    except Exception:
                                        pass
                                    client_socket.send((json.dumps({'status':'ok'}) + '\n').encode('utf-8'))
                                    client_socket.close()
                                    return
                                    
                            except Exception:
                                try:
                                    client_socket.send((json.dumps({'status':'error','reason':'Internal error'}) + '\n').encode('utf-8'))
                                    client_socket.close()
                                except:
                                    pass
                        
                        threading.Thread(target=async_room_dialback_check, daemon=True).start()
                        return
                except Exception:
                    pass
        except socket.timeout:
            pass

        client_socket.settimeout(None)

        while not logged_in_user:
            if not last_cmd == "/":
                send_to_client(client_socket, "Enter command (/login /register): ", client_key)
            else:
                send_to_client(client_socket, "*Ping!*", client_key)
            command = receive_from_client(client_socket, client_key)

            if not command:
                break

            last_cmd = command

            if not command == "/":
                log_message(f"TCP {client_address} message: {command}.")

            if command.startswith("/register"):
                parts = command.split(" ", 2)
                if len(parts) != 3:
                    send_to_client(client_socket, "Usage: /register <username> <password>", client_key)
                    continue
                _, username, password = parts
                username = username.replace('@', '_')
                if username in users:
                    send_to_client(client_socket, "Username already taken. Try another.", client_key)
                    continue
                users[username] = password
                save_users(users)
                send_to_client(client_socket, "Registration successful. Please log in.", client_key)

            elif command.startswith("/login"):
                parts = command.split(" ", 2)
                if len(parts) != 3:
                    send_to_client(client_socket, "Usage: /login <username> <password>", client_key)
                    continue
                _, username, password = parts
                if authenticate_user(username, password, users):
                    logged_in_user = username
                    session.username = username
                    with session_lock:
                        sessions = clients_by_user.get(username)
                        if sessions is None:
                            clients_by_user[username] = {session}
                        else:
                            sessions.add(session)
                        socket_to_session[client_socket] = session
                        send_to_client(client_socket, "Login successful.", client_key)
                        send_to_client(client_socket, f"Available servers: {', '.join(servers.keys())}", client_key)
                        send_to_client(client_socket, "Select a server using /join_server <server_name>.", client_key)
                else:
                    send_to_client(client_socket, "Invalid username or password.", client_key)

    except (ConnectionResetError, BrokenPipeError):
        log_message(f"TCP client {client_address} disconnected unexpectedly.")
        client_socket.close()
    except Exception as e:
        log_message(f"TCP client {client_address} error: {e}.")

    try:
        while True:
            message = receive_from_client(client_socket, client_key)

            if not message:
                break

            if not message == "/":
                log_message(f"TCP {client_address} message: {message}")

            if message.startswith("/"):
                if message.startswith("/create_server"):
                    parts = message.split(" ", 1)
                    if len(parts) != 2:
                        send_to_client(client_socket, "Usage: /create_server <server_name>", client_key)
                        continue
                    _, server_name = parts
                    server_name = get_safe_server_path(server_name)
                    if server_name in servers:
                        send_to_client(client_socket, "Server already exists.", client_key)
                    else:
                        servers[server_name] = []
                        save_server(server_name, servers[server_name])
                        send_to_client(client_socket, f"Server '{server_name}' created successfully.", client_key)
                elif message.startswith("/join_server"):
                    parts = message.split(" ", 1)
                    if len(parts) != 2:
                        send_to_client(client_socket, "Usage: /join_server <server_name>", client_key)
                        continue
                    _, server_spec = parts
                    room_name, host_part = parse_room_and_host(server_spec)
                    if host_part and host_part != MY_SERVER_HOST:
                        if user_server is not None:
                            send_to_client(client_socket, f"You're already connected to the server '{user_server}'.", client_key)
                            continue
                            
                        try:
                            with socket.create_connection((host_part, 42439), timeout=3):
                                pass
                        except Exception:
                            send_to_client(client_socket, "Server does not exist.", client_key)
                            continue
                        user_server = f"{room_name}@{host_part}"
                        session.server_name = user_server
                        should_remote_join = False
                        with session_lock:
                            server_sessions = clients_by_server.get(user_server)
                            if server_sessions is None:
                                clients_by_server[user_server] = {session}
                            else:
                                server_sessions.add(session)

                            key = (logged_in_user, room_name, host_part)
                            prev = user_remote_counters.get(key, 0)
                            user_remote_counters[key] = prev + 1
                            if prev == 0:
                                should_remote_join = True
                        if should_remote_join:
                            payload = {
                                'type':'room_join',
                                'room': room_name,
                                'sender': logged_in_user
                            }
                            send_remote_room_message(host_part, room_name, payload)
                        send_to_client(client_socket, f"Joined server '{user_server}' successfully.", client_key)
                    else:
                        local_room = room_name
                        if local_room not in servers:
                            send_to_client(client_socket, "Server does not exist.", client_key)
                        else:
                            if user_server is not None:
                                send_to_client(client_socket, f"You're already connected to the server '{user_server}'.", client_key)
                            else:
                                user_server = local_room
                                session.server_name = local_room
                                should_broadcast_join = False
                                with session_lock:
                                    server_sessions = clients_by_server.get(local_room)
                                    if server_sessions is None:
                                        clients_by_server[local_room] = {session}
                                        should_broadcast_join = True
                                    else:
                                        had_sessions_for_user = any(s.username == logged_in_user for s in server_sessions)
                                        server_sessions.add(session)
                                        if not had_sessions_for_user:
                                            should_broadcast_join = True

                                    first = _authoritative_room_add_member(local_room, logged_in_user, MY_SERVER_HOST)
                                    if first:
                                        should_broadcast_join = True

                                    members = servers.get(local_room, [])
                                    if logged_in_user not in members:
                                        members.append(logged_in_user)
                                        servers[local_room] = members
                                        save_server(local_room, members)
                                if should_broadcast_join:
                                    broadcast_message(f"*** {logged_in_user} has joined the server.", user_server, sender=logged_in_user)
                                    try:
                                        threading.Thread(target=_send_room_event_to_remotes, args=(local_room, 'joined', logged_in_user, MY_SERVER_HOST, None), daemon=True).start()
                                    except Exception:
                                        pass
                                send_to_client(client_socket, f"Joined server '{local_room}' successfully.", client_key)
                elif message.startswith("/delete_server") and logged_in_user == ADMIN_USERNAME:
                    parts = message.split(" ", 1)
                    if len(parts) != 2:
                        send_to_client(client_socket, "Usage: /delete_server <server_name>", client_key)
                        continue
                    _, server_name = parts
                    if server_name == default_server:
                        send_to_client(client_socket, f"You cannot delete the default server '{default_server}'.", client_key)
                    elif server_name not in servers:
                        send_to_client(client_socket, f"Server '{server_name}' does not exist.", client_key)
                    else:
                        del servers[server_name]
                        if os.path.exists(os.path.join(servers_dir, f'{server_name}.json')):
                            os.remove(os.path.join(servers_dir, f'{server_name}.json'))
                        
                        send_to_client(client_socket, f"Server '{server_name}' deleted successfully.", client_key)

                elif message.startswith("/list_servers"):
                    send_to_client(client_socket, f"Servers: {', '.join(servers.keys())}", client_key)
                elif message.startswith("/members"):
                    if not (logged_in_user and user_server):
                        send_to_client(client_socket, "Please log in and join a server first.", client_key)
                        continue

                    room_name, host_part = parse_room_and_host(user_server)
                    if host_part and host_part != MY_SERVER_HOST:
                        req = {
                            'type': 'room_members_request',
                            'room': room_name
                        }
                        resp = send_remote_room_message(host_part, room_name, req)
                        if not resp or resp.get('status') != 'ok':
                            send_to_client(client_socket, "Failed to fetch members.", client_key)
                            continue
                        members_raw = resp.get('members', [])
                        disp = [display_name_for(MY_SERVER_HOST, m['username'], m['origin']) for m in members_raw]
                        send_to_client(client_socket, f"Members in '{user_server}': {', '.join(disp)}", client_key)
                    else:
                        room = room_name
                        room_map = _room_members(room)
                        disp = [display_name_for(MY_SERVER_HOST, u, h) for (u,h) in room_map.keys()]
                        send_to_client(client_socket, f"Members in '{user_server}': {', '.join(disp)}", client_key)
                elif message.startswith("/ban") and logged_in_user == ADMIN_USERNAME:
                    parts = message.split(" ", 1)
                    if len(parts) != 2:
                        send_to_client(client_socket, "Usage: /ban <username>", client_key)
                        continue
                    _, banned_user = parts
                    servers_to_notify = set()
                    with session_lock:
                        user_sessions = clients_by_user.pop(banned_user, set())
                        for sess in list(user_sessions):
                            srv = sess.server_name
                            try:
                                if srv:
                                    server_sessions = clients_by_server.get(srv, set())
                                    if sess in server_sessions:
                                        server_sessions.remove(sess)

                                    still_has = any(s.username == banned_user for s in server_sessions)
                                    if not still_has:
                                        members = servers.get(srv, [])
                                        if banned_user in members:
                                            members.remove(banned_user)
                                            servers[srv] = members
                                            save_server(srv, members)
                                        servers_to_notify.add(srv)
                            finally:
                                try:
                                    sess.client_socket.close()
                                except Exception:
                                    pass

                        for sock, s in list(socket_to_session.items()):
                            if s.username == banned_user:
                                socket_to_session.pop(sock, None)

                    bans[banned_user] = "BANNED"
                    save_bans(bans)
                elif message.startswith("/act"):
                    parts = message.split(" ", 1)
                    if len(parts) < 2:
                        if not logged_in_user or not username:
                            send_to_client(client_socket, "Please log in and join a server first.", client_key)
                            continue

                        send_to_client(client_socket, "Usage: /act <act>", client_key)
                        continue

                    _, act_name = parts 

                    if act_name == "has joined the server." or act_name == "has left the server.":
                        send_to_client(client_socket, "This action is not allowed.", client_key)
                        continue

                    room_name, host_part = parse_room_and_host(user_server)
                    if host_part and host_part != MY_SERVER_HOST:
                        payload = {
                            'type': 'room_act',
                            'room': room_name,
                            'sender': logged_in_user,
                            'payload': {'act': act_name}
                        }
                        send_remote_room_message(host_part, room_name, payload)
                    else:
                        broadcast_message(f"*** {logged_in_user} {act_name}", user_server, message_type='action_message', sender=logged_in_user)
                        try:
                            threading.Thread(target=_send_room_event_to_remotes, args=(room_name, 'act', logged_in_user, MY_SERVER_HOST, {'act': act_name}), daemon=True).start()
                        except Exception:
                            pass
                elif message.startswith("/pm"):
                    parts = message.split(" ", 2)
                    if len(parts) < 3:
                        send_to_client(client_socket, "Usage: /pm <username> <message>", client_key)
                        continue
                    _, recipient, private_message = parts
                    m = re.match(r"^([\w\-]+)@([\w.-]+)$", recipient)
                    if m:
                        remote_user, remote_host = m.group(1), m.group(2)
                        if remote_host == MY_SERVER_HOST:
                            recipient = remote_user 
                        else:
                            threading.Thread(target=handle_remote_pm_tcp, args=(logged_in_user, remote_user, remote_host, private_message, client_socket, recipient, client_key), daemon=True).start()
                            continue
                    if recipient not in users:
                        send_to_client(client_socket, "User does not exist.", client_key)
                        _kick_user(recipient)
                        continue
                    if recipient == logged_in_user:
                        send_to_client(client_socket, "You cannot send private messages to yourself.", client_key)
                        continue
                    if recipient in bans:
                        send_to_client(client_socket, f"{recipient} is banned.", client_key)
                        continue

                    result = send_private_message(logged_in_user, recipient, private_message)
                    if not result:
                        _kick_user(recipient)
                    notify_tcp_result(client_socket, result, recipient, client_key)
                elif message.startswith("/help"):
                    help_message = "\n".join([f"{cmd} {desc}" for cmd, desc in commands.items()])
                    send_to_client(client_socket, help_message, client_key)
                elif message.startswith("/list_capabilities"):
                    caps_list = capabilities_manager.get_capabilities_list()
                    if caps_list:
                        caps_text = "Capabilities: " + ", ".join(caps_list) + ". Use /CAPABILITY_NAME for help."
                    else:
                        caps_text = "No capabilities available."
                    send_to_client(client_socket, caps_text, client_key)
                elif message.startswith("/") and message != "/" and not any(message.startswith(cmd) for cmd in ["/login", "/register", "/create_server", "/join_server", "/list_servers", "/members", "/pm", "/act", "/help", "/list_capabilities", "/ban", "/delete_server"]):
                    cap_command = message[1:]
                    parts = cap_command.split()
                    if len(parts) > 1:
                        command_part = parts[0]
                        args = parts[1:]
                    else:
                        command_part = cap_command
                        args = []

                    server_context = {
                        'clients_by_user': clients_by_user,
                        'clients_by_server': clients_by_server,
                        'socket_to_session': socket_to_session,
                        'session_lock': session_lock,
                        'users': users,
                        'bans': bans,
                        'servers': servers
                    }
                    
                    if capabilities_manager.handle_capability_command(command_part, args, session, client_socket, client_key, server_context):
                        pass
                    else:
                        send_to_client(client_socket, "Unknown command.", client_key)
                elif message == "/":
                    send_to_client(client_socket, "*Ping!*", client_key)
                else:
                    send_to_client(client_socket, "Unknown command.", client_key)
                        
            else:
                if not logged_in_user in bans and logged_in_user and user_server:
                    room_name, host_part = parse_room_and_host(user_server)
                    if host_part and host_part != MY_SERVER_HOST:
                        payload = {
                            'type': 'room_message',
                            'room': room_name,
                            'sender': logged_in_user,
                            'payload': {'text': message}
                        }
                        send_remote_room_message(host_part, room_name, payload)
                    else:
                        full_message = f"{logged_in_user}: {message}"
                        broadcast_message(full_message, user_server, message_type='chat_message', sender=logged_in_user)
                        _send_room_event_to_remotes(room_name, 'message', logged_in_user, MY_SERVER_HOST, {'text': message})
    except Exception as e:
        log_message(f"TCP client {client_address} error: {e}.")

    finally:
        try:
            left_broadcast_needed = None
            with session_lock:
                s = socket_to_session.pop(client_socket, None)
                if s is None:
                    s = session
                if s and s.username:
                    user_sessions = clients_by_user.get(s.username, set())
                    if s in user_sessions:
                        user_sessions.remove(s)
                    if not user_sessions:
                        remaining_sessions = [sess for sess in clients_by_user.get(s.username, set()) 
                                           if hasattr(sess, 'client_socket') and sess.client_socket]
                        if not remaining_sessions:
                            clients_by_user.pop(s.username, None)
                if s and s.server_name:
                    server_sessions = clients_by_server.get(s.server_name, set())
                    if s in server_sessions:
                        server_sessions.remove(s)

                    if '@' not in s.server_name:
                        still_has = any(sess.username == s.username for sess in server_sessions)
                        if not still_has:
                            members = servers.get(s.server_name, [])
                            if s.username in members:
                                members.remove(s.username)
                                servers[s.server_name] = members
                                save_server(s.server_name, members)

                            left_broadcast_needed = (s.username, s.server_name)
                            last = _authoritative_room_remove_member(s.server_name, s.username, MY_SERVER_HOST)
                            if last:
                                try:
                                    threading.Thread(target=_send_room_event_to_remotes, args=(s.server_name, 'left', s.username, MY_SERVER_HOST, None), daemon=True).start()
                                except Exception:
                                    pass
                    else:
                        try:
                            room_name, host_part = s.server_name.split('@', 1)
                            key = (s.username, room_name, host_part)
                            prev = user_remote_counters.get(key, 0)
                            if prev > 1:
                                user_remote_counters[key] = prev - 1
                            else:
                                user_remote_counters.pop(key, None)
                                payload = {
                                    'type': 'room_leave',
                                    'room': room_name,
                                    'sender': s.username
                                }
                                send_remote_room_message(host_part, room_name, payload)
                        except Exception:
                            pass
        finally:
            try:
                client_socket.close()
            except Exception:
                pass
            client_keys.pop(client_address, None)
            try:
                with _send_state_lock:
                    q = _send_queues.get(client_socket)
                if q is not None:
                    try:
                        q.put_nowait(None)
                    except Exception:
                        pass
                with _send_state_lock:
                    _send_queues.pop(client_socket, None)
                    _send_workers.pop(client_socket, None)
            except Exception:
                pass
            if left_broadcast_needed:
                u, srv = left_broadcast_needed
                broadcast_message(f"*** {u} has left the server.", srv, sender=u)
        log_message(f"TCP client {client_address} disconnected.")


def start_tcp_server(host='0.0.0.0', port=TCP_PORT):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"TCP server started on {host}:{port}")

    while True:
        client_socket, client_address = server_socket.accept()

        def _dispatch_connection(sock, addr):
            try:
                sock.settimeout(0.5)
                try:
                    peek = sock.recv(1024, socket.MSG_PEEK)
                except socket.timeout:
                    peek = b''
                except Exception:
                    peek = b''
                finally:
                    try:
                        sock.settimeout(None)
                    except Exception:
                        pass

                try:
                    if capabilities_manager.try_handle_raw_connection(sock, addr, peek):
                        return
                except Exception:
                    pass

                handle_client(sock, addr)
            except Exception:
                try:
                    sock.close()
                except Exception:
                    pass

        client_thread = threading.Thread(target=_dispatch_connection, args=(client_socket, client_address))
        client_thread.start()

def handle_dialback_check(msg_data):
    msg_id = msg_data.get('msg_id')

    return {
        'type': 'dialback_result', 
        'msg_id': msg_id, 
        'result': 'ok'
    }

def _send_remote_room_sync(target_host, target_port, data):
    def _send_room_msg():
        try:
            with socket.create_connection((target_host, target_port), timeout=5) as s:
                s.sendall((json.dumps(data) + '\n').encode('utf-8'))
                s.settimeout(5)
                response = b''
                while not response.endswith(b'\n'):
                    chunk = s.recv(MAX_PACKET_SIZE)
                    if not chunk:
                        break
                    response += chunk
                if response:
                    try:
                        return json.loads(response.decode('utf-8').strip())
                    except Exception:
                        return None
                return None
        except Exception:
            raise
    
    return send_with_retry(_send_room_msg)

def _kick_user(username):
    try:
        removed_from_servers = []

        for server_name in list(servers.keys()):
            if '@' in server_name:
                continue

            room_map = _room_members(server_name)
            
            for (user, origin_host) in list(room_map.keys()):
                if user == username and origin_host == MY_SERVER_HOST:
                    last = _authoritative_room_remove_member(server_name, username, origin_host)
                    
                    if last:
                        broadcast_message(f"*** {username} has left the server.", server_name, sender=username)

                        members = servers.get(server_name, [])
                        
                        if username in members:
                            members.remove(username)
                            servers[server_name] = members
                            save_server(server_name, members)

                        removed_from_servers.append(server_name)
                    break

    except Exception as e:
        log_message(f"Error: {e}.")

def cleanup_OU():
    try:
        with session_lock:
            active_users_by_server = {}
            for server_name, sessions in clients_by_server.items():
                active_users_by_server[server_name] = {sess.username for sess in sessions if sess.username}

        for server_name in list(servers.keys()):
            room_map = _room_members(server_name)
            users_to_remove = []

            active_users_on_server = active_users_by_server.get(server_name, set())

            for (username, origin_host) in list(room_map.keys()):
                if origin_host == MY_SERVER_HOST:
                    if username not in active_users_on_server:
                        users_to_remove.append((username, origin_host))
                else:
                    subs = _remote_subscribers(server_name)
                    if origin_host not in subs:
                        users_to_remove.append((username, origin_host))

            for username, origin_host in users_to_remove:
                last = _authoritative_room_remove_member(server_name, username, origin_host)
                if last:
                    broadcast_message(f"*** {username} has left the server.", server_name, sender=username)

                    if '@' not in server_name:
                        members = servers.get(server_name, [])
                        if username in members:
                            members.remove(username)
                            servers[server_name] = members
                            save_server(server_name, members)

    except Exception as e:
        log_message(f"Error: {e}.")

def cleanup_tasks():
    while True:
        time.sleep(60)
        current_time = time.time()
        to_remove = []
        for key, (timestamp, result) in dialback_cache.items():
            if current_time - timestamp > DIALBACK_CACHE_TTL:
                to_remove.append(key)
        for key in to_remove:
            del dialback_cache[key]

        cleanup_OU()

if __name__ == "__main__":
    threading.Thread(target=cleanup_tasks, daemon=True).start()
    threading.Thread(target=start_key_exchange_server, daemon=True).start()
    threading.Thread(target=start_tcp_server).start()
