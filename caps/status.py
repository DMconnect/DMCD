from caps.caps import Capability
import json
import os
import socket
import threading
import time

_state_lock = threading.RLock()
_subs_file = 'status_subs.json'
_subscriptions = None
_last_state = {}
_REMOTE_CHECK_TIMEOUT = 5

_REMOTE_SUBS_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'status_remote_subs.json')
_remote_subs = None

def _dmcd_module():
    import sys

    main = sys.modules.get('__main__')

    if main and hasattr(main, 'clients_by_user') and hasattr(main, 'session_lock'):
        return main

    return sys.modules.get('DMCD') or main

def _load_remote_subs():
    global _remote_subs

    with _state_lock:
        if _remote_subs is not None:
            return
            
        out = {}

        try:
            if os.path.exists(_REMOTE_SUBS_FILE):
                with open(_REMOTE_SUBS_FILE, 'r', encoding='utf-8') as f:
                    raw = json.load(f)

                if isinstance(raw, dict):
                    for local_user, by_host in raw.items():
                        if not isinstance(local_user, str) or not isinstance(by_host, dict):
                            continue

                        out.setdefault(local_user, {})

                        for host, users in by_host.items():
                            if not isinstance(host, str) or not isinstance(users, list):
                                continue

                            out[local_user][host] = set(str(u) for u in users if u)

        except Exception:
            out = {}

        _remote_subs = out

def _save_remote_subs():
    _load_remote_subs()

    with _state_lock:
        data = {}

        for local_user, by_host in _remote_subs.items():

            if not by_host:
                continue

            data[local_user] = {h: sorted(list(us)) for h, us in by_host.items() if us}
    try:

        with open(_REMOTE_SUBS_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=4)

    except Exception:
        pass

def _send_s2s(host, payload):
    DMCD = _dmcd_module()

    if DMCD is None:
        return None

    try:
        out = dict(payload or {})

        out.setdefault('from_host', getattr(DMCD, 'MY_SERVER_HOST', '') or DMCD.get_advertised_host())
        out.setdefault('msg_id', DMCD.generate_msg_id(out.get('type', 'presence'), host, str(time.time())))
        resp = DMCD._send_remote_room_sync(host, 42439, out)
        return resp

    except Exception:
        return None

def handle_presence_subscribe(from_host, subscriber_user, target_local_user):
    _load_remote_subs()

    if not from_host or not subscriber_user or not target_local_user:
        return False

    with _state_lock:
        by_host = _remote_subs.setdefault(target_local_user, {})
        users = by_host.setdefault(from_host, set())
        users.add(subscriber_user)
        
    _save_remote_subs()

    return True

def handle_presence_unsubscribe(from_host, subscriber_user, target_local_user):
    _load_remote_subs()

    if not from_host or not subscriber_user or not target_local_user:
        return False

    changed = False

    with _state_lock:
        by_host = _remote_subs.get(target_local_user, {})
        users = by_host.get(from_host, set())

        if subscriber_user in users:
            users.remove(subscriber_user)
            changed = True

        if not users:
            by_host.pop(from_host, None)

        if not by_host:
            _remote_subs.pop(target_local_user, None)

    if changed:
        _save_remote_subs()
    return True

def handle_presence_update(from_host, user, online):
    if not from_host or not user:
        return False

    notify_status_change(f"{user}@{from_host}", bool(online))
    return True

def _load_subscriptions():
    global _subscriptions
    with _state_lock:

        if _subscriptions is not None:
            return

        subs = {}

        try:
            if os.path.exists(_subs_file):
                with open(_subs_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                if isinstance(data, dict):
                    for subscriber, targets in data.items():
                        if isinstance(subscriber, str) and isinstance(targets, list):
                            subs[subscriber] = set(str(t) for t in targets if t)

        except Exception:
            subs = {}

        _subscriptions = subs

def _save_subscriptions():
    with _state_lock:
        if _subscriptions is None:
            return

        data = {k: sorted(list(v)) for k, v in _subscriptions.items() if v}

    try:
        with open(_subs_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=4)

    except Exception:
        pass

def _normalize_target(raw):
    try:
        t = (raw or '').strip().replace(' ', '')

        if not t:
            return None

        if '@' in t:
            u, h = t.rsplit('@', 1)

            if not u or not h:
                return None

            dmcd = _dmcd_module()
            if dmcd and getattr(dmcd, 'MY_SERVER_HOST', None) and h == dmcd.MY_SERVER_HOST:
                return u

            return f"{u}@{h}"
        return t

    except Exception:
        return None

def sub_add(subscriber, target_raw):
    _load_subscriptions()
    t = _normalize_target(target_raw)

    if not subscriber:
        return False, "Please log in first."

    if not t:
        return False, "Invalid username."

    if t == subscriber:
        return False, "You cannot subscribe to yourself."

    with _state_lock:
        targets = _subscriptions.get(subscriber)

        if targets is None:
            targets = set()
            _subscriptions[subscriber] = targets

        if t in targets:
            return True, f"Already subscribed to {t}."
        targets.add(t)

    _save_subscriptions()
    return True, f"Subscribed to {t}."

def sub_del(subscriber, target_raw):
    _load_subscriptions()
    t = _normalize_target(target_raw)

    if not subscriber:
        return False, "Please log in first."

    if not t:
        return False, "Invalid username."

    with _state_lock:
        targets = _subscriptions.get(subscriber, set())

        if t not in targets:
            return True, f"Not subscribed to {t}."

        targets.remove(t)

        if not targets:
            _subscriptions.pop(subscriber, None)

    _save_subscriptions()
    return True, f"Unsubscribed from {t}."

def sub_list(subscriber):
    _load_subscriptions()

    if not subscriber:
        return []
        
    with _state_lock:
        return sorted(list(_subscriptions.get(subscriber, set())))

def sub_clear(subscriber):
    _load_subscriptions()
    if not subscriber:
        return

    with _state_lock:
        _subscriptions.pop(subscriber, None)
        
    _save_subscriptions()

def notify_status_change(target_identifier, online):
    _load_subscriptions()
    key = _normalize_target(target_identifier)

    if not key:
        return

    now = bool(online)

    with _state_lock:
        prev = _last_state.get(key)

        if prev is None:
            _last_state[key] = now

        if prev == now:
            return

        _last_state[key] = now
        subs_snapshot = {k: set(v) for k, v in (_subscriptions or {}).items()}

    msg = f"{key} is {'online' if now else 'offline'}."

    try:
        DMCD = _dmcd_module()

        if DMCD is None:
            return

        for subscriber, targets in subs_snapshot.items():
            if key not in targets:
                continue

            with DMCD.session_lock:
                sessions = list(DMCD.clients_by_user.get(subscriber, set()))

            for sess in sessions:
                try:
                    client_key = DMCD.get_client_encryption_key(sess)

                    if client_key:
                        DMCD.send_to_client(sess.client_socket, msg, client_key, 'system')

                    else:
                        sess.send_text(msg, 'system')

                except Exception:
                    pass

    except Exception:
        pass

    try:
        _load_remote_subs()
        if '@' in key:
            return

        with _state_lock:
            by_host = dict(_remote_subs.get(key, {}))

        for host in by_host.keys():
            if host:
                _send_s2s(host, {'type': 'presence_update', 'user': key, 'online': now})

    except Exception:
        pass

class StatusCapability(Capability):
    def __init__(self):
        super().__init__(
            name="status",
            commands={
                "check": "<username> - Check if a user is online or offline",
                "sub-add": "<username> - Subscribe to status notifications",
                "sub-del": "<username> - Unsubscribe from status notifications",
                "sub-list": "- Show your subscription list",
                "sub-clear": "- Clear your subscription list"
            }
        )
    
    def handle_check(self, args, session, client_socket, client_key, server_context=None):
        if len(args) < 1:
            self.send_message("Usage: /status-check <username>", client_socket, client_key)
            return True
        
        username = args[0]

        if '@' in username:
            user_part, host_part = username.rsplit('@', 1)

            import sys

            dmcd = sys.modules.get('DMCD') or sys.modules.get('__main__')
            my_host = getattr(dmcd, 'MY_SERVER_HOST', None) if dmcd else None

            if my_host and host_part == my_host:
                username = user_part
            else:
                try:
                    with socket.create_connection((host_part, 42439), timeout=_REMOTE_CHECK_TIMEOUT) as s:
                        req = {'type': 'status_request', 'usernames': [user_part], 'from_host': my_host or ''}
                        s.sendall((json.dumps(req) + '\n').encode('utf-8'))
                        s.settimeout(_REMOTE_CHECK_TIMEOUT)
                        resp = b''

                        while not resp.endswith(b'\n'):
                            chunk = s.recv(32 * 1024)

                            if not chunk:
                                break

                            resp += chunk

                    out = json.loads(resp.decode('utf-8', errors='replace').strip() or '{}')
                    online_map = out.get('online_map') if isinstance(out, dict) else None
                    online = bool(online_map.get(user_part, False)) if isinstance(online_map, dict) else False
                    self.send_message(f"{user_part}@{host_part} is {'online' if online else 'offline'}.", client_socket, client_key)

                except Exception:
                    self.send_message(f"{user_part}@{host_part} is offline.", client_socket, client_key)

                return True

        if server_context:
            clients_by_user = server_context.get('clients_by_user', {})
            session_lock = server_context.get('session_lock')

            with session_lock:
                user_sessions = list(clients_by_user.get(username, set()))
        else:
            import sys
            DMCD = sys.modules.get('DMCD') or sys.modules.get('__main__')

            if DMCD is None:
                user_sessions = []

            else:
                with DMCD.session_lock:
                    user_sessions = list(DMCD.clients_by_user.get(username, set()))

        self.send_message(f"{username} is {'online' if user_sessions else 'offline'}.", client_socket, client_key)
        
        return True

    def handle_sub_add(self, args, session, client_socket, client_key, server_context=None):
        if not getattr(session, 'username', None):
            self.send_message("Please log in first.", client_socket, client_key)
            return True

        if len(args) < 1:
            self.send_message("Usage: /status-sub-add <username>", client_socket, client_key)
            return True

        ok, msg = sub_add(session.username, args[0])
        self.send_message(msg, client_socket, client_key)

        try:
            t = _normalize_target(args[0])

            if t and '@' in t:
                user_part, host_part = t.rsplit('@', 1)
                dmcd = _dmcd_module()
                my_host = getattr(dmcd, 'MY_SERVER_HOST', None) if dmcd else None

                if host_part and my_host and host_part != my_host:

                    resp = _send_s2s(host_part, {
                        'type': 'presence_subscribe',
                        'subscriber': session.username,
                        'target': user_part
                    })

                    if not isinstance(resp, dict):
                        self.send_message("User does not exist.", client_socket, client_key)
                        
                    elif resp.get('status') != 'ok':
                        self.send_message(f"User does not exist.", client_socket, client_key)

        except Exception:
            pass

        return True

    def handle_sub_del(self, args, session, client_socket, client_key, server_context=None):
        if not getattr(session, 'username', None):
            self.send_message("Please log in first.", client_socket, client_key)
            return True

        if len(args) < 1:
            self.send_message("Usage: /status-sub-del <username>", client_socket, client_key)
            return True

        ok, msg = sub_del(session.username, args[0])
        self.send_message(msg, client_socket, client_key)

        try:
            t = _normalize_target(args[0])

            if t and '@' in t:
                user_part, host_part = t.rsplit('@', 1)
                dmcd = _dmcd_module()
                my_host = getattr(dmcd, 'MY_SERVER_HOST', None) if dmcd else None

                if host_part and my_host and host_part != my_host:
                    resp = _send_s2s(host_part, {
                        'type': 'presence_unsubscribe',
                        'subscriber': session.username,
                        'target': user_part
                    })

                    if not isinstance(resp, dict):
                        self.send_message("Remote unsubscribe: no response.", client_socket, client_key)

                    elif resp.get('status') != 'ok':
                        self.send_message(f"Remote unsubscribe failed: {resp}", client_socket, client_key)
        except Exception:
            pass
        return True

    def handle_sub_list(self, args, session, client_socket, client_key, server_context=None):
        if not getattr(session, 'username', None):
            self.send_message("Please log in first.", client_socket, client_key)
            return True

        subs = sub_list(session.username)

        if not subs:
            self.send_message("Subscriptions list is empty.", client_socket, client_key)

        else:
            self.send_message("Subscriptions list: " + ", ".join(subs), client_socket, client_key)
        return True

    def handle_sub_clear(self, args, session, client_socket, client_key, server_context=None):
        if not getattr(session, 'username', None):
            self.send_message("Please log in first.", client_socket, client_key)
            return True

        try:
            prior = sub_list(session.username)
            for t in prior:
                if '@' not in t:
                    continue

                user_part, host_part = t.rsplit('@', 1)
                dmcd = _dmcd_module()
                my_host = getattr(dmcd, 'MY_SERVER_HOST', None) if dmcd else None

                if host_part and my_host and host_part != my_host:
                    _send_s2s(host_part, {
                        'type': 'presence_unsubscribe',
                        'subscriber': session.username,
                        'target': user_part
                    })

        except Exception:
            pass

        sub_clear(session.username)
        self.send_message("Subscriptions cleared.", client_socket, client_key)

        return True
