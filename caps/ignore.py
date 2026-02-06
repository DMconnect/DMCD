import json
import os
import threading

from caps.caps import Capability

_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'ignores.json')
_lock = threading.RLock()


def _load():
    with _lock:
        if not os.path.exists(_PATH):
            return {}
        try:
            with open(_PATH, 'r', encoding='utf-8') as f:
                raw = json.load(f)
            return {u: list(v) if isinstance(v, list) else list(v.keys()) for u, v in raw.items()}
        except Exception:
            return {}


def _save(data):
    with _lock:
        with open(_PATH, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=4)


def is_ignored(recipient_username, sender_username, context):
    return sender_username in _load().get(recipient_username, [])


class IgnoreCapability(Capability):
    def __init__(self):
        super().__init__("ignore", {
            "add": "<username> - add to ignore list",
            "del": "<username> - remove from ignore list",
            "list": "- show ignore list",
            "clear": "- clear entire ignore list"
        })

    def register_filters(self, manager):
        try:
            manager.register_message_filter(lambda r, s, c: is_ignored(r, s, c))
        except Exception:
            pass

    def _ok(self, session, sock, key):
        if session and session.username:
            return session.username
        self.send_message("Please log in first.", sock, key)
        return None

    def handle_add(self, args, session, client_socket, client_key, server_context=None):
        if self._ok(session, client_socket, client_key) is None:
            return True
        if not args:
            self.send_message("Usage: /ignore-add <username>", client_socket, client_key)
            return True
        target = args[0].strip()
        data = _load()
        data.setdefault(session.username, [])
        if target not in data[session.username]:
            data[session.username].append(target)
            _save(data)
        self.send_message(f"Ignoring {target}.", client_socket, client_key)
        return True

    def handle_del(self, args, session, client_socket, client_key, server_context=None):
        if self._ok(session, client_socket, client_key) is None:
            return True
        if not args:
            self.send_message("Usage: /ignore-del <username>", client_socket, client_key)
            return True
        target, data = args[0].strip(), _load()
        rec = data.get(session.username, [])
        if target not in rec:
            self.send_message(f"{target} is not in your ignore list.", client_socket, client_key)
            return True
        rec.remove(target)
        if not rec:
            del data[session.username]
        _save(data)
        self.send_message(f"Stopped ignoring {target}.", client_socket, client_key)
        return True

    def handle_list(self, args, session, client_socket, client_key, server_context=None):
        if self._ok(session, client_socket, client_key) is None:
            return True
        rec = _load().get(session.username, [])
        self.send_message("Ignore list: " + ", ".join(rec) if rec else "Ignore list is empty.", client_socket, client_key)
        return True

    def handle_clear(self, args, session, client_socket, client_key, server_context=None):
        if self._ok(session, client_socket, client_key) is None:
            return True
        data = _load()
        if session.username in data:
            del data[session.username]
            _save(data)
            self.send_message("Ignore list cleared.", client_socket, client_key)
        else:
            self.send_message("Ignore list is already empty.", client_socket, client_key)
        return True
