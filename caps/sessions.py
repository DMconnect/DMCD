from caps.caps import Capability


class SessionsCapability(Capability):
    def __init__(self):
        super().__init__(
            name="sessions",
            commands={
                "list": "- Show IP addresses of active sessions for your account"
            }
        )

    def handle_list(self, args, session, client_socket, client_key, server_context=None):
        if not session or not getattr(session, 'username', None):
            self.send_message("Please log in first.", client_socket, client_key)
            return True

        username = session.username
        current_ip = None
        try:
            current_ip = client_socket.getpeername()[0]
        except Exception:
            current_ip = None

        if server_context:
            clients_by_user = server_context.get('clients_by_user', {})
            session_lock = server_context.get('session_lock')
            with session_lock:
                user_sessions = list(clients_by_user.get(username, set()))
        else:
            import DMCD
            with DMCD.session_lock:
                user_sessions = list(DMCD.clients_by_user.get(username, set()))

        ips = []
        seen = set()
        for sess in user_sessions:
            try:
                ip = sess.client_socket.getpeername()[0]
            except Exception:
                continue
            if not ip or ip in seen:
                continue
                
            seen.add(ip)
            ips.append(ip)

        if not ips:
            self.send_message("No active sessions found.", client_socket, client_key)
            return True

        formatted = []
        for ip in sorted(ips):
            if current_ip and ip == current_ip:
                formatted.append(f"{ip} (this is you)")
            else:
                formatted.append(ip)

        self.send_message("Active session IPs: " + ", ".join(formatted), client_socket, client_key)
        return True
