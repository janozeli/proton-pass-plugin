"""MCP server-to-client requests. Input continues while a tool awaits consent."""
import secrets
import threading


class ConsentError(Exception):
    pass


class Peer:
    def __init__(self, send):
        self.send = send
        self.capabilities = {}
        self.pending = {}
        self.lock = threading.Lock()
        self.closed = False

    def supports_forms(self):
        cap = self.capabilities.get("elicitation")
        return isinstance(cap, dict) and (not cap or "form" in cap)

    def consent(self, message, network=False):
        if not self.supports_forms():
            raise ConsentError("This host does not advertise MCP form elicitation. User approval is unavailable; nothing was released.")
        props = {"approve": {"type": "boolean", "title": "Approve this operation", "default": False}}
        if network:
            props["allow_network"] = {"type": "boolean", "title": "Also allow network access", "default": False}
        params = {"message": message, "requestedSchema": {"type": "object", "properties": props, "required": ["approve"]}}
        event, box = threading.Event(), {}
        mid = "consent-" + secrets.token_hex(16)
        with self.lock:
            if self.closed:
                raise ConsentError("client disconnected")
            self.pending[mid] = (event, box)
        try:
            self.send({"jsonrpc": "2.0", "id": mid, "method": "elicitation/create", "params": params})
            if not event.wait(180):
                raise ConsentError("approval timed out")
            result = box.get("result", {})
            if not isinstance(result, dict):
                raise ConsentError("invalid approval response")
            content = result.get("content", {})
            if not isinstance(content, dict):
                raise ConsentError("invalid approval response")
            if result.get("action") != "accept" or content.get("approve") is not True:
                raise ConsentError("release denied")
            return "allow-net" if network and content.get("allow_network") is True else "allow"
        finally:
            with self.lock:
                self.pending.pop(mid, None)

    def receive(self, msg):
        if not isinstance(msg, dict) or "method" in msg or not ("result" in msg or "error" in msg):
            return False
        with self.lock:
            item = self.pending.get(msg.get("id")) if isinstance(msg.get("id"), str) else None
            if item:
                item[1].update(msg)
                item[0].set()
        return True  # Never answer an RPC response, including a late response.

    def close(self):
        with self.lock:
            self.closed = True
            for event, box in self.pending.values():
                event.set()
