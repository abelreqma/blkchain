import ast
import socket
import threading
import types
import unittest
from unittest import mock
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from blkchain.httputil import read_json_body, send_json


def server_class(host="127.0.0.1", timeout=15.0, max_clients=16):
    path = Path(__file__).resolve().parent.parent / "blkchain" / "embed_server.py"
    tree = ast.parse(path.read_text())
    node = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "_Server")
    definition = compile(ast.Module(body=[node], type_ignores=[]), str(path), "exec")
    namespace = {"socket": socket, "threading": threading,
                 "_MAX_CLIENTS": max_clients, "_CLIENT_IO_TIMEOUT": timeout,
                 "config": types.SimpleNamespace(EMBED_SERVER_HOST=host),
                 "ThreadingHTTPServer": ThreadingHTTPServer}
    exec(definition, namespace)
    return namespace["_Server"]


class EmbedServerBindTest(unittest.TestCase):
    def test_server_binds_the_configured_address_family(self):
        for host, family in (("127.0.0.1", socket.AF_INET), ("localhost", socket.AF_INET), ("::1", socket.AF_INET6)):
            with self.subTest(host=host):
                if family == socket.AF_INET6 and not socket.has_ipv6:
                    continue
                with server_class(host)((host, 0), BaseHTTPRequestHandler) as server:
                    self.assertEqual(server.socket.family, family)
                    self.assertGreater(server.server_port, 0)

    def test_server_limits_connections_and_socket_io(self):
        with server_class()(("127.0.0.1", 0), BaseHTTPRequestHandler) as server:
            peer = socket.create_connection(server.server_address)
            accepted, _ = server.get_request()
            try:
                self.assertEqual(accepted.gettimeout(), 15.0)
            finally:
                accepted.close()
                peer.close()

            for _ in range(16):
                self.assertTrue(server._slots.acquire(blocking=False))
            self.assertFalse(server._slots.acquire(blocking=False))
            incoming, client = socket.socketpair()
            try:
                server.process_request(incoming, ("127.0.0.1", 1))
                self.assertEqual(incoming.fileno(), -1)
            finally:
                incoming.close()
                client.close()
                for _ in range(16):
                    server._slots.release()

    def test_incomplete_post_times_out_on_a_real_connection(self):
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                _, code, message = read_json_body(self, 1024)
                send_json(self, code, {"error": message})

            def log_message(self, *_args):
                pass

        with server_class(timeout=0.25, max_clients=2)(("127.0.0.1", 0), Handler) as server:
            worker = threading.Thread(target=server.serve_forever,
                                      kwargs={"poll_interval": 0.01}, daemon=True)
            worker.start()
            try:
                with mock.patch("blkchain.httputil.BODY_READ_SECONDS", 0.25):
                    with socket.create_connection(server.server_address, timeout=2) as conn:
                        conn.settimeout(2)
                        conn.sendall(b"POST /embed HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\n\r\n{")
                        self.assertIn(b" 408 ", conn.recv(4096))
            finally:
                server.shutdown()
                worker.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
