import ast
import socket
import types
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class EmbedServerBindTest(unittest.TestCase):
    def test_server_binds_the_configured_address_family(self):
        path = Path(__file__).resolve().parent.parent / "blkchain" / "embed_server.py"
        tree = ast.parse(path.read_text())
        node = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "_Server")
        definition = compile(ast.Module(body=[node], type_ignores=[]), str(path), "exec")
        for host, family in (("127.0.0.1", socket.AF_INET), ("localhost", socket.AF_INET), ("::1", socket.AF_INET6)):
            with self.subTest(host=host):
                if family == socket.AF_INET6 and not socket.has_ipv6:
                    continue
                namespace = {"socket": socket, "config": types.SimpleNamespace(EMBED_SERVER_HOST=host),
                             "ThreadingHTTPServer": ThreadingHTTPServer}
                exec(definition, namespace)
                with namespace["_Server"]((host, 0), BaseHTTPRequestHandler) as server:
                    self.assertEqual(server.socket.family, family)
                    self.assertGreater(server.server_port, 0)


if __name__ == "__main__":
    unittest.main()
