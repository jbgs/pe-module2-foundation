import json
import threading
import unittest
import urllib.error
import urllib.request

import main


class ServiceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Port 0 lets the OS pick a free port, so tests never collide with anything.
        cls.server = main.make_server("127.0.0.1", 0, "test-version")
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def get(self, path):
        url = "http://127.0.0.1:%d%s" % (self.port, path)
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                return response.status, response.headers, json.loads(response.read())
        except urllib.error.HTTPError as error:
            return error.code, error.headers, json.loads(error.read())

    def test_root_reports_service_and_version(self):
        status, _, body = self.get("/")
        self.assertEqual(status, 200)
        self.assertEqual(body, {"service": main.SERVICE_NAME, "version": "test-version"})

    def test_healthz_is_ok(self):
        status, _, body = self.get("/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(body, {"status": "ok"})

    def test_unknown_path_is_404(self):
        status, _, body = self.get("/nope")
        self.assertEqual(status, 404)
        self.assertEqual(body, {"error": "not found"})

    def test_responses_are_json(self):
        for path in ("/", "/healthz", "/nope"):
            _, headers, _ = self.get(path)
            self.assertEqual(headers["Content-Type"], "application/json")

    def test_head_matches_get_without_a_body(self):
        url = "http://127.0.0.1:%d/healthz" % self.port
        request = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(request, timeout=5) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(response.headers["Content-Type"], "application/json")
            self.assertEqual(response.read(), b"")

    def test_server_header_does_not_leak_python_version(self):
        _, headers, _ = self.get("/")
        self.assertNotIn("Python", headers["Server"])


if __name__ == "__main__":
    unittest.main()
