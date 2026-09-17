"""Offline regression tests; no TrueNAS, Docker daemon, or Tailscale required."""
import datetime
import ipaddress
import json
import logging
import os
from pathlib import Path
import runpy
import ssl
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch
import warnings

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from websockets.exceptions import ConnectionClosed
from websockets.sync.server import serve

import renew_update_cert as app


SECRET = "test-api-key-never-log"
PRIVATE_KEY = "test-private-key-never-log"
ROOT = Path(app.__file__).parent


def config(url="https://127.0.0.1/api/v2.0", verify=False):
    return app.Config(url, SECRET, "nas.tailnet.ts.net", "tailscale", verify_ssl=verify)


class MockTrueNAS:
    """A real local WebSocket endpoint with a small TrueNAS state machine."""

    def __init__(self, tls=None, pem="certificate", existing=False, legacy=False):
        self.tls = tls
        self.pem = pem
        self.existing = existing
        self.legacy = legacy
        self.active_id = 9
        self.calls = []
        self.paths = []
        self.errors = []
        self.connections = 0
        self.reject_auth = False
        self.fail = None
        self.drop = None
        self.job_state = "SUCCESS"
        self.job_result = None
        self.ignore_update = False
        self.stall = None
        self.malformed = None
        self.notices = False
        self.drop_first_reconnect = False

    def record(self, name):
        return {"id": 7, "name": name, "certificate": self.pem}

    def handler(self, ws):
        self.connections += 1
        connection = self.connections
        self.paths.append(ws.request.path)
        authenticated = False
        try:
            for raw in ws:
                request = json.loads(raw)
                assert request["jsonrpc"] == "2.0"
                method, params = request["method"], request["params"]
                self.calls.append((connection, method, params))
                if self.drop_first_reconnect and connection == 2:
                    ws.close()
                    return
                if method == self.drop:
                    ws.close()
                    return
                if method == self.malformed:
                    ws.send("not json " + SECRET + PRIVATE_KEY)
                    continue
                if method == self.stall:
                    for _ in range(100):
                        ws.send(json.dumps({"jsonrpc": "2.0", "method": "collection_update", "params": {}}))
                        time.sleep(0.01)
                    continue
                if method == self.fail:
                    ws.send(json.dumps({"jsonrpc": "2.0", "id": request["id"], "error": {
                        "code": -32001, "message": SECRET, "data": {"reason": PRIVATE_KEY},
                    }}))
                    continue
                if method == "auth.login_with_api_key":
                    assert params == [SECRET]
                    authenticated = not self.reject_auth
                    result = authenticated
                else:
                    assert authenticated, "Method sent before authentication"
                    if method == "system.state":
                        result = "READY"
                    elif method == "system.general.config":
                        result = {"ui_certificate": {"id": self.active_id} if self.active_id else None}
                    elif method == "certificate.query":
                        name = params[0][0][2]
                        assert params == [[["name", "=", name]]]
                        # The unrelated first item ensures cleanup never uses the
                        # first certificate choice as the previous active cert.
                        result = [{"id": 1, "name": "unrelated"}]
                        if self.existing:
                            result.append(self.record(name))
                    elif method == "certificate.create":
                        payload = params[0]
                        assert payload["create_type"] == "CERTIFICATE_CREATE_IMPORTED"
                        assert payload["privatekey"] == PRIVATE_KEY
                        self.job_result = self.record(payload["name"])
                        result = 42 if self.legacy else self.job_result
                    elif method == "core.get_jobs":
                        assert params == [[["id", "=", 42]]]
                        result = [{"id": 42, "state": self.job_state, "result": self.job_result,
                                   "error": SECRET + PRIVATE_KEY}]
                    elif method == "system.general.update":
                        assert params == [{"ui_certificate": 7}]
                        if not self.ignore_update:
                            self.active_id = 7
                        result = {"ui_certificate": {"id": self.active_id}}
                    elif method == "system.general.ui_restart":
                        assert params == [3]
                        result = None
                    elif method == "certificate.delete":
                        assert params == [9, False]
                        assert self.active_id == 7
                        self.job_result = True
                        result = 42 if self.legacy else True
                    else:
                        raise AssertionError("Unexpected method: " + method)
                if self.notices:
                    ws.ping(b"keepalive")
                    ws.send(json.dumps({"jsonrpc": "2.0", "method": "collection_update", "params": {}}))
                    ws.send(json.dumps({"jsonrpc": "2.0", "id": -99, "result": "unrelated"}))
                ws.send(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}))
                if method == "system.general.ui_restart":
                    # Restart acknowledgement followed by the nginx disconnect.
                    ws.close()
                    return
        except ConnectionClosed:
            pass
        except Exception as exc:
            self.errors.append(exc)

    def __enter__(self):
        quiet_logger = logging.getLogger("mock-truenas")
        quiet_logger.disabled = True
        self.server = serve(self.handler, "127.0.0.1", 0, ssl=self.tls,
                            close_timeout=0.1, logger=quiet_logger)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        port = self.server.socket.getsockname()[1]
        self.url = f"{'https' if self.tls else 'http'}://127.0.0.1:{port}/proxy/api/v2.0"
        return self

    def __exit__(self, *args):
        self.server.shutdown()
        self.thread.join(timeout=3)
        if self.errors:
            raise AssertionError(self.errors)

    def methods(self):
        return [method for _, method, _ in self.calls]


class ConfigTests(unittest.TestCase):
    def test_url_translation(self):
        cases = {
            "https://127.0.0.1/api/v2.0/": "wss://127.0.0.1/api/current",
            "http://nas:8080/api/v2.0": "ws://nas:8080/api/current",
            "https://[::1]:444/proxy/api/v2.0": "wss://[::1]:444/proxy/api/current",
            "https://nas": "wss://nas/api/current",
            "https://nas/proxy/": "wss://nas/proxy/api/current",
            "wss://nas/proxy/api/current": "wss://nas/proxy/api/current",
            "ws://nas/api/v25.10.0/": "ws://nas/api/v25.10.0",
        }
        for source, expected in cases.items():
            with self.subTest(source=source):
                self.assertEqual(app.websocket_url(source), expected)

    def test_bad_urls_fail_without_echoing_input(self):
        for url in ["ftp://nas", "https://", "https://nas:bad", "ws://nas/websocket",
                    f"https://user:{SECRET}@nas", f"https://nas?key={SECRET}"]:
            with self.subTest(url=url), self.assertRaises(app.APIError) as caught:
                app.websocket_url(url)
            self.assertNotIn(SECRET, str(caught.exception))

    def test_config_formats_defaults_and_overrides(self):
        with tempfile.TemporaryDirectory() as directory:
            for suffix in [".yaml", ".yml", ".json"]:
                path = Path(directory) / ("config" + suffix)
                # JSON is also valid YAML.
                path.write_text(json.dumps({"api_key": SECRET, "hostname": "nas"}))
                loaded = app.load_config(path)
                self.assertEqual(loaded, app.Config("https://127.0.0.1/api/v2.0", SECRET, "nas", "tailscale"))
                path.write_text(json.dumps({"api_key": SECRET, "hostname": "custom",
                    "api_base_url": "https://nas:444/proxy/api/v2.0/", "verify_ssl": True,
                    "tailscale_container_name_pattern": "custom", "certificate_name_prefix": "prefix"}))
                loaded = app.load_config(path)
                self.assertTrue(loaded.verify_ssl)
                self.assertEqual(loaded.certificate_name_prefix, "prefix")
                self.assertEqual(loaded.tailscale_container_name_pattern, "custom")
                self.assertEqual(loaded.api_base_url, "https://nas:444/proxy/api/v2.0")

    def test_discovery_from_script_directory_and_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            with patch.object(app, "__file__", str(folder / "renew_update_cert.py")), patch.dict(os.environ, {}, clear=True):
                for suffix in [".json", ".yml", ".yaml"]:
                    path = folder / (".config" + suffix)
                    path.touch()
                    self.assertEqual(app.discover_config_path(), path)
                custom = folder / "custom.json"
                custom.touch()
                with patch.dict(os.environ, {"TRUENAS_CERT_CONFIG": str(custom.with_suffix(".yaml"))}):
                    self.assertEqual(app.discover_config_path(), custom)

    def test_invalid_config(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.yaml"
            path.write_text("hostname: nas")
            with self.assertRaisesRegex(ValueError, "api_key"):
                app.load_config(path)


class TransportTests(unittest.TestCase):
    def test_authenticated_session_notifications_and_matching(self):
        with MockTrueNAS() as server:
            server.notices = True
            with app.TrueNASClient(config(server.url)) as client:
                self.assertEqual(client.call("system.state"), "READY")
                self.assertEqual(client.call("system.state"), "READY")
            self.assertEqual(server.methods().count("auth.login_with_api_key"), 1)
            self.assertEqual(server.paths, ["/proxy/api/current"])
            self.assertIsNone(client._socket)

    def test_authentication_failure_closes_connection(self):
        with MockTrueNAS() as server:
            server.reject_auth = True
            client = app.TrueNASClient(config(server.url))
            with self.assertRaisesRegex(app.APIError, "authentication"):
                client.connect()
            self.assertIsNone(client._socket)
            self.assertEqual(server.methods(), ["auth.login_with_api_key"])

    def test_errors_and_invalid_json_do_not_expose_secrets(self):
        for mode in ["fail", "malformed"]:
            with self.subTest(mode=mode), MockTrueNAS() as server:
                setattr(server, mode, "system.state")
                with app.TrueNASClient(config(server.url)) as client:
                    with self.assertRaises(app.APIError) as caught:
                        client.call("system.state")
                self.assertNotIn(SECRET, str(caught.exception))
                self.assertNotIn(PRIVATE_KEY, str(caught.exception))

    def test_notifications_cannot_extend_deadline(self):
        with MockTrueNAS() as server:
            server.stall = "system.state"
            with app.TrueNASClient(config(server.url)) as client:
                start = time.monotonic()
                with self.assertRaisesRegex(app.TransportError, "timed out"):
                    client.call("system.state", timeout=0.05)
                self.assertLess(time.monotonic() - start, 0.5)
                self.assertIsNone(client._socket)

    def test_ambiguous_mutation_is_not_replayed(self):
        with MockTrueNAS() as server:
            server.drop = "system.general.update"
            with app.TrueNASClient(config(server.url)) as client:
                with self.assertRaisesRegex(app.TransportError, "not retried"):
                    client.call("system.general.update", {"ui_certificate": 7})
            self.assertEqual(server.methods().count("system.general.update"), 1)
            self.assertEqual(server.connections, 1)

    def test_legacy_jobs_wait_and_propagate_terminal_failure(self):
        for state in ["SUCCESS", "FAILED", "ABORTED", "RUNNING"]:
            with self.subTest(state=state), MockTrueNAS(legacy=True) as server:
                server.job_state = state
                with app.TrueNASClient(config(server.url)) as client:
                    payload = {"name": "test", "create_type": "CERTIFICATE_CREATE_IMPORTED", "privatekey": PRIVATE_KEY}
                    if state == "SUCCESS":
                        result = client.call_job("certificate.create", payload)
                        self.assertEqual(result["id"], 7)
                    else:
                        with self.assertRaises(app.APIError) as caught:
                            client.call_job("certificate.create", payload, timeout=0.05)
                        self.assertNotIn(PRIVATE_KEY, str(caught.exception))
                self.assertEqual(server.methods().count("certificate.create"), 1)
                self.assertIn("core.get_jobs", server.methods())

    def test_ssl_options_preserve_verification_setting(self):
        for verify in [False, True]:
            sock = Mock()
            sock.recv.return_value = '{"jsonrpc":"2.0","id":1,"result":true}'
            with patch.object(app.websocket, "create_connection", return_value=sock) as connect:
                with app.TrueNASClient(config(verify=verify)):
                    pass
                options = connect.call_args.kwargs["sslopt"]
                self.assertEqual(options["check_hostname"], verify)
                self.assertEqual(options["cert_reqs"], ssl.CERT_REQUIRED if verify else ssl.CERT_NONE)


class WorkflowTests(unittest.TestCase):
    def run_workflow(self, server, **kwargs):
        docker_client = Mock()
        container = Mock()
        container.name = "tailscale-app"
        container.image.tags = ["ghcr.io/tailscale/tailscale:latest"]
        container.exec_run.side_effect = [(0, b""), (0, b"generated certificate"), (0, PRIVATE_KEY.encode()), (0, b"")]
        docker_client.containers.list.return_value = [container]
        with patch.object(app.docker, "from_env", return_value=docker_client), \
                patch.object(app, "RESTART_GRACE_SECONDS", 0), \
                patch.object(app, "RESTART_TIMEOUT", 0.15), \
                patch.object(app, "RECONNECT_INTERVAL", 0.01):
            app.renew_certificate(config(server.url, **kwargs))
        docker_client.close.assert_called_once()
        self.assertIn("rm -rf", container.exec_run.call_args.args[0][-1])

    def test_new_import_both_job_styles_and_exact_cleanup_target(self):
        for legacy in [False, True]:
            with self.subTest(legacy=legacy), MockTrueNAS(legacy=legacy) as server:
                self.run_workflow(server)
                methods = server.methods()
                self.assertEqual(methods.count("auth.login_with_api_key"), 2)
                self.assertEqual(methods.count("certificate.create"), 1)
                self.assertLess(methods.index("certificate.create"), methods.index("system.general.update"))
                self.assertLess(methods.index("system.general.ui_restart"), methods.index("certificate.delete"))
                deletes = [call for call in server.calls if call[1] == "certificate.delete"]
                self.assertEqual(deletes, [(2, "certificate.delete", [9, False])])
                self.assertTrue(all(path == "/proxy/api/current" for path in server.paths))

    def test_reuses_same_name_without_importing(self):
        with MockTrueNAS(existing=True) as server:
            self.run_workflow(server)
            self.assertNotIn("certificate.create", server.methods())
            query = next(params for _, method, params in server.calls if method == "certificate.query")
            self.assertEqual(query[0][0][2], "tailscale-ui-" + datetime.datetime.now().strftime("%Y%m%d"))

    def test_same_or_missing_previous_certificate_is_not_deleted(self):
        for previous in [7, None]:
            with self.subTest(previous=previous), MockTrueNAS(existing=True) as server:
                server.active_id = previous
                self.run_workflow(server)
                self.assertNotIn("certificate.delete", server.methods())

    def test_failure_before_restart_never_deletes_old_certificate(self):
        for method in ["auth.login_with_api_key", "certificate.create", "system.general.update", "system.general.ui_restart"]:
            with self.subTest(method=method), MockTrueNAS() as server:
                server.fail = method
                with self.assertRaises(app.APIError):
                    self.run_workflow(server)
                self.assertNotIn("certificate.delete", server.methods())
                if method == "certificate.create":
                    self.assertNotIn("system.general.update", server.methods())

    def test_restart_without_acknowledgement_retains_old_certificate(self):
        with MockTrueNAS() as server:
            server.drop = "system.general.ui_restart"
            with self.assertRaises(app.TransportError):
                self.run_workflow(server)
            self.assertEqual(server.methods().count("system.general.ui_restart"), 1)
            self.assertNotIn("certificate.delete", server.methods())

    def test_failed_readback_retains_old_certificate(self):
        with MockTrueNAS() as server:
            server.ignore_update = True
            with self.assertRaisesRegex(app.APIError, "retained"):
                self.run_workflow(server)
            self.assertNotIn("certificate.delete", server.methods())

    def test_transient_restart_disconnect_reconnects_without_replaying_mutations(self):
        with MockTrueNAS() as server:
            server.drop_first_reconnect = True
            self.run_workflow(server)
            self.assertEqual(server.connections, 3)
            for method in ["certificate.create", "system.general.update", "system.general.ui_restart", "certificate.delete"]:
                self.assertEqual(server.methods().count(method), 1)

    def test_delete_failure_is_nonfatal_and_secret_free(self):
        with MockTrueNAS() as server:
            server.fail = "certificate.delete"
            with self.assertLogs(app.logger, level="INFO") as logs:
                self.run_workflow(server)
            output = "\n".join(logs.output)
            self.assertIn("Skipping delete", output)
            self.assertIn("Done.", output)
            self.assertNotIn(SECRET, output)
            self.assertNotIn(PRIVATE_KEY, output)


class TLSTests(unittest.TestCase):
    run_workflow = WorkflowTests.run_workflow

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=1))
                .add_extension(x509.SubjectAlternativeName([
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")), x509.DNSName("localhost")]), critical=False)
                .sign(key, hashes.SHA256()))
        cls.pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        cls.der = cert.public_bytes(serialization.Encoding.DER)
        cls.cert_path = Path(cls.temp.name) / "cert.pem"
        cls.cert_path.write_text(cls.pem)
        key_path = Path(cls.temp.name) / "key.pem"
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        cls.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.tls.load_cert_chain(cls.cert_path, key_path)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_wss_unverified_and_trusted_verified_connections(self):
        with MockTrueNAS(tls=self.tls, pem=self.pem) as server:
            for verify in [False, True]:
                with self.subTest(verify=verify), patch.dict(os.environ, {"WEBSOCKET_CLIENT_CA_BUNDLE": str(self.cert_path)}):
                    with app.TrueNASClient(config(server.url, verify)) as client:
                        self.assertEqual(client.peer_certificate(), self.der)

    def test_untrusted_tls_fails_before_authentication(self):
        with MockTrueNAS(tls=self.tls) as server, patch.dict(os.environ, {"WEBSOCKET_CLIENT_CA_BUNDLE": ""}):
            with self.assertRaises(app.TransportError):
                app.TrueNASClient(config(server.url, True)).connect()
            self.assertEqual(server.calls, [])

    def test_tls_workflow_uses_reused_certificate_leaf_not_new_generated_pem(self):
        with MockTrueNAS(tls=self.tls, pem=self.pem + self.pem, existing=True) as server:
            self.run_workflow(server)
            self.assertIn("certificate.delete", server.methods())

    def test_tls_mismatch_prevents_cleanup(self):
        with MockTrueNAS(tls=self.tls, pem="-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----", existing=True) as server:
            with self.assertRaisesRegex(app.APIError, "retained"):
                self.run_workflow(server)
            self.assertNotIn("certificate.delete", server.methods())


class EntryPointAndDockerTests(unittest.TestCase):
    def test_deprecated_entry_point_delegates(self):
        with patch.object(app, "main") as main, warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            runpy.run_path(str(ROOT / "update_cert.py"), run_name="__main__")
            main.assert_called_once_with()

    def test_main_preserves_config_and_returns_failure_without_secrets(self):
        with patch.object(app, "discover_config_path", return_value=Path("custom.json")), \
                patch.object(app, "load_config", return_value=config()) as load, \
                patch.object(app, "renew_certificate") as renew:
            app.main()
            load.assert_called_once_with(Path("custom.json"))
            renew.assert_called_once_with(config())
            renew.side_effect = ValueError(SECRET + PRIVATE_KEY)
            with self.assertLogs(app.logger, level="ERROR") as logs, self.assertRaises(SystemExit) as caught:
                app.main()
            self.assertEqual(caught.exception.code, 1)
            self.assertNotIn(SECRET, str(logs.output))
            self.assertNotIn(PRIVATE_KEY, str(logs.output))

    def test_primary_entry_point_runs_with_existing_config(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.yaml"
            path.write_text(json.dumps({"api_key": SECRET, "hostname": "nas"}))
            sock = Mock()
            sock.recv.return_value = '{"jsonrpc":"2.0","id":1,"result":false}'
            with patch.dict(os.environ, {"TRUENAS_CERT_CONFIG": str(path)}), \
                    patch.object(app.websocket, "create_connection", return_value=sock), \
                    patch.object(app.logging, "basicConfig"), \
                    self.assertLogs("__main__", level="ERROR"), self.assertRaises(SystemExit) as caught:
                runpy.run_path(str(ROOT / "renew_update_cert.py"), run_name="__main__")
            self.assertEqual(caught.exception.code, 1)
            request = json.loads(sock.send.call_args.args[0])
            self.assertEqual(request["method"], "auth.login_with_api_key")
            self.assertEqual(request["params"], [SECRET])

    def test_container_discovery_and_fallback_unchanged(self):
        client = Mock()
        first, fallback = Mock(), Mock()
        first.name, first.image.tags = "My-Tailscale", ["tailscale/custom"]
        fallback.name, fallback.image.tags = "arbitrary", ["ghcr.io/tailscale/tailscale:latest"]
        client.containers.list.return_value = [first, fallback]
        self.assertIs(app.find_tailscale_container(client, "my-tail"), first)
        self.assertIs(app.find_tailscale_container(client, "no-match"), fallback)
        client.containers.list.return_value = []
        with self.assertRaisesRegex(RuntimeError, "Could not find"):
            app.find_tailscale_container(client, "tailscale")

    def test_tailscale_command_and_cleanup_on_each_failure(self):
        for failure in [None, 0, 1, 2]:
            container = Mock()
            results = [(0, b""), (0, b"certificate"), (0, PRIVATE_KEY.encode())]
            if failure is not None:
                results[failure] = (1, (SECRET + PRIVATE_KEY).encode())
                if failure == 0:
                    results = results[:1]
            container.exec_run.side_effect = results + [(0, b"")]
            if failure is None:
                self.assertEqual(app.generate_tailscale_cert(container, "nas.ts.net"), ("certificate", PRIVATE_KEY))
            else:
                with self.assertRaises(app.APIError) as caught:
                    app.generate_tailscale_cert(container, "nas.ts.net")
                self.assertNotIn(PRIVATE_KEY, str(caught.exception))
            command = container.exec_run.call_args_list[0].args[0][-1]
            self.assertIn("tailscale cert --cert-file", command)
            self.assertIn("--key-file", command)
            self.assertIn("'nas.ts.net'", command)
            self.assertIn("rm -rf", container.exec_run.call_args.args[0][-1])


if __name__ == "__main__":
    unittest.main()
