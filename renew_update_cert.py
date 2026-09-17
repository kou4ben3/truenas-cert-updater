#!/usr/bin/env python3

from __future__ import annotations
import re
import datetime
import os
import pathlib
import ssl
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import docker
import websocket
import yaml
import json
import logging

logger = logging.getLogger(__name__)

CALL_TIMEOUT = 60.0
JOB_TIMEOUT = 300.0
RESTART_TIMEOUT = 60.0
RESTART_DELAY = 3
RESTART_GRACE_SECONDS = RESTART_DELAY + 1
RECONNECT_INTERVAL = 3.0


@dataclass(frozen=True)
class Config:
    api_base_url: str
    api_key: str
    hostname: str
    tailscale_container_name_pattern: str
    certificate_name_prefix: str = "tailscale-ui"
    verify_ssl: bool = False


def load_config(config_path: str | Path) -> Config:
    config_path = Path(config_path)

    with open(config_path, "rt", encoding="utf-8") as f:
        if config_path.suffix.lower() == ".json":
            raw = json.load(f) or {}
        elif config_path.suffix.lower() in {".yaml", ".yml"}:
            raw = yaml.safe_load(f) or {}
        else:
            raise ValueError("Config file must be .json, .yaml, or .yml")

    required = [
        "api_key",
        "hostname",
    ]
    missing = [key for key in required if not raw.get(key)]
    if missing:
        raise ValueError(f"Missing required config keys: {', '.join(missing)}")

    return Config(
        api_base_url=raw.get("api_base_url", "https://127.0.0.1/api/v2.0").rstrip("/"),
        api_key=raw["api_key"],
        hostname=raw["hostname"],
        tailscale_container_name_pattern=raw.get("tailscale_container_name_pattern", "tailscale"),
        certificate_name_prefix=raw.get("certificate_name_prefix", "tailscale-ui"),
        verify_ssl=bool(raw.get("verify_ssl", False)),
    )


class APIError(RuntimeError):
    """Safe-to-log failure; never includes server payloads or credentials."""


class TransportError(APIError):
    pass


def websocket_url(api_base_url: str) -> str:
    """Accept existing REST configuration without making any REST requests."""
    try:
        parsed = urlsplit(api_base_url)
        schemes = {"http": "ws", "https": "wss", "ws": "ws", "wss": "wss"}
        if (parsed.scheme not in schemes or not parsed.hostname or parsed.username
                or parsed.password or parsed.query or parsed.fragment):
            raise ValueError
        # Validate the port without reconstructing netloc (which preserves IPv6).
        parsed.port
        path = parsed.path.rstrip("/")
        if path.endswith("/websocket"):
            raise ValueError
        if path.endswith("/api/v2.0"):
            path = path[:-len("/api/v2.0")] + "/api/current"
        elif not re.search(r"/api/(current|v\d+\.\d+(?:\.\d+)*)$", path):
            path += "/api/current"
        return urlunsplit((schemes[parsed.scheme], parsed.netloc, path, "", ""))
    except (ValueError, TypeError):
        raise APIError("Invalid api_base_url; use a TrueNAS HTTP(S) base URL or JSON-RPC WebSocket URL.") from None


class TrueNASClient:
    """One synchronous, authenticated JSON-RPC session; never replays calls."""

    def __init__(self, config: Config):
        self.url = websocket_url(config.api_base_url)
        self._api_key = config.api_key
        self._verify_ssl = config.verify_ssl
        self._socket = None
        self._request_id = 0

    def connect(self, timeout: float = CALL_TIMEOUT) -> TrueNASClient:
        self.close()
        deadline = time.monotonic() + timeout
        sslopt = {"cert_reqs": ssl.CERT_REQUIRED, "check_hostname": True}
        if not self._verify_ssl:
            sslopt = {"cert_reqs": ssl.CERT_NONE, "check_hostname": False}
        try:
            self._socket = websocket.create_connection(
                self.url, timeout=timeout, sslopt=sslopt, suppress_origin=True,
                redirect_limit=0,
            )
        except Exception:
            raise TransportError("WebSocket connection failed; check the address, TLS settings, and TrueNAS 25.04+ support.") from None
        try:
            if self.call("auth.login_with_api_key", self._api_key,
                         timeout=max(0, deadline - time.monotonic())) is not True:
                raise APIError("TrueNAS API key authentication failed.")
        except Exception:
            self.close()
            raise
        return self

    def close(self) -> None:
        sock, self._socket = self._socket, None
        if sock is not None:
            try:
                sock.close(timeout=0)
            except Exception:
                pass
            finally:
                # Receiving a server close frame marks websocket-client as
                # disconnected, so close() alone may leave its TCP socket open.
                sock.shutdown()

    def __enter__(self) -> TrueNASClient:
        return self.connect()

    def __exit__(self, *args: Any) -> None:
        self.close()

    def call(self, method: str, *params: Any, timeout: float = CALL_TIMEOUT) -> Any:
        if self._socket is None:
            raise TransportError("WebSocket session is not connected.")
        deadline = time.monotonic() + timeout
        self._request_id += 1
        request_id = self._request_id
        try:
            if timeout <= 0:
                raise TimeoutError
            self._socket.settimeout(timeout)
            self._socket.send(json.dumps({
                "jsonrpc": "2.0", "id": request_id, "method": method, "params": list(params),
            }))
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError
                self._socket.settimeout(remaining)
                raw = self._socket.recv()
                if not raw:
                    raise ConnectionError
                response = json.loads(raw)
                if not isinstance(response, dict) or response.get("jsonrpc") != "2.0":
                    raise ValueError
                # Notifications and unrelated responses do not reset the deadline.
                if "id" not in response or response["id"] != request_id:
                    continue
                if "error" in response:
                    error = response["error"]
                    code = error.get("code") if isinstance(error, dict) else None
                    code_text = f" (code {code})" if type(code) is int else ""
                    raise APIError(f"TrueNAS {method} failed{code_text}; check the server logs for details.")
                if "result" not in response:
                    raise ValueError
                return response["result"]
        except APIError:
            raise
        except (TimeoutError, websocket.WebSocketTimeoutException):
            self.close()
            raise TransportError(f"TrueNAS {method} timed out; the request was not retried.") from None
        except (ValueError, TypeError):
            self.close()
            raise APIError(f"Invalid JSON-RPC response to {method}.") from None
        except Exception:
            self.close()
            raise TransportError(f"Connection lost during {method}; the request was not retried.") from None

    def call_job(self, method: str, *params: Any, timeout: float = JOB_TIMEOUT) -> Any:
        deadline = time.monotonic() + timeout
        result = self.call(method, *params, timeout=timeout)
        # New-style JSON-RPC jobs return the completed result. Older servers may
        # return a job ID. bool is deliberately excluded (certificate.delete).
        if type(result) is not int:
            return result
        job_id = result
        while time.monotonic() < deadline:
            jobs = self.call("core.get_jobs", [["id", "=", job_id]],
                             timeout=min(CALL_TIMEOUT, deadline - time.monotonic()))
            if (not isinstance(jobs, list) or len(jobs) != 1
                    or not isinstance(jobs[0], dict) or jobs[0].get("id") != job_id):
                raise APIError(f"Unable to find the job for {method}; the request was not retried.")
            job = jobs[0]
            if job.get("state") == "SUCCESS":
                return job.get("result")
            if job.get("state") in {"FAILED", "ABORTED"}:
                raise APIError(f"TrueNAS {method} job failed or was aborted; check the server logs.")
            time.sleep(min(1.0, max(0, deadline - time.monotonic())))
        raise APIError(f"TrueNAS {method} job timed out; the request was not retried.")

    def peer_certificate(self) -> bytes:
        try:
            return self._socket.sock.getpeercert(binary_form=True)
        except Exception:
            raise APIError("Unable to verify the certificate served by the restarted UI.") from None


def get_ui_certificate_id(client: TrueNASClient, *, timeout: float = CALL_TIMEOUT) -> int | None:
    settings = client.call("system.general.config", timeout=timeout)
    if not isinstance(settings, dict) or "ui_certificate" not in settings:
        raise APIError("TrueNAS returned invalid UI certificate settings.")
    certificate = settings["ui_certificate"]
    if certificate is None:
        return None
    cert_id = certificate.get("id") if isinstance(certificate, dict) else certificate
    if type(cert_id) is not int or cert_id <= 0:
        raise APIError("TrueNAS returned an invalid UI certificate ID.")
    return cert_id


def find_tailscale_container(client: docker.DockerClient, name_pattern: str) -> docker.models.containers.Container:
    containers = client.containers.list(all=True)
    for container in containers:
        image = container.image.tags[0] if container.image.tags else ""
        name = container.name or ""

        if "tailscale" in image.lower() and re.search(name_pattern, name, re.IGNORECASE):
            return container

        if "ghcr.io/tailscale/tailscale" in image.lower():
            return container

    raise RuntimeError(
        "Could not find a Tailscale container. "
        "Check tailscale_container_name_pattern in config."
    )


def generate_tailscale_cert(
    container: docker.models.containers.Container,
    hostname: str,
) -> tuple[str, str]:
    """
    Create the certificate inside the container, then read the generated files
    back into Python strings. Always clean up the temp directory afterward.
    """
    tmp_dir = f"/tmp/tailscale-cert-{os.getpid()}"
    cert_path = f"{tmp_dir}/{hostname}.crt"
    key_path = f"{tmp_dir}/{hostname}.key"

    try:
        create_command = [
            "sh",
            "-lc",
            (
                "set -e; "
                f"mkdir -p '{tmp_dir}'; "
                f"cd '{tmp_dir}'; "
                f"tailscale cert --cert-file '{cert_path}' "
                f"--key-file '{key_path}' '{hostname}'"
            ),
        ]
        exit_code, _ = container.exec_run(create_command, stdout=True, stderr=True)

        if exit_code != 0:
            raise APIError("tailscale cert failed; check the Tailscale container logs.")

        read_cert_command = ["sh", "-lc", f"cat '{cert_path}'"]
        read_key_command = ["sh", "-lc", f"cat '{key_path}'"]

        cert_exit_code, cert_output = container.exec_run(read_cert_command, stdout=True, stderr=True)
        key_exit_code, key_output = container.exec_run(read_key_command, stdout=True, stderr=True)

        cert_text = cert_output.decode("utf-8", errors="replace") if isinstance(cert_output, (bytes, bytearray)) else str(cert_output)
        key_text = key_output.decode("utf-8", errors="replace") if isinstance(key_output, (bytes, bytearray)) else str(key_output)

        if cert_exit_code != 0:
            raise APIError("Failed to read the generated certificate file.")
        if key_exit_code != 0:
            raise APIError("Failed to read the generated private key file.")

        return cert_text, key_text
    finally:
        cleanup_command = ["sh", "-lc", f"rm -rf '{tmp_dir}'"]
        container.exec_run(cleanup_command, stdout=True, stderr=True)


def get_certificate_by_name(
    client: TrueNASClient,
    cert_name: str,
) -> dict[str, Any] | None:
    certificates = client.call("certificate.query", [["name", "=", cert_name]])
    if not isinstance(certificates, list) or any(not isinstance(cert, dict) for cert in certificates):
        raise APIError("TrueNAS returned an invalid certificate list.")
    return next((cert for cert in certificates if cert.get("name") == cert_name), None)


def create_certificate(
    client: TrueNASClient,
    cert_name: str,
    certificate: str,
    private_key: str,
) -> dict[str, Any]:
    payload = {
        "name": cert_name,
        "privatekey": private_key,
        "certificate": certificate,
        "create_type": "CERTIFICATE_CREATE_IMPORTED",
    }
    result = client.call_job("certificate.create", payload)
    if not isinstance(result, dict):
        raise APIError("TrueNAS certificate import did not return a certificate record.")
    return result


def certificate_der(certificate: str) -> bytes:
    """Compare only the leaf, even when TrueNAS returns a full PEM chain."""
    try:
        leaf = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", certificate, re.DOTALL)
        if leaf is None:
            raise ValueError
        return ssl.PEM_cert_to_DER_cert(leaf.group())
    except (ValueError, TypeError):
        raise APIError("The selected certificate does not contain a valid PEM certificate.") from None


def reconnect_after_restart(
    config: Config,
    cert_id: int,
    expected_der: bytes | None,
) -> TrueNASClient:
    deadline = time.monotonic() + RESTART_TIMEOUT
    time.sleep(min(RESTART_GRACE_SECONDS, RESTART_TIMEOUT))
    while time.monotonic() < deadline:
        client = TrueNASClient(config)
        try:
            client.connect(timeout=min(10.0, deadline - time.monotonic()))
            active_id = get_ui_certificate_id(client, timeout=max(0, deadline - time.monotonic()))
            if active_id == cert_id and (expected_der is None or client.peer_certificate() == expected_der):
                return client
        except TransportError:
            # Only reconnection and read-only verification are retried.
            pass
        except Exception:
            client.close()
            raise
        client.close()
        time.sleep(min(RECONNECT_INTERVAL, max(0, deadline - time.monotonic())))
    raise APIError("UI restart verification timed out; the previous certificate was retained.")


def discover_config_path() -> Path:
    config_path = os.environ.get(
        "TRUENAS_CERT_CONFIG",
        pathlib.Path(__file__).parent / ".config.yaml"
    )
    config_path = Path(config_path)

    if not config_path.exists():
        yaml_path = config_path.with_suffix(".yaml")
        yml_path = config_path.with_suffix(".yml")
        json_path = config_path.with_suffix(".json")

        if yaml_path.exists():
            config_path = yaml_path
        elif yml_path.exists():
            config_path = yml_path
        elif json_path.exists():
            config_path = json_path

    return config_path


def renew_certificate(config: Config) -> None:
    cert_name = f"{config.certificate_name_prefix}-{datetime.datetime.now().strftime('%Y%m%d')}"
    logger.info("Checking TrueNAS WebSocket connectivity...")
    with TrueNASClient(config) as client:
        client.call("system.state")

        docker_client = docker.from_env()
        try:
            container = find_tailscale_container(docker_client, config.tailscale_container_name_pattern)
            logger.info("Using Tailscale container: %s", container.name)
            logger.info("Generating certificate via tailscale cert...")
            certificate, private_key = generate_tailscale_cert(container, config.hostname)
        finally:
            docker_client.close()

        previous_ui_cert_id = get_ui_certificate_id(client)
        cert_record = get_certificate_by_name(client, cert_name)
        if cert_record is not None:
            logger.info("Reusing existing certificate: %s", cert_name)
        else:
            logger.info("Creating certificate in TrueNAS: %s", cert_name)
            cert_record = create_certificate(client, cert_name, certificate, private_key)

        cert_id = cert_record.get("id")
        if type(cert_id) is not int or cert_id <= 0:
            raise APIError("TrueNAS returned an invalid certificate ID after import or lookup.")
        expected_der = None
        if client.url.startswith("wss://"):
            expected_der = certificate_der(cert_record.get("certificate"))

        logger.info("Setting UI certificate to id=%s", cert_id)
        client.call("system.general.update", {"ui_certificate": cert_id})
        logger.info("Restarting TrueNAS UI...")
        client.call("system.general.ui_restart", RESTART_DELAY)

    client = reconnect_after_restart(config, cert_id, expected_der)
    try:
        if previous_ui_cert_id and previous_ui_cert_id != cert_id:
            try:
                logger.info("Deleting previous UI certificate id=%s", previous_ui_cert_id)
                if client.call_job("certificate.delete", previous_ui_cert_id, False) is not True:
                    raise APIError("TrueNAS did not confirm certificate deletion.")
            except APIError as exc:
                logger.info("Skipping delete for previous UI cert id=%s: %s", previous_ui_cert_id, exc)
        else:
            logger.info("No previous UI certificate to delete, or it is the same as the new one.")
    finally:
        client.close()
    logger.info("Done.")


def main() -> None:
    try:
        renew_certificate(load_config(discover_config_path()))
    except APIError as exc:
        logger.error("%s", exc)
        raise SystemExit(1) from None
    except Exception:
        # YAML parsing and Docker exceptions can contain configuration or key
        # material. Do not print arbitrary exception payloads or tracebacks.
        logger.error("Certificate renewal failed; check the configuration, Docker, and Tailscale container.")
        raise SystemExit(1) from None


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
