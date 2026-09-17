# TrueNAS Certificate AutoUpdate

This repo contains scripts that automate TrueNAS UI certificate updates using
the JSON-RPC 2.0 WebSocket API. It does not change application certificate assignments.

`renew_update_cert.py` automates the process of generating a new Tailscale certificate and applying it to the TrueNAS UI.

## What it does

The script will:

1. Read configuration values from a YAML or JSON file.
2. Find the running Tailscale container on the host.
3. Run `tailscale cert` inside that container to generate a fresh certificate and private key.
4. Import the new certificate into TrueNAS.
5. Set the new certificate as the TrueNAS UI certificate.
6. Restart the TrueNAS UI to apply the change.
7. Reconnect, verify the selected certificate (and the served certificate over TLS),
   then delete the previously active UI certificate.

## Requirements

- TrueNAS 25.04 or later with the JSON-RPC API and `auth.login_with_api_key` support
- Python 3.12+ (included in TrueNas SCALE)
- Python packages:
  - `websocket-client` (included with the TrueNAS API client; Python import: `websocket`)
  - `PyYAML` (included in TrueNas SCALE)
  - `docker` (included in TrueNas SCALE)
- A running Tailscale app connected to your tailnet
  - expected to be a running docker container

## Upgrading an existing installation

Replace `renew_update_cert.py` with this version. Keep your existing configuration,
API key, and cron command unchanged. The `update_cert.py` compatibility entry point
still works. No package installation is needed on a standard TrueNAS installation.

The existing default `https://127.0.0.1/api/v2.0` is automatically translated to
`wss://127.0.0.1/api/current`. Custom hosts, ports, and reverse-proxy path prefixes
are preserved. HTTP URLs become `ws://` URLs; explicit JSON-RPC `ws://` and `wss://`
URLs are also accepted. No REST authentication or REST fallback is used.

TrueNAS 24.10 and earlier are no longer supported by this version.

## Configuration

Create a YAML config file, for example `.config.yaml`, with the following values:

```yaml 
api_key: "<API_KEY>" 
hostname: "hostname.tailnet-name.ts.net" 
# optional parameters
api_base_url: "https://127.0.0.1/api/v2.0" 
tailscale_container_name_pattern: "tailscale" 
certificate_name_prefix: "tailscale-ui" 
verify_ssl: false
```

### Configuration fields

- `api_key`
  - TrueNAS API key used for authentication.
- `hostname`
  - The Tailscale hostname to pass to `tailscale cert`.
- `api_base_url` (optional)
  - Existing TrueNAS HTTP(S) API base URL or a JSON-RPC WebSocket endpoint.
  - Default: `https://127.0.0.1/api/v2.0`
  - Translated to the WebSocket endpoint automatically; no config edit required.
- `tailscale_container_name_pattern` (optional)
  - Pattern used to locate the Tailscale container.
  - Default: `tailscale`
- `certificate_name_prefix` (optional)
  - Prefix used when naming the imported certificate.
  - Default: `tailscale-ui`
- `verify_ssl` (optional)
  - Whether to verify TLS when calling the TrueNAS API.
  - Default: `false`

## Usage

1. `git clone git@github.com:mcao2/truenas-cert-updater.git`
2. Create a config file `.config.yaml` as described above.
3. Create a cronjob that runs the script periodically.
    - Select the `root` user for the cronjob.
    - Set the cronjob to run more often than every 90 days (the default expiry for the certificate). It can safely be run as often as you want. 
    - Set the command to:
    ```bash
    python3 /path/to/renew_update_cert.py
    ```
4. (Optional) Test the script by running it directly.

By default, configuration is read from `.config.yaml` beside the script. Set
`TRUENAS_CERT_CONFIG` to use another path. If that path is missing, the script tries
the same filename with `.yaml`, `.yml`, then `.json`, as in the previous version.

## Behavior details

- The script searches for a container whose image or name matches the Tailscale pattern.
- It generates the certificate using:
  - `tailscale cert --cert-file ... --key-file ... <hostname>`
- Certificates are named `<certificate_name_prefix>-YYYYMMDD` using the local date.
  If that name already exists in TrueNAS, the script reuses that certificate entry.
- The script authenticates once per WebSocket connection. Certificate imports and
  deletions wait for job completion, with a 300-second deadline. Ordinary API calls
  have a 60-second deadline.
- The old UI certificate is deleted only after:
  1. the new certificate has been set,
  2. the TrueNAS UI restart has been acknowledged, and
  3. a fresh connection confirms the selected certificate and, for TLS connections,
     the certificate actually served by that endpoint.
- Restart recovery is bounded to 60 seconds. Failed imports, activation, or restart
  verification stop the script with a nonzero exit status and retain the old certificate
  record. This does not automatically roll back an already-applied UI setting.
- Mutating calls are never replayed after an ambiguous disconnect. Old-certificate
  deletion failures are logged but remain nonfatal; deletion is never forced.
- Errors omit server payloads, API keys, and private keys. Consult the TrueNAS logs
  for server-side failure details.

## Notes

- The script assumes TrueNAS is reachable on localhost unless you override `api_base_url`.
- SSL verification is disabled by default for convenience in local TrueNAS setups.
- Make sure the Tailscale container can write certificate files to the temporary directory used by the script.
- When using a TLS-terminating reverse proxy, its served certificate must match the
  selected TrueNAS UI certificate for restart verification to succeed. Otherwise,
  the script retains the old certificate and reports verification failure.
- API changes in future TrueNAS releases may require updates. In particular,
  TrueNAS documents removal of `auth.login_with_api_key` in version 27; this script
  preserves existing key-only configuration using that method.

## Offline tests

On a development machine:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m unittest discover -s tests -v
```

On Windows, use `.venv\Scripts\python.exe` instead of `.venv/bin/python`.
These tests use local WebSocket/TLS servers and mocked Docker execution. They do
not renew a real certificate or contact TrueNAS.

For live acceptance, run the existing cron command on TrueNAS and confirm the
new UI certificate is served, the prior certificate is cleaned up where permitted,
and the run produces no new REST authentication events. The existing alert reports
a rolling 24-hour window, so historical events can remain visible after migration.
Passing offline tests alone does not establish live acceptance.

## References

- [TrueNAS JSON-RPC API](https://api.truenas.com/v25.10/jsonrpc.html)
- [TrueNAS job semantics](https://api.truenas.com/v25.10/jobs.html)
- [TrueNAS WebSocket client](https://github.com/truenas/api_client)
- [API-key authentication compatibility](https://api.truenas.com/v25.10/api_methods_auth.login_with_api_key.html)
