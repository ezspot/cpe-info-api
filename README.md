# device-api

Production-oriented Go 1.26+ service that collects diagnostics from **CPEs over SSH** and from **switches over SNMP**.

- CPE (SSH) model command matrix: [docs/device-command-matrix.md](docs/device-command-matrix.md)
- Switch (SNMP) polling guide: [docs/snmp-switch-polling.md](docs/snmp-switch-polling.md)

The OpenAPI 3.1 contract is generated from swaggo annotations into [internal/ports/docs/openapi.yaml](internal/ports/docs/openapi.yaml) and served at `GET /openapi.yaml` (`GET /docs` renders Swagger UI).

## Endpoints

Operational:

- `GET /healthz`, `GET /readyz`
- `GET /openapi.yaml`, `GET /docs` (Swagger UI)
- `GET /metrics` (Prometheus scrape endpoint)

CPE (SSH):

- `GET /v1/cpe/collect?ip=192.168.1.1&port=22&model=FO1&raw=1&includePsk=0`
- `POST /v1/cpe/collect` (JSON body)
- `POST /v1/cpe/actions` (JSON body)

Switch (SNMP):

- `GET /v1/switch/ports?host=10.160.25.72&port=6/2&macs=true`
- `GET /v1/switch/ports?portGroup=TAFAALLERSTADAR2S003P20`
- `POST /v1/switch/ports` (JSON body)

`POST /v1/cpe/collect`:

```json
{ "ip": "192.168.1.1", "port": 22, "model": "FO1" }
```

`POST /v1/cpe/actions`:

```json
{ "ip": "192.168.1.1", "port": 22, "model": "EX5401", "action": "reboot", "dryRun": true }
```

`POST /v1/switch/ports`:

```json
{ "portGroup": "TAFAALLERSTADAR2S003P20" }
```

## Model-based SSH behavior

- `VANTIVA` family (`FO1`, `F1X`, `EWA`):
  - key: `cpe-ssh-keys/VANTIVA_TAFJORD`
  - user: `VANTIVA_CPE_CLI_USER`
  - password: `VANTIVA_CPE_CLI_PASSWORD`
  - OpenWRT-based profile
  - if key parsing fails (for example passphrase-protected key), password auth is used
- ZyXEL family (`VMG8825` / `VMG`, `EX5401`, `EX5601`, `AX7501` / `AX`, `FMG`, `EMG-P2812` / `EMG`):
  - always user `root`
  - always key-only from `CPE_SSH_KEYS_DIR`:
    - `EMG-P2812` / `EMG` -> `P2812_TAFJORD`
    - `FMG` -> `FMG3542_TAFJORD`
    - `VMG8825` / `VMG`, `EX5401`, `EX5601`, `AX7501` / `AX` -> `VMG8825-EX-AX_TAFJORD`
- Other models:
  - fallback to generic settings (`CPE_SSH_USER`, `CPE_SSH_PASS`, `CPE_SSH_KEY_PATH`, optional `CPE_SSH_MODEL_KEY_MAP`)

## Model command profiles

- `model=FO1`, `model=F1X`, `model=EWA*`, and `model=VANTIVA` use the OpenWRT poll profile (`ubus`/`uci`) and parse `ubus call system info` into `cpeInfo`/`uptime` when possible.
- `model=AX7501` and `model=AX*` use the ZyXEL poll profile without `zycli sfp show`.
- `model=VMG8825`, `VMG*`, `EX5401`, `EX5601`, `EX*`, `EMG-P2812`, `EMG*`, and `FMG*` use the ZyXEL poll profile with SFP command.
- Unknown model values use the ZyXEL-compatible default profile.
- Evidence and confirmation state per model is tracked in `docs/device-command-matrix.md`.

## CPE actions

- Supported actions are exposed through `POST /v1/cpe/actions`.
- VANTIVA OpenWRT family (`FO1`, `F1X`, `EWA`, `VANTIVA`) supports:
  - `reboot`
  - `semi_reset`
  - `factory_reset`
- ZyXEL family (`VMG8825` / `VMG`, `EX5401`, `EX5601`, `AX7501` / `AX`, `FMG`, `EMG-P2812` / `EMG`) supports:
  - `reboot`
  - `factory_reset`
- Use `"dryRun": true` to validate the resolved command/profile without executing the action on the device.
- TR-069 parameter presence is still documented in `docs/device-command-matrix.md`, but no TR-069 mutation endpoint is exposed yet.

## Switch polling (SNMP)

- `GET|POST /v1/switch/ports` polls Cisco Catalyst 4500/9400 and Huawei S5736 (VRP) over SNMP. Vendor is detected automatically via `sysObjectID`; no per-request vendor selection.
- Returns per interface: oper/admin status, time-in-state, speed (Mbps), duplex, Ds/Us byte counters (+ MB) and packet errors, transceiver optics (Rx/Tx power dBm, temperature, voltage, current), and learned MAC addresses (with VLAN).
- `Ds` (downstream) = switch egress; `Us` (upstream) = switch ingress. Pass `reverse=true` for core-facing ports.
- `port` accepts CLI shorthand (`6/2`, `Gi6/2`, `GE0/0/2`) or the full SNMP name; 2-tuple labels also match stacked 3-tuple names (`3/20` ↔ `GigabitEthernet3/0/20`). Omit `port` for all interfaces.
- MAC addresses are included automatically for a single-port query, or on demand with `macs=true` (source: Q-BRIDGE `dot1qTpFdbTable`).
- `portGroup` (e.g. `TAFAALLERSTADAR2S003P20`) resolves the switch IP and interface from a hosts file (`SWITCH_HOSTS_FILE`): prefix `TAF`→Cisco / `NVF`→Huawei, then location + `ARn`, card `Sxxx`, port `Pyy`.
- SNMP is optional; the endpoint returns `502` "snmp polling is not configured" until `SNMP_COMMUNITY` (or a v3 user) is set.
- Full setup, device config, and `snmpwalk` verification: [docs/snmp-switch-polling.md](docs/snmp-switch-polling.md).

## Security defaults

- Optional API-key auth (`CPE_API_KEY`) — send the key directly in the `Authorization` header, or as `Bearer <key>`
- Target IP allowlist CIDRs (`CPE_ALLOWED_TARGET_CIDRS`; SNMP uses `SNMP_ALLOWED_TARGET_CIDRS`)
- SSH host-key verification via known_hosts (`CPE_SSH_KNOWN_HOSTS`)
- SNMPv3 authPriv supported; v2c community strings are sent in cleartext
- Safe output: WLAN PSK redacted unless `includePsk=1`
- Global concurrency limiter (`CPE_CONCURRENCY`)
- Per-target execution gate (one in-flight collect per CPE IP)
- Request, dial, and command timeouts; the poll budget must fit inside the HTTP write deadline (enforced at startup)

## Environment

Server / shared:

- `ADDR` (default `:8080`)
- `LOG_LEVEL` (`DEBUG|INFO|WARN|ERROR`, default `INFO`)
- `CPE_API_KEY` (optional)
- `CPE_ALLOWED_TARGET_CIDRS` (default private CIDRs)
- `CPE_CONCURRENCY` (default `16`)
- `HTTP_READ_HEADER_TIMEOUT` (`5s`), `HTTP_READ_TIMEOUT` (`20s`), `HTTP_WRITE_TIMEOUT` (`60s`), `HTTP_IDLE_TIMEOUT` (`60s`)
- `.env` in the working dir is auto-loaded on startup (real env vars take precedence)

CPE (SSH):

- `CPE_REQUEST_TIMEOUT` (default `45s`, must be `< HTTP_WRITE_TIMEOUT`)
- `CPE_SSH_DIAL_TIMEOUT` (default `6s`)
- `CPE_SSH_CMD_TIMEOUT` (default `12s`)
- `CPE_SSH_USER` (default `root`)
- `CPE_SSH_PASS` (optional, required if no key)
- `CPE_SSH_KEY_PATH` (optional, required if no password)
- `CPE_SSH_KEY_PASSPHRASE` (optional)
- `CPE_SSH_KEYS_DIR` (default `cpe-ssh-keys`, required for model-based key lookup)
- `CPE_SSH_MODEL_KEY_MAP` (optional format: `MODEL=FILENAME,MODEL2=FILENAME2`)
- `VANTIVA_CPE_CLI_USER` / `VANTIVA_CPE_CLI_PASSWORD` (required for VANTIVA models `FO1`, `F1X`, `EWA`, `VANTIVA`)
- `CPE_SSH_KNOWN_HOSTS` (required unless insecure host key is enabled)
- `CPE_SSH_INSECURE_HOSTKEY` (default `false`, not recommended)

Switch (SNMP) — optional, enables `/v1/switch/ports`:

- `SNMP_VERSION` (`2c` | `3`, default `2c`)
- `SNMP_COMMUNITY` (required for v2c)
- `SNMP_V3_USER`, `SNMP_V3_LEVEL` (default `authPriv`), `SNMP_V3_AUTH_PROTOCOL` (default `SHA`), `SNMP_V3_AUTH_PASS`, `SNMP_V3_PRIV_PROTOCOL` (default `AES`), `SNMP_V3_PRIV_PASS`
- `SNMP_PORT` (default `161`)
- `SNMP_TIMEOUT` (`5s`), `SNMP_RETRIES` (`2`), `SNMP_REQUEST_TIMEOUT` (`30s`, must be `< HTTP_WRITE_TIMEOUT`), `SNMP_MAX_REPETITIONS` (`20`)
- `SNMP_ALLOWED_TARGET_CIDRS` (defaults to `CPE_ALLOWED_TARGET_CIDRS`)
- `SWITCH_HOSTS_FILE` (hosts file of `IP hostname` lines for `portGroup` resolution)

## Run

```bash
go mod tidy
go run ./cmd/device-api
```

PowerShell with `.env` reload (equivalent; the binary also auto-loads `.env`):

```powershell
.\run.ps1
```

Open in browser:

- `http://localhost:8080/docs`
- `http://localhost:8080/openapi.yaml`
- `http://localhost:8080/metrics`

## API contract (swaggo-generated)

The OpenAPI 3.1 document is generated from swaggo annotations on the controllers — it is not hand-edited. Regenerate after changing handlers or DTOs:

```bash
swag init --v3.1 --generalInfo cmd/device-api/main.go --output internal/ports/docs --outputTypes yaml
mv internal/ports/docs/swagger.yaml internal/ports/docs/openapi.yaml
```

`GET /openapi.yaml` serves that exact (embedded) document and `GET /docs` renders Swagger UI against it. Optionally lint the output in CI with Spectral or Redocly (parse validation, missing responses, security consistency, breaking-change checks).

## Observability

- Prometheus metrics are exposed at `GET /metrics`, all under the `device_api_` namespace.
- Metrics include:
  - HTTP request totals by route, method, and status
  - HTTP request duration histogram by route and method
  - in-flight request gauge by route
  - collector request totals by normalized model and result
  - SSH dial failures by normalized model and classified reason
  - command duration histogram by profile, command key, and result
  - concurrency rejection totals
  - SNMP poll totals and duration by result
  - SNMP failures by classified reason
- Optional OTLP tracing: set `OTEL_EXPORTER_OTLP_ENDPOINT` to enable the OTLP/HTTP trace exporter (service name `device-api`); otherwise tracing is a no-op.
- Labels intentionally avoid high-cardinality values such as request IDs, raw IPs, and raw error strings.

## Example calls

CPE collect (Bearer or raw key both accepted):

```bash
curl -sS -X POST "http://localhost:8080/v1/cpe/collect?raw=1" \
  -H "Authorization: Bearer change-me" \
  -H "Content-Type: application/json" \
  -d '{"ip":"192.168.1.1","model":"VANTIVA"}'
```

CPE action dry-run:

```bash
curl -sS -X POST "http://localhost:8080/v1/cpe/actions" \
  -H "Authorization: change-me" \
  -H "Content-Type: application/json" \
  -d '{"ip":"192.168.1.1","model":"EX5401","action":"reboot","dryRun":true}'
```

Switch port by port-group:

```bash
curl -sS "http://localhost:8080/v1/switch/ports?portGroup=TAFAALLERSTADAR2S003P20" \
  -H "Authorization: change-me"
```

## Real-device validation

1. Prepare config and secrets in `.env` (auto-loaded):
   - set `VANTIVA_CPE_CLI_USER` / `VANTIVA_CPE_CLI_PASSWORD` for VANTIVA
   - set `SNMP_COMMUNITY` (or v3 user) and `SWITCH_HOSTS_FILE` for switches
   - set `LOG_LEVEL=DEBUG` during troubleshooting
   - set `CPE_SSH_KNOWN_HOSTS` (or use insecure host key only in non-prod)
2. Start API: `go run ./cmd/device-api`
3. Validate `VANTIVA` path: call with `"model":"VANTIVA"` and verify SSH auth
4. Validate ZyXEL path: call with `"model":"FMG"` / `"P2812"` / `"VMG"` and verify root+key auth
5. Validate switch path: call `?portGroup=...` from inside the management network and verify port status/optics/MACs
6. Negative test: call `model=../bad` and verify HTTP `400 bad_request`

## SSH readiness rule

- The collector requires interactive shell readiness before running commands:
  - BusyBox banner must be detected
  - prompt must reach `#`
- Commands are executed strictly one-by-one in the same shell, and each command must return to `#` before the next starts.

## Troubleshooting

- Command errors like `Process exited with status 127` mean that command is missing on that firmware/profile. The API logs command key, duration, and output sample so you can identify which parsers are not applicable.
- Use `raw=1` while validating new firmware variants to see exact command output.
- If commands differ significantly between vendors/firmware, add model-specific command sets in `internal/cpe/collector.go`.
- `ssh dial` errors are classified with hints in response/logs:
  - `connection refused` / `actively refused`: target port is closed or SSH is disabled on that interface.
  - `timed out`: network path/firewall issue.
  - `unable to authenticate`: credentials/key/passphrase mismatch.
- Switch `502 snmpFailed` with a `timeout` reason usually means UDP/161 is unreachable or the community/credentials are wrong; empty duplex/optics on a port usually means copper/no-DDM or a too-restrictive SNMP view.

## Notes

- The `portmap` command includes `dmesg -c`, which clears the kernel ring buffer on the CPE.
- Switch byte/error counters are absolute totals; compute rates client-side from two polls.
- Reboot/reset/TR-069 command mappings are documented in `docs/device-command-matrix.md` for operational parity.
