# cpe-api

Production-oriented Go 1.24+ service that collects CPE diagnostics over SSH.

Canonical model command documentation is maintained in [docs/device-command-matrix.md](docs/device-command-matrix.md).
The canonical API contract is maintained in [internal/httpapi/docs/openapi.yaml](internal/httpapi/docs/openapi.yaml).

## Endpoints

- `GET /healthz`
- `GET /readyz`
- `GET /openapi.yaml`
- `GET /docs` (Swagger UI)
- `GET /metrics` (Prometheus scrape endpoint)
- `GET /v1/cpe/collect?ip=192.168.1.1&port=22&model=VANTIVA&raw=1&includePsk=0`
- `POST /v1/cpe/collect?raw=1&includePsk=0` with JSON body:

```json
{
  "ip": "192.168.1.1",
  "port": 22,
  "model": "VANTIVA"
}
```

## Model-based SSH behavior

- `VANTIVA` family (`F01`, `F1X`):
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

- `model=F01`, `model=F1X`, and `model=VANTIVA` use the OpenWRT poll profile (`ubus`/`uci`) and parse `ubus call system info` into `cpeInfo`/`uptime` when possible.
- `model=AX7501` and `model=AX*` use the ZyXEL poll profile without `zycli sfp show`.
- `model=VMG8825`, `VMG*`, `EX5401`, `EX5601`, `EX*`, `EMG-P2812`, `EMG*`, and `FMG*` use the ZyXEL poll profile with SFP command.
- Unknown model values use the ZyXEL-compatible default profile.
- Evidence and confirmation state per model is tracked in `docs/device-command-matrix.md`.

## Security defaults

- Optional bearer auth (`CPE_API_KEY`)
- Target IP allowlist CIDRs (`CPE_ALLOWED_TARGET_CIDRS`)
- SSH host-key verification via known_hosts (`CPE_SSH_KNOWN_HOSTS`)
- Safe output: WLAN PSK redacted unless `includePsk=1`
- Global concurrency limiter (`CPE_CONCURRENCY`)
- Per-target execution gate (one in-flight collect per CPE IP)
- Request, dial, and command timeouts

## Environment

- `ADDR` (default `:8080`)
- `LOG_LEVEL` (`DEBUG|INFO|WARN|ERROR`, default `INFO`)
- `CPE_API_KEY` (optional)
- `CPE_ALLOWED_TARGET_CIDRS` (default private CIDRs)
- `CPE_CONCURRENCY` (default `16`)
- `CPE_REQUEST_TIMEOUT` (default `45s`)
- `CPE_SSH_DIAL_TIMEOUT` (default `6s`)
- `CPE_SSH_CMD_TIMEOUT` (default `12s`)
- `CPE_SSH_USER` (default `root`)
- `CPE_SSH_PASS` (optional, required if no key)
- `CPE_SSH_KEY_PATH` (optional, required if no password)
- `CPE_SSH_KEY_PASSPHRASE` (optional)
- `CPE_SSH_KEYS_DIR` (default `cpe-ssh-keys`, required for model-based key lookup)
- `CPE_SSH_MODEL_KEY_MAP` (optional format: `MODEL=FILENAME,MODEL2=FILENAME2`)
- `VANTIVA_CPE_CLI_USER` (required for `model=VANTIVA`)
- `VANTIVA_CPE_CLI_PASSWORD` (required for `model=VANTIVA`)
- `CPE_SSH_KNOWN_HOSTS` (required unless insecure host key is enabled)
- `CPE_SSH_INSECURE_HOSTKEY` (default `false`, not recommended)

## Run

```bash
go mod tidy
go run ./cmd/cpe-api
```

PowerShell with `.env` reload (recommended for local dev):

```powershell
.\run.ps1
```

Open docs in browser:

- `http://localhost:8080/docs`
- `http://localhost:8080/openapi.yaml`
- `http://localhost:8080/metrics`

## API contract workflow

- `internal/httpapi/docs/openapi.yaml` is the single authoritative API contract.
- `GET /openapi.yaml` serves that exact document.
- `GET /docs` renders Swagger UI against the canonical OpenAPI 3 document.
- When behavior or payloads change, update the code and `internal/httpapi/docs/openapi.yaml` together in the same change.
- Prefer contract-first review: update the OpenAPI document first when introducing new operations or response shapes.

## Contract validation guidance

- Validate the OpenAPI document in CI or locally with an OpenAPI linter/validator such as Spectral or Redocly.
- Recommended checks:
  - validate the OpenAPI document parses successfully
  - lint for missing operation IDs, undocumented responses, and security inconsistencies
  - add breaking-change checks before publishing client-facing changes

## Observability

- Prometheus metrics are exposed at `GET /metrics`.
- Metrics include:
  - HTTP request totals by route, method, and status
  - HTTP request duration histogram by route and method
  - in-flight request gauge by route
  - collector request totals by normalized model and result
  - SSH dial failures by normalized model and classified reason
  - command duration histogram by profile, command key, and result
  - concurrency rejection totals
- Labels intentionally avoid high-cardinality values such as request IDs, raw IPs, and raw error strings.

## Example call

```bash
curl -sS -X POST "http://localhost:8080/v1/cpe/collect?raw=1" \
  -H "Authorization: Bearer change-me" \
  -H "Content-Type: application/json" \
  -d '{"ip":"192.168.1.1","model":"VANTIVA"}'
```

ZyXEL example:

```bash
curl -sS -X POST "http://localhost:8080/v1/cpe/collect" \
  -H "Authorization: Bearer change-me" \
  -H "Content-Type: application/json" \
  -d '{"ip":"192.168.1.1","model":"FMG"}'
```

PowerShell example:

```powershell
$token = "change-me"
$body = @{ ip = "10.13.94.62"; model = "EX" } | ConvertTo-Json
Invoke-RestMethod `
  -Method Post `
  -Uri "http://localhost:8080/v1/cpe/collect" `
  -Headers @{ Authorization = "Bearer $token" } `
  -ContentType "application/json" `
  -Body $body
```

## Real-device validation

1. Prepare config and secrets:
   - copy `.env.example` to `.env`
   - set `VANTIVA_CPE_CLI_USER` and `VANTIVA_CPE_CLI_PASSWORD`
   - set `LOG_LEVEL=DEBUG` during troubleshooting
   - set `CPE_SSH_KNOWN_HOSTS` (or use insecure host key only in non-prod)
2. Start API:
   - `go run ./cmd/cpe-api`
3. Validate `VANTIVA` path:
   - call with `"model":"VANTIVA"` and verify successful SSH auth
4. Validate ZyXEL path:
   - call with `"model":"FMG"` / `"P2812"` / `"VMG"` and verify root+key auth works
5. Negative test:
   - call `model=../bad` and verify HTTP `400 bad_request`

## SSH readiness rule

- The collector now requires interactive shell readiness before running commands:
  - BusyBox banner must be detected
  - prompt must reach `#`
- Commands are executed strictly one-by-one in the same shell, and each command must return to `#` before the next starts.

## Troubleshooting

- Command errors like `Process exited with status 127` mean that command is missing on that firmware/profile. The API now logs command key, duration, and output sample so you can identify which parsers are not applicable.
- Use `raw=1` while validating new firmware variants to see exact command output.
- If commands differ significantly between vendors/firmware, add model-specific command sets in `internal/cpe/collector.go`.
- `ssh dial` errors are classified with hints in response/logs:
  - `connection refused` / `actively refused`: target port is closed or SSH is disabled on that interface.
  - `timed out`: network path/firewall issue.
  - `unable to authenticate`: credentials/key/passphrase mismatch.

## Notes

- The `portmap` command includes `dmesg -c`, which clears the kernel ring buffer on the CPE.
- Reboot/reset/TR-069 command mappings are documented in `docs/device-command-matrix.md` for operational parity, but this API currently exposes collection endpoints only.
