# cpe-api

Production-oriented Go 1.24+ service that collects CPE diagnostics over SSH.

## Endpoints

- `GET /healthz`
- `GET /readyz`
- `GET /openapi.yaml`
- `GET /docs` (Swagger UI)
- `GET /swagger/index.html` (swaggo-generated Swagger UI)
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

- `VANTIVA`:
  - key: `cpe-ssh-keys/VANTIVA_TAFJORD`
  - user: `VANTIVA_CPE_CLI_USER`
  - password: `VANTIVA_CPE_CLI_PASSWORD`
  - if key parsing fails (for example passphrase-protected key), password auth is used
- ZyXEL family (`FMG`, `P2812`, `VMG`, `AX`, `EX`):
  - always user `root`
  - always key-only from `CPE_SSH_KEYS_DIR`:
    - `P2812` -> `P2812_TAFJORD`
    - `FMG` -> `FMG3542_TAFJORD`
    - `VMG` / `AX` / `EX` -> `VMG8825-EX-AX_TAFJORD`
- Other models:
  - fallback to generic settings (`CPE_SSH_USER`, `CPE_SSH_PASS`, `CPE_SSH_KEY_PATH`, optional `CPE_SSH_MODEL_KEY_MAP`)

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
- `http://localhost:8080/swagger/index.html`

## Swagger automation (swaggo)

- Swagger docs are generated from Go annotations.
- Regenerate after endpoint/schema annotation changes:

```bash
go generate ./cmd/cpe-api
```

- Generated files are written to `internal/httpapi/swagdocs`.

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

## Notes

- The `portmap` command includes `dmesg -c`, which clears the kernel ring buffer on the CPE.
