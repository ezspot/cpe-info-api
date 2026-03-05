# Device Command Matrix

This matrix is the source of truth for model command profiles in this service.

- Evidence policy: only commands confirmed from provided payloads/logs are listed as `confirmed`.
- Unknown policy: commands not present in payloads are marked `not confirmed`.
- Last updated: 2026-03-05.

## Profiles in code

- `zyxel-v1`: VMG8825, EX5401, EX5601, FMG, P2812, and generic ZyXEL fallback.
- `zyxel-ax-v1`: AX7501 (same as ZyXEL profile but without `zycli sfp show`).
- `vantiva-openwrt-v1`: VANTIVA FGA2235TCS (OpenWRT ubus/uci poll commands).

## ZyXEL VMG8825 / EX5401 / EX5601 (confirmed)

Poll/info commands:

- `sys atsh`
- `uptime`
- `ifconfig`
- `cfg lanhosts get`
- `dmesg -c > /dev/null 2>&1; ethswctl -c arldump > /dev/null 2>&1; for line in $(cfg lanhosts get | grep Ethernet | awk '{print $4}' | sed 's/://g'); do dmesg | grep $line | awk '{print $3 " " $4}'; done`
- `arp -a | grep br0`
- `cat /var/dnsmasq/dnsmasq.leases`
- `cfg ethctl get`
- `zywlctl -b 2 assoclist`
- `zywlctl -b 5 assoclist`
- `cfg wlan get`
- `cat /proc/loadavg`
- `zycli sfp show`

Actions:

- Reboot: `reboot`
- Factory reset: `sys atcr reboot`
- TR-069 parameter set present: `Device.X_ZYXEL_RemoteManagement.SPService.5.Enable` (`1`/`0`)

## ZyXEL AX7501 (confirmed)

Poll/info commands:

- `sys atsh`
- `uptime`
- `ifconfig`
- `cfg lanhosts get`
- `dmesg -c > /dev/null 2>&1; ethswctl -c arldump > /dev/null 2>&1; for line in $(cfg lanhosts get | grep Ethernet | awk '{print $4}' | sed 's/://g'); do dmesg | grep $line | awk '{print $3 " " $4}'; done`
- `arp -a | grep br0`
- `cat /var/dnsmasq/dnsmasq.leases`
- `cfg ethctl get`
- `zywlctl -b 2 assoclist`
- `zywlctl -b 5 assoclist`
- `cfg wlan get`
- `cat /proc/loadavg`

Actions:

- Reboot: `reboot`
- Factory reset: `sys atcr reboot`
- TR-069 parameter set present: `Device.X_ZYXEL_RemoteManagement.SPService.5.Enable` (`1`/`0`)

## VANTIVA FGA2235TCS OpenWRT (confirmed)

Poll/info commands:

- `ubus call system info`
- `uci show env`
- `ubus call network.device status`
- `ubus call hostmanager.device get`
- `ubus call gpon.trsv get_info`

Actions:

- Reboot: `reboot`
- Semi-reset: `rtfd --soft`
- Factory reset: `rtfd`
- ACS task templates present: `SAM uptime`, `SAM F1 RemoteUser`

## FMG3542 / EMG2812AC command set status

- FMG3542: `not confirmed` in provided payloads.
- EMG2812AC: `not confirmed` in provided payloads.

The current implementation keeps ZyXEL-compatible polling for FMG/P2812/VMG/EX/AX based on existing production behavior, but this matrix still marks FMG/EMG command evidence as unconfirmed until payload proof is captured.

## Operational notes

- `portmap` command uses `dmesg -c` and clears the kernel ring buffer.
- Command execution is sequential in one interactive shell per request.
- Commands are model-profile based and selected from the request `model`.
