# Recon Pro VPS shell MCP

Optional companion to `vps_mcp/`. Where the updater accepts exactly one fixed
operation, this endpoint exposes the checkout owner's shell: `run_command`,
`read_file`, `write_file`, `list_dir`.

Use it only while you need remote work on the VPS, and stop it afterwards. It
runs with the permissions of whoever starts it, so run it as the checkout owner,
never as root.

## adb keepalive

`bash recon.sh --update` also re-installs the adb keepalive service, so a host
that holds the adb server for an `ip:port` device keeps that transport alive
across Wi-Fi drops and reboots. It stays silent unless the host is root, has
`adb` installed, and already owns a running adb server, and it runs the loop as
the account that owns that server (a second adb server under another user would
keep nothing alive).

```bash
sudo bash vps_shell/keepalive_ctl.sh              # install/refresh now
sudo bash vps_shell/keepalive_ctl.sh --restart    # force a fresh process
bash vps_shell/keepalive_ctl.sh --status          # unit, pid, last log lines
sudo bash vps_shell/keepalive_ctl.sh --uninstall  # remove it again
ADB_KEEPALIVE=0                                   # in state/recon_pro.conf: never install
```

The loop checks every 5s while healthy, drops to 1s while a device is down, and
restarts the adb server itself after 6 failed rounds. Installing also shortens
the kernel TCP keepalive (60s idle, 3 probes) so a dead phone link is noticed in
about a minute and a half instead of the 15 minute default.

Logs: `journalctl -u adb-keepalive -n 50 --no-pager`. Overrides:
`ADB_KEEPALIVE_USER`, `ADB_KEEPALIVE_SERIALS` (space separated), and the
`ADB_KEEPALIVE_*` knobs in the script header.

## Start it (temporary HTTPS URL)

```bash
bash vps_shell/start_quick_tunnel.sh
```

It builds a local virtualenv, generates a random bearer key at
`$RECON_PRO_HOME/state/shell_api_key` (default `~/recon_pro/state/`,
mode 600), starts the server on `127.0.0.1:8767`, opens a Cloudflare Quick
Tunnel, and prints:

```
MCP shell endpoint: https://<random>.trycloudflare.com/mcp
API key tersimpan lokal di: /home/<user>/recon_pro/state/shell_api_key
```

In FreeMilk, open **Integrations**, add the MCP server with that exact endpoint
(including `/mcp`), and paste the key from `state/shell_api_key` into the
integration prompt. Never paste the key into chat or a committed file.

## Stop it

```bash
bash vps_shell/stop_quick_tunnel.sh
```

The Quick Tunnel URL changes every time the tunnel is recreated, so re-add the
integration after a restart. For a stable hostname, put the same server behind
your existing named Cloudflare Tunnel on port 8767 instead of a Quick Tunnel.

## Limits and safety

- Binds `127.0.0.1:8767` only. Do not open that port in the VPS firewall.
- Every request needs the bearer key; anything without it gets `401`.
- The Quick Tunnel URL is public and unauthenticated at the transport level, so
  the key is the only door. Rotate it by deleting `state/shell_api_key` and
  starting again.
- Commands run non-interactively (`bash -lc`, no stdin, no TTY) with a timeout,
  and output is truncated at 12000 characters.
- Prefer `vps_mcp/` for routine updates; this endpoint exists for one-off
  administration such as installing a service.
