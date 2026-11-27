# Recon Pro VPS shell MCP

Optional companion to `vps_mcp/`. Where the updater accepts exactly one fixed
operation, this endpoint exposes the checkout owner's shell: `run_command`,
`read_file`, `write_file`, `list_dir`.

Use it only while you need remote work on the VPS, and stop it afterwards. It
runs with the permissions of whoever starts it, so run it as the checkout owner,
never as root.

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
