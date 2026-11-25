# Temporary Recon Pro MCP updater

This optional service lets FreeMilk request one narrowly scoped operation on the VPS: run the existing `bash recon.sh --update`, then independently run `bash recon.sh --self-test`. It does not accept shell commands, paths, branch names, or other caller-supplied arguments. It refuses a dirty checkout, a branch other than `main`, an unexpected `origin`, and a detected Recon Pro scan. It does not restart the dashboard or bot.

## Temporary HTTPS setup without a domain

Cloudflare Quick Tunnels create a random `trycloudflare.com` URL without a Cloudflare account or custom domain. The hostname changes whenever the tunnel is recreated, there is no uptime guarantee, and the endpoint must be added to FreeMilk again after the URL changes. Quick Tunnels do not support SSE, so this server uses stateless JSON Streamable HTTP. A locally generated 48-byte bearer secret protects the MCP endpoint. Anyone who learns the URL can reach the service, but cannot call its tool without that key.

The MCP app binds only to `127.0.0.1:8766`. Do not open port 8766 in the VPS firewall or expose it with a different proxy. The Cloudflare tunnel is the only public route. Keep the MCP process running only while you want the temporary connection active.

### Requirements

- Linux VPS, Bash, Git, and Python 3.11+.
- `cloudflared` installed from Cloudflare's official instructions: <https://developers.cloudflare.com/tunnel/downloads/>.
- The checkout's `origin` must be `https://github.com/rayhanmaulana040519-source/recon-pro.git`, on branch `main`, with working GitHub read access for the Linux account that runs the MCP service.
- Run the service as the account that owns the checkout and Git credentials. It inherits that account's filesystem privileges; running it as root is discouraged. The endpoint exposes no general shell, but a compromised service running as root would still be a root-process compromise.

### Start

First make the latest project files available on the VPS, then from the checkout run:

```bash
bash vps_mcp/start_quick_tunnel.sh
```

The script installs the directly pinned MCP dependencies into `vps_mcp/.venv`, creates a random key at `$RECON_PRO_HOME/state/mcp_api_key` (default: `~/recon_pro/state/mcp_api_key`, mode 600), starts the MCP service and Quick Tunnel in the background, and prints the temporary endpoint, for example `https://random-name.trycloudflare.com/mcp`. It clears the old tunnel log before startup so it cannot accidentally print a stale Quick Tunnel URL. The updater also requires `main` to track `origin/main` before pulling.

Add that URL in FreeMilk's **Integrations** tab with the MCP name `Recon Pro VPS updater`. When asked for the API key, read it locally on the VPS with:

```bash
cat "${RECON_PRO_HOME:-$HOME/recon_pro}/state/mcp_api_key"
```

Paste the key directly into the integration prompt. Never send it in chat, commit it, or put it in a URL. The server expects `Authorization: Bearer <key>`.

To stop the temporary service and tunnel:

```bash
bash vps_mcp/stop_quick_tunnel.sh
```

The API key remains on the VPS for the next start. To rotate it, stop the service, remove `state/mcp_api_key`, start again, then replace the key in the FreeMilk integration. The Quick Tunnel URL will also change after a restart, so update that integration URL as well.

## Operational limits

- Calling the MCP tool updates only the local checkout and checks syntax; it does not restart a running dashboard, bot, or other process. Restart services only after any active scan finishes.
- If GitHub credentials are unavailable to the Linux account, the operation fails closed because interactive Git prompts are disabled.
- If there are local changes or an active scan, the updater refuses to proceed; resolve or wait on the VPS, then call it again.
- This is a temporary tunnel, not a production deployment. For a stable endpoint, use a named Cloudflare Tunnel on a domain you control, keep bearer authentication, and allow only the exact hostname at the proxy.
