# Recon Pro VPS MCP updater

This optional service lets FreeMilk request one narrowly scoped operation on the VPS: run the existing `bash recon.sh --update`, then independently run `bash recon.sh --self-test`. It does not accept shell commands, paths, branch names, or other caller-supplied arguments. It refuses a dirty checkout, a branch other than `main`, an unexpected `origin`, and a detected Recon Pro scan. It does not restart the dashboard or bot.

The MCP app binds only to `127.0.0.1:8766`. Do not open port 8766 in the VPS firewall or expose it with another proxy. Cloudflare Tunnel is the only public route. The endpoint requires a locally generated bearer key; never put that key or the Cloudflare Tunnel token in chat, a URL, or a committed file.

## Persistent HTTPS setup with a named Cloudflare Tunnel

Use this when you own a domain managed by Cloudflare and have already added a **Published application** route to the intended tunnel. The route's service must be `http://127.0.0.1:8766` (or `http://localhost:8766`). The public hostname should match the hostname you enter during setup. Do not point it to the dashboard port 8765.

### Requirements

- Linux VPS with systemd, Bash, Git, and Python 3.11+.
- `cloudflared` installed from Cloudflare's official instructions: <https://developers.cloudflare.com/tunnel/downloads/>.
- The checkout's `origin` must be `https://github.com/rayhanmaulana040519-source/recon-pro.git`, on branch `main`, with working GitHub read access for the Linux account that owns the checkout.
- The MCP updater runs as the checkout owner. Running it as root is discouraged; if the checkout is owned by root, the installer warns you.
- A named Cloudflare Tunnel and Published application hostname already configured in Cloudflare Zero Trust. If the host does not already have an active `cloudflared.service`, have the tunnel's connector token available in the Cloudflare dashboard. Enter it only at the hidden prompt in the VPS terminal.

### Install and start

First update the VPS checkout so it contains this setup script. Then run from the checkout:

```bash
sudo bash vps_mcp/install_named_tunnel.sh
```

The installer asks for the public hostname and, only if there is no active `cloudflared.service`, a Tunnel Token. The token prompt does not echo input. The script installs pinned Python dependencies, creates a random 48-byte bearer key at `$RECON_PRO_HOME/state/mcp_api_key` (default: the checkout owner's `~/recon_pro/state/mcp_api_key`, mode 600), writes a protected systemd environment file, and creates/enables `recon-pro-mcp.service`. It also installs/enables Cloudflare's `cloudflared.service` if needed. Both services are enabled at boot; the MCP unit restarts on failure. Existing Cloudflare services are not overwritten; if one is already active, verify it belongs to the intended tunnel.

The installer prints the MCP endpoint, for example `https://mcp.yourdomain.id/mcp`. Check both services on the VPS:

```bash
sudo systemctl status cloudflared recon-pro-mcp --no-pager
```

If the route was not set up yet, go to Cloudflare Zero Trust > Networks > Tunnels, select the named tunnel, and add a Published application route with the hostname you used and service `http://127.0.0.1:8766`. Keep the VPS firewall closed for port 8766.

### Connect FreeMilk

In FreeMilk, open **Integrations** and add the MCP server using the exact endpoint printed by the installer, including `/mcp`. Name it `Recon Pro VPS updater`. When asked for the API key, read it locally on the VPS:

```bash
cat "${RECON_PRO_HOME:-$HOME/recon_pro}/state/mcp_api_key"
```

Paste the key directly into the FreeMilk integration prompt, never into chat. The key is also stored in a mode-600 environment file for systemd. Do not commit either file.

### Manage the persistent services

```bash
sudo systemctl status recon-pro-mcp cloudflared --no-pager
sudo journalctl -u recon-pro-mcp -n 50 --no-pager
sudo journalctl -u cloudflared -n 50 --no-pager
sudo systemctl restart recon-pro-mcp
```

To pause only the updater, use `sudo systemctl disable --now recon-pro-mcp`. To disconnect this VPS from Cloudflare as well, use `sudo systemctl disable --now cloudflared`; this also disconnects any other routes that depend on that connector. Re-enable with `sudo systemctl enable --now cloudflared recon-pro-mcp`.

## Temporary HTTPS setup without a domain

Cloudflare Quick Tunnels create a random `trycloudflare.com` URL without a Cloudflare account or custom domain. The hostname changes whenever the tunnel is recreated, there is no uptime guarantee, and the endpoint must be added to FreeMilk again after the URL changes. Quick Tunnels do not support SSE, so this server uses stateless JSON Streamable HTTP.

To start the temporary service from the checkout:

```bash
bash vps_mcp/start_quick_tunnel.sh
```

The script starts MCP and a Quick Tunnel in the background, prints a temporary `/mcp` endpoint, and stores the same bearer key in `$RECON_PRO_HOME/state/mcp_api_key`. Add the URL and key in FreeMilk **Integrations**. To stop the temporary service:

```bash
bash vps_mcp/stop_quick_tunnel.sh
```

Do not run Quick Tunnel and the persistent MCP service at the same time; both need port 8766. Quick Tunnel is not the stable setup and does not start on reboot.

## Operational limits and security

- Keep the endpoint behind Cloudflare HTTPS and bearer authentication. The Cloudflare Tunnel token is a separate, powerful connector credential; keep it private and rotate it in Cloudflare if exposed.
- The updater inherits the checkout owner's filesystem permissions. It refuses to run if GitHub credentials are unavailable, the working tree is dirty, a scan is active, or the branch/origin/upstream do not match the configured repository.
- Calling the MCP tool updates only the local checkout and checks syntax; it does not restart a running dashboard, bot, or other process. Restart services only after any active scan finishes.
- The local MCP service can be stopped independently from the Cloudflare connector. Do not stop the connector if other applications use the same tunnel.
