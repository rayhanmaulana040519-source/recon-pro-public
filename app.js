(() => {
  "use strict";

  const TOKEN_KEY = "reconpro-local-session";
  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));
  const state = { token: "", scope: [], targets: [], reports: [], selectedReport: null, selectedLog: null, outputSeq: 0, scanId: null, scanRunning: false, shellSeq: 0, shellId: null, shellRunning: false, shellEnabled: false, timer: null, reportLoadSerial: 0, logLoadSerial: 0, arsenal: [], arsenalFilter: "all", clock: null, boot: null };
  const loginScreen = $("#loginScreen");
  const appShell = $("#appShell");
  const loginError = $("#loginError");
  const previewHost = /(^|\.)freemilk\.app$/i.test(location.hostname);

  function text(node, value) {
    if (node) node.textContent = value == null ? "" : String(value);
  }

  function toast(message, kind = "info") {
    const item = document.createElement("div");
    item.className = `toast toast-${kind}`;
    item.textContent = message;
    $("#toastRegion").appendChild(item);
    window.setTimeout(() => item.remove(), 4200);
  }

  async function request(path, options = {}) {
    const headers = new Headers(options.headers || {});
    if (state.token) headers.set("Authorization", `Bearer ${state.token}`);
    if (options.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
    let response;
    try {
      response = await fetch(path, { ...options, headers, cache: "no-store", credentials: "omit" });
    } catch (_error) {
      throw new Error("Backend lokal tidak merespons. Pastikan web_ui/server.py masih berjalan pada mesin R3YN0D3.");
    }
    let payload = {};
    try { payload = await response.json(); } catch (_error) { /* handled below */ }
    if (response.status === 401 && path !== "/api/login") {
      signOut(false);
      throw new Error("Sesi berakhir. Masuk kembali dengan token dashboard.");
    }
    if (!response.ok) throw new Error(payload.error || `Permintaan gagal (${response.status}).`);
    return payload;
  }

  function showLogin(message = "") {
    loginScreen.classList.remove("hidden");
    appShell.classList.add("hidden");
    text(loginError, message);
    if (previewHost) {
      $("#previewNotice").classList.remove("hidden");
      $("#loginForm").classList.add("preview-disabled");
      $("#accessToken").disabled = true;
      $("#loginForm button[type='submit']").disabled = true;
    }
  }

  function signOut(showMessage = true) {
    state.token = "";
    sessionStorage.removeItem(TOKEN_KEY);
    if (state.timer) window.clearInterval(state.timer);
    showLogin(showMessage ? "Sesi lokal telah diakhiri." : "");
  }

  async function login(token) {
    state.token = token;
    await request("/api/login", { method: "POST", body: JSON.stringify({ token }) });
    sessionStorage.setItem(TOKEN_KEY, token);
    loginScreen.classList.add("hidden");
    appShell.classList.remove("hidden");
    text(loginError, "");
    await refreshAll();
    if (state.timer) window.clearInterval(state.timer);
    state.timer = window.setInterval(refreshLive, 2800);
  }

  function goto(page) {
    const valid = ["overview", "scan", "reports", "logs", "tools", "terminal", "scope"].includes(page) ? page : "overview";
    $$(".page-view").forEach((item) => item.classList.toggle("hidden", item.dataset.view !== valid));
    $$(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.page === valid));
    const names = { overview: "IKHTISAR", scan: "PEMINDAIAN", reports: "LAPORAN", logs: "LOG AKTIVITAS", tools: "ARSENAL", terminal: "TERMINAL VPS", scope: "SCOPE & PROXY" };
    text($("#pageCrumb"), names[valid]);
    const view = document.querySelector(`[data-view="${valid}"]`);
    const heading = view ? view.querySelector("h1") : null;
    if (heading) {
      heading.classList.remove("glitch-hit");
      void heading.offsetWidth;
      heading.classList.add("glitch-hit");
    }
    history.replaceState(null, "", `#${valid}`);
    if (valid === "scope") { loadScope(); loadProxies(); }
    if (valid === "tools") loadTools();
    if (valid === "reports") loadReports();
    if (valid === "logs") loadLogs();
    if (valid === "scan") refreshOutput();
    if (valid === "terminal") refreshShellOutput();
  }

  function addOption(select, value, label, selected = false) {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = label;
    option.selected = selected;
    select.appendChild(option);
  }

  function fillSelect(select, entries, placeholder, prefer = "") {
    if (!select) return;
    const prior = select.value;
    const selected = entries.includes(prior) ? prior : prefer;
    select.replaceChildren();
    addOption(select, "", placeholder, !selected);
    entries.forEach((item) => addOption(select, item, item, item === selected));
  }

  function fillArchiveSelect(select, items, placeholder, prefer = "") {
    if (!select) return "";
    const prior = select.value;
    const selected = items.some((item) => item.id === prior) ? prior : items.some((item) => item.id === prefer) ? prefer : (items[0] && items[0].id) || "";
    select.replaceChildren();
    addOption(select, "", placeholder, !selected);
    items.forEach((item) => addOption(select, item.id, item.label, item.id === selected));
    select.disabled = items.length === 0;
    return selected;
  }

  function fillFileSelect(select, files, placeholder, prefer = "") {
    const items = files.map((file) => ({
      id: file.id,
      label: `${file.name} · ${formatBytes(file.size)}`,
    }));
    return fillArchiveSelect(select, items, placeholder, prefer);
  }

  function formatBytes(value) {
    const size = Number(value) || 0;
    if (size < 1024) return `${size} B`;
    if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
    return `${(size / (1024 * 1024)).toFixed(1)} MB`;
  }

  async function refreshAll() {
    await Promise.all([loadStatus(), loadScope(), loadTools(), loadProxies()]);
    await Promise.all([refreshOutput(), refreshShellOutput(), loadPassiveSummary()]);
  }

  const PASSIVE_SOURCE_LABELS = {
    crtsh: "crt.sh", certspotter: "Cert Spotter", wayback: "Wayback", wayback_urls: "Wayback URL",
    otx: "OTX", anubis: "Anubis", rapiddns: "RapidDNS", commoncrawl_urls: "Common Crawl",
  };

  function passiveTarget() {
    const report = $("#reportTarget");
    const chosen = report && report.value ? report.value : "";
    return chosen || (state.targets[0] && state.targets[0].domain) || "";
  }

  function renderPassive(summary) {
    text($("#passiveCollected"), summary.collected_at ? `Snapshot ${String(summary.collected_at).replace("T", " ").slice(0, 19)} UTC` : "—");
    const chips = $("#passiveSourceChips");
    if (chips) {
      chips.replaceChildren();
      const entries = Object.entries(summary.sources || {});
      if (!entries.length) {
        const empty = document.createElement("div");
        empty.className = "empty-inline";
        empty.textContent = "Snapshot belum menyertakan rincian sumber.";
        chips.appendChild(empty);
      }
      entries.forEach(([key, value]) => {
        const chip = document.createElement("span");
        chip.className = `passive-source-chip${Number(value) > 0 ? " chip-hot" : ""}`;
        chip.textContent = `${PASSIVE_SOURCE_LABELS[key] || key} · ${value}`;
        chips.appendChild(chip);
      });
    }
    text($("#passiveSubdomains"), summary.subdomains ?? 0);
    text($("#passiveLive"), summary.live_subdomains ?? 0);
    text($("#passiveArchived"), summary.archived_urls ?? 0);
    text($("#passiveJs"), `${summary.js_scanned ?? 0} / ${summary.js_secrets ?? 0}`);
    const axfrNode = $("#passiveAxfr");
    text(axfrNode, summary.axfr ? "BOCOR" : "AMAN");
    if (axfrNode) axfrNode.classList.toggle("axfr-hot", !!summary.axfr);
    const dmarcNode = $("#passiveDmarc");
    text(dmarcNode, summary.dmarc ? "AKTIF" : "HILANG");
    if (dmarcNode) dmarcNode.classList.toggle("dmarc-missing", !summary.dmarc);
    const tlsFailed = Number(summary.tls_failed) || 0;
    const tlsNode = $("#passiveTls");
    text(tlsNode, tlsFailed);
    if (tlsNode) tlsNode.classList.toggle("axfr-hot", tlsFailed > 0);
    text($("#passiveRobots"), Number(summary.robots_paths) || 0);
    text($("#passiveNote"), summary.axfr
      ? `AXFR berhasil di ${summary.axfr_ns || "nameserver"} — zona DNS bocor. Laporkan ke program dan tutup transfer.`
      : "Panel memakai snapshot toolkit terbaru dari data/history.");
  }

  async function loadPassiveSummary() {
    const target = passiveTarget();
    if (!target) return;
    try {
      const data = await request(`/api/passive/summary?target=${encodeURIComponent(target)}`);
      renderPassive(data.summary || {});
    } catch (error) {
      const chips = $("#passiveSourceChips");
      if (chips) {
        chips.replaceChildren();
        const empty = document.createElement("div");
        empty.className = "empty-inline";
        empty.textContent = error.message;
        chips.appendChild(empty);
      }
    }
  }

  async function loadStatus() {
    const data = await request("/api/status");
    state.scanRunning = !!data.scan_running;
    if (state.scanId !== null && data.scan && data.scan.id !== state.scanId) appendOutput([], true);
    if (data.scan) state.scanId = data.scan.id;
    state.targets = data.targets || [];
    const latest = data.latest_target || "";
    text($("#hostLabel"), data.host_type || "LOCAL HOST");
    text($("#metricTarget"), latest || "—");
    text($("#metricTargetNote"), latest ? "Laporan tersedia" : "Belum ada run");
    text($("#metricFindings"), data.findings ?? 0);
    text($("#metricTools"), data.tools_installed ?? 0);
    text($("#metricToolsTotal"), `/ ${data.tools_total ?? 0}`);
    text($("#metricProxies"), data.proxy_count ?? 0);
    text($("#metricProxyNote"), data.proxy_rotate ? "Rotasi aktif" : "Rotasi nonaktif");
    const targets = state.targets.map((item) => item.domain);
    fillSelect($("#reportTarget"), targets, "Pilih target", latest);
    fillSelect($("#logTarget"), targets, "Pilih target", latest);
    renderTargetList(state.targets);
    updateScanBadge(data.scan);
    text($("#connectionText"), data.scan_running ? "Scan berjalan" : "Backend lokal");
  }

  function renderTargetList(targets) {
    const list = $("#targetList");
    list.replaceChildren();
    $("#emptyRuns").classList.toggle("hidden", targets.length > 0);
    if (!targets.length) return;
    targets.slice(0, 5).forEach((item, index) => {
      const row = document.createElement("button");
      row.className = "target-row";
      row.type = "button";
      const ordinal = document.createElement("span");
      ordinal.className = "target-ordinal";
      ordinal.textContent = String(index + 1).padStart(2, "0");
      const dot = document.createElement("i");
      dot.className = "target-dot";
      const name = document.createElement("span");
      name.className = "target-name";
      name.textContent = item.domain;
      const date = document.createElement("small");
      date.className = "target-date";
      date.textContent = item.updated ? new Date(item.updated).toLocaleDateString("id-ID", { day: "2-digit", month: "short", year: "numeric" }) : "—";
      const arrow = document.createElement("span");
      arrow.className = "target-arrow";
      arrow.textContent = "↗";
      row.append(ordinal, dot, name, date, arrow);
      row.addEventListener("click", () => {
        $("#reportTarget").value = item.domain;
        goto("reports");
        loadReports();
      });
      list.appendChild(row);
    });
  }

  function updateScanBadge(scan) {
    const active = scan && scan.status === "running";
    $("#scanCurrent").classList.toggle("hidden", !active);
    if (active) {
      text($("#currentScanTitle"), `${scan.target} · ${scan.mode === "passive" ? "Passive" : "Full pipeline"}`);
      text($("#currentScanDetail"), `Dimulai ${scan.started_at ? new Date(scan.started_at).toLocaleTimeString("id-ID") : "baru saja"} · output live`);
    }
    text($("#consoleStatus"), active ? `Berjalan · ${scan.target}` : scan && scan.status === "completed" ? "Scan selesai" : scan && scan.status === "failed" ? "Scan berakhir dengan error" : "Menunggu scan");
    $("#consoleIndicator").classList.toggle("console-running", !!active);
  }

  async function loadScope() {
    try {
      const data = await request("/api/scope");
      state.scope = data.domains || [];
      renderScope(data);
      fillSelect($("#scanTarget"), state.scope, state.scope.length ? "Pilih domain scope…" : "Tambahkan domain scope dahulu");
      fillSelect($("#arsenalTarget"), state.scope, state.scope.length ? "Pilih domain scope…" : "Belum ada domain scope");
      if (state.arsenal.length) renderArsenal();
    } catch (error) { toast(error.message, "error"); }
  }

  function renderScope(data) {
    const list = $("#scopeList");
    list.replaceChildren();
    text($("#scopeCount"), data.domains.length);
    if (!data.domains.length) {
      const empty = document.createElement("div"); empty.className = "empty-inline"; empty.textContent = "Belum ada domain scope."; list.appendChild(empty);
    }
    data.domains.forEach((domain) => {
      const row = document.createElement("div"); row.className = "scope-row";
      const mark = document.createElement("span"); mark.className = "scope-row-mark"; mark.textContent = "◎";
      const name = document.createElement("b"); name.textContent = domain;
      const status = document.createElement("span"); status.className = "scope-live"; status.textContent = "AKTIF";
      const remove = document.createElement("button"); remove.className = "scope-remove"; remove.type = "button"; remove.textContent = "×"; remove.setAttribute("aria-label", `Hapus ${domain} dari scope`);
      remove.addEventListener("click", () => changeScope("remove", domain));
      row.append(mark, name, status, remove); list.appendChild(row);
    });
    const exclusions = $("#exclusionList");
    exclusions.replaceChildren();
    if (!data.exclusions.length) {
      const empty = document.createElement("div"); empty.className = "empty-inline"; empty.textContent = "Tidak ada pengecualian tercatat."; exclusions.appendChild(empty);
    }
    data.exclusions.forEach((domain) => {
      const row = document.createElement("div"); row.className = "exclusion-row";
      const mark = document.createElement("span"); mark.textContent = "−";
      const name = document.createElement("b"); name.textContent = domain;
      row.append(mark, name); exclusions.appendChild(row);
    });
  }

  async function changeScope(action, domain) {
    const verb = action === "add" ? "menambahkan" : "menghapus";
    if (!window.confirm(`Konfirmasi ${verb} ${domain} ${action === "add" ? "ke" : "dari"} allowlist? Perubahan scope memengaruhi domain yang dapat dipindai.`)) return;
    try {
      const data = await request("/api/scope", { method: "POST", body: JSON.stringify({ action, domain, authorized: true }) });
      state.scope = data.domains || [];
      renderScope(data);
      fillSelect($("#scanTarget"), state.scope, state.scope.length ? "Pilih domain scope…" : "Tambahkan domain scope dahulu");
      fillSelect($("#arsenalTarget"), state.scope, state.scope.length ? "Pilih domain scope…" : "Belum ada domain scope");
      if (state.arsenal.length) renderArsenal();
      toast(action === "add" ? `${domain} ditambahkan ke scope.` : `${domain} dihapus dari scope.`, "success");
      await loadStatus();
    } catch (error) { toast(error.message, "error"); }
  }

  async function loadProxies() {
    try {
      const data = await request("/api/proxies");
      text($("#proxyCountBig"), data.count);
      text($("#proxyState"), data.count ? "TERKONFIGURASI" : "BELUM ADA");
      text($("#proxyFileLabel"), data.file_label || "state/proxies.txt");
      text($("#proxyHelpText"), `${data.rotate ? "Rotasi diaktifkan" : "Rotasi dinonaktifkan"} · ${data.required ? "pipeline menolak run tanpa proxy" : "proxy opsional"}.`);
      $("#proxyEntries").value = data.editor_value || "";
      $("#proxyEntries").disabled = !data.editable;
      $("#saveProxies").disabled = !data.editable;
    } catch (error) { toast(error.message, "error"); }
  }

  async function loadTools() {
    try {
      const [data, arsenal] = await Promise.all([request("/api/tools"), request("/api/arsenal")]);
      text($("#toolSummaryCount"), data.installed);
      text($("#toolSummaryTotal"), data.total);
      const percent = data.total ? Math.round((data.installed / data.total) * 100) : 0;
      $(".meter-track").dataset.percent = String(Math.round(percent / 10) * 10);
      text($("#toolPercent"), `${percent}%`);
      const groups = new Map();
      (data.tools || []).forEach((tool) => {
        if (!groups.has(tool.group)) groups.set(tool.group, []);
        groups.get(tool.group).push(tool);
      });
      const grid = $("#toolGrid"); grid.replaceChildren();
      groups.forEach((tools, group) => {
        const card = document.createElement("article"); card.className = "panel tool-card";
        const head = document.createElement("div"); head.className = "tool-card-head";
        const name = document.createElement("h3"); name.textContent = group;
        const total = document.createElement("span"); total.textContent = `${tools.filter((item) => item.installed).length}/${tools.length}`;
        head.append(name, total); card.appendChild(head);
        tools.forEach((tool) => {
          const row = document.createElement("div"); row.className = "tool-row";
          const mark = document.createElement("i"); mark.className = tool.installed ? "tool-mark tool-installed" : "tool-mark";
          const label = document.createElement("span"); label.textContent = tool.name;
          const status = document.createElement("small"); status.className = tool.installed ? "tool-ok" : "tool-missing"; status.textContent = tool.installed ? "TERSEDIA" : "BELUM ADA";
          row.append(mark, label, status); card.appendChild(row);
        });
        grid.appendChild(card);
      });
      state.arsenal = arsenal.items || [];
      text($("#arsenalCount"), `${arsenal.installed}/${arsenal.total}`);
      fillSelect($("#arsenalTarget"), state.scope, state.scope.length ? "Pilih domain scope…" : "Belum ada domain scope");
      renderArsenal();
    } catch (error) { toast(error.message, "error"); }
  }

  const ARSENAL_LABELS = { crawl: "CRAWL", audit: "AUDIT", param: "PARAMETER", recon: "RECON", port: "PORT/TLS" };

  function arsenalTarget() {
    const node = $("#arsenalTarget");
    return node ? node.value.trim() : "";
  }

  async function copyText(value, description) {
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
      toast(`${description} disalin ke clipboard.`, "success");
    } catch (_error) {
      toast("Browser menolak clipboard. Salin manual dari kartu perintah.", "error");
    }
  }

  function sendToTerminal(template) {
    const target = arsenalTarget();
    if (!target) { toast("Pilih target scope pada bilah Arsenal lebih dulu.", "error"); return; }
    const command = String(template || "").replace(/\{\{TARGET\}\}/g, target).trim();
    if (!command) return;
    const field = $("#shellCommand");
    if (!field) return;
    field.value = command;
    goto("terminal");
    toast("Perintah ditempel ke terminal. Periksa dulu sebelum dijalankan.", "success");
    window.setTimeout(() => field.focus(), 140);
  }

  function arsenalCode(label, display) {
    const box = document.createElement("div"); box.className = "arsenal-code";
    const head = document.createElement("div"); head.className = "arsenal-code-head";
    const tag = document.createElement("span"); tag.className = "arsenal-code-label"; tag.textContent = label;
    const copy = document.createElement("button"); copy.type = "button"; copy.className = "arsenal-copy"; copy.textContent = "SALIN";
    copy.addEventListener("click", () => copyText(display, label === "PASANG" ? "Perintah pasang" : "Perintah uji"));
    head.append(tag, copy);
    const code = document.createElement("code"); code.textContent = display;
    box.append(head, code);
    return box;
  }

  function renderArsenal() {
    const chips = $("#arsenalChips");
    const grid = $("#arsenalGrid");
    if (!chips || !grid) return;
    const items = state.arsenal || [];
    chips.replaceChildren();
    const categories = [];
    items.forEach((item) => { if (!categories.includes(item.category)) categories.push(item.category); });
    const entries = [["all", `SEMUA · ${items.length}`]];
    categories.forEach((category) => {
      const count = items.filter((item) => item.category === category).length;
      entries.push([category, `${ARSENAL_LABELS[category] || category.toUpperCase()} · ${count}`]);
    });
    entries.forEach(([value, label]) => {
      const chip = document.createElement("button");
      chip.type = "button";
      chip.className = `arsenal-chip${state.arsenalFilter === value ? " active" : ""}`;
      chip.textContent = label;
      chip.addEventListener("click", () => { state.arsenalFilter = value; renderArsenal(); });
      chips.appendChild(chip);
    });
    text($("#arsenalFilterLabel"), state.arsenalFilter === "all" ? "SEMUA" : (ARSENAL_LABELS[state.arsenalFilter] || state.arsenalFilter.toUpperCase()));
    const target = arsenalTarget() || "{{TARGET}}";
    const visible = items.filter((item) => state.arsenalFilter === "all" || item.category === state.arsenalFilter);
    grid.replaceChildren();
    if (!visible.length) {
      const empty = document.createElement("div"); empty.className = "empty-inline"; empty.textContent = "Katalog arsenal belum dimuat dari backend lokal.";
      grid.appendChild(empty);
      return;
    }
    visible.forEach((item) => {
      const card = document.createElement("article");
      card.className = "arsenal-card";
      card.dataset.state = item.installed ? "ready" : "missing";
      const head = document.createElement("header");
      const category = document.createElement("span"); category.className = "arsenal-cat"; category.textContent = ARSENAL_LABELS[item.category] || item.category;
      const name = document.createElement("h4"); name.textContent = item.name;
      const status = document.createElement("span"); status.className = "arsenal-state"; status.textContent = item.installed ? "READY" : "MISSING";
      head.append(category, name, status);
      const summary = document.createElement("p"); summary.textContent = item.summary;
      card.append(head, summary);
      card.appendChild(arsenalCode("PASANG", item.install || "—"));
      card.appendChild(arsenalCode("JALANKAN", String(item.usage || "").replace(/\{\{TARGET\}\}/g, target)));
      const send = document.createElement("button");
      send.type = "button"; send.className = "arsenal-send"; send.textContent = "Kirim ke terminal →";
      send.addEventListener("click", () => sendToTerminal(item.usage));
      card.appendChild(send);
      grid.appendChild(card);
    });
  }

  function startClock() {
    const node = $("#opClock");
    if (!node) return;
    const paint = () => {
      node.textContent = new Date().toLocaleTimeString("en-GB", { hour12: false });
    };
    paint();
    if (state.clock) window.clearInterval(state.clock);
    state.clock = window.setInterval(paint, 1000);
  }

  const TICKER_LINES = [
    "// exclusion selalu menang atas allowlist — periksa sebelum setiap run",
    "// rotasi proxy berlaku per stage; DNS dan nmap tetap langsung dari host",
    "// temuan hanya dicatat confirmed bila ada dua sinyal independen",
    "// semua output tetap tersimpan di mesin ini, tidak pernah di cloud",
    "// jangan menaikkan rate di luar batas yang diizinkan program bounty",
  ];

  function startTicker() {
    const node = $("#opTickerText");
    if (!node) return;
    let index = 0;
    const paint = () => {
      node.textContent = TICKER_LINES[index % TICKER_LINES.length];
      index += 1;
    };
    paint();
    window.setInterval(paint, 7000);
  }

  function startBootLog() {
    const node = $("#bootLog");
    if (!node) return;
    const lines = [
      "[ 0.001 ] mount //blacksite .......... ok",
      "[ 0.284 ] scope guard ................ armed",
      "[ 0.612 ] exclusion list ............. loaded",
      "[ 0.905 ] proxy mesh ................. standby",
      "[ 1.104 ] awaiting operator token _",
    ];
    node.textContent = "";
    let index = 0;
    if (state.boot) window.clearInterval(state.boot);
    state.boot = window.setInterval(() => {
      if (index >= lines.length) { window.clearInterval(state.boot); state.boot = null; return; }
      node.textContent = `${node.textContent}${lines[index]}\n`;
      index += 1;
    }, 260);
  }

  function startMatrix() {
    const canvas = $("#matrixCanvas");
    if (!canvas || typeof canvas.getContext !== "function") return;
    const context = canvas.getContext("2d");
    if (!context) return;
    const glyphs = "01ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉ#$%&@!?<>/\\|=+*";
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)");
    let step = 16;
    let drops = [];
    const resize = () => {
      const ratio = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = Math.max(1, Math.floor(window.innerWidth * ratio));
      canvas.height = Math.max(1, Math.floor(window.innerHeight * ratio));
      step = 16 * ratio;
      const columns = Math.max(1, Math.ceil(canvas.width / step));
      drops = Array.from({ length: columns }, () => Math.random() * -40);
    };
    const paint = () => {
      context.fillStyle = "rgba(3, 6, 3, 0.14)";
      context.fillRect(0, 0, canvas.width, canvas.height);
      context.font = `${Math.round(step)}px ui-monospace, monospace`;
      for (let index = 0; index < drops.length; index += 1) {
        const glyph = glyphs.charAt(Math.floor(Math.random() * glyphs.length));
        const y = drops[index] * step;
        context.fillStyle = Math.random() > 0.985 ? "#e6ffe0" : "#39ff14";
        context.fillText(glyph, index * step, y);
        drops[index] = y > canvas.height ? 0 : drops[index] + 1;
      }
    };
    resize();
    window.addEventListener("resize", resize);
    paint();
    if (reduced.matches) return;
    window.setInterval(() => { if (!document.hidden) paint(); }, 95);
  }

  function archiveUrl(endpoint, target, kind, collection = "", file = "") {
    const params = new URLSearchParams({ target, kind });
    if (collection) params.set("collection", collection);
    if (file) params.set("file", file);
    return `/api/${endpoint}?${params.toString()}`;
  }

  async function loadReports() {
    const serial = ++state.reportLoadSerial;
    const target = $("#reportTarget").value;
    if (!target) {
      fillArchiveSelect($("#reportRun"), [], "Pilih run laporan");
      await loadReportFiles("");
      return;
    }
    try {
      const data = await request(archiveUrl("runs", target, "reports"));
      if (serial !== state.reportLoadSerial) return;
      const collection = fillArchiveSelect($("#reportRun"), data.items || [], "Pilih run laporan");
      await loadReportFiles(collection);
    } catch (error) { if (serial === state.reportLoadSerial) toast(error.message, "error"); }
  }

  async function loadReportFiles(collection = $("#reportRun").value) {
    const serial = ++state.reportLoadSerial;
    const target = $("#reportTarget").value;
    const list = $("#reportList");
    state.selectedReport = null;
    $("#downloadReport").disabled = true;
    if (!target || !collection) {
      list.replaceChildren();
      const empty = document.createElement("div"); empty.className = "empty-inline"; empty.textContent = "Belum ada riwayat laporan untuk target ini."; list.appendChild(empty);
      state.selectedReport = null;
      text($("#reportFileName"), "BELUM ADA DOKUMEN"); text($("#reportContent"), "Laporan belum tersedia."); $("#downloadReport").disabled = true;
      return;
    }
    list.replaceChildren();
    const loading = document.createElement("div"); loading.className = "empty-inline"; loading.textContent = "Memuat daftar file laporan…"; list.appendChild(loading);
    try {
      const data = await request(archiveUrl("files", target, "reports", collection));
      if (serial !== state.reportLoadSerial) return;
      state.reports = data.files || [];
      state.selectedReport = null;
      list.replaceChildren();
      if (!state.reports.length) {
        const empty = document.createElement("div"); empty.className = "empty-inline"; empty.textContent = "Tidak ada file laporan pada koleksi ini."; list.appendChild(empty);
        text($("#reportFileName"), "BELUM ADA DOKUMEN"); text($("#reportContent"), "Laporan belum tersedia."); $("#downloadReport").disabled = true; return;
      }
      state.reports.forEach((file, index) => {
        const button = document.createElement("button"); button.className = `report-item${index === 0 ? " active" : ""}`; button.type = "button";
        const icon = document.createElement("span"); icon.className = `report-type report-type-${file.name.split(".").pop()}`; icon.textContent = file.name.endsWith(".json") ? "{}" : "▤";
        const title = document.createElement("span"); title.className = "report-item-title"; title.textContent = `${file.name} · ${formatBytes(file.size)}`;
        const arrow = document.createElement("i"); arrow.textContent = "↗";
        button.append(icon, title, arrow);
        button.addEventListener("click", () => selectReport(file, button, collection));
        list.appendChild(button);
      });
      await selectReport(state.reports[0], $(".report-item", list), collection);
    } catch (error) { toast(error.message, "error"); }
  }

  async function selectReport(file, button, collection = $("#reportRun").value) {
    const serial = ++state.reportLoadSerial;
    const selected = { ...file, collection, kind: "reports" };
    state.selectedReport = selected;
    $$(".report-item").forEach((item) => item.classList.toggle("active", item === button));
    text($("#reportFileName"), `${file.name.toUpperCase()} · MEMUAT`);
    text($("#reportContent"), "Memuat isi file laporan…");
    $("#downloadReport").disabled = true;
    try {
      const data = await request(archiveUrl("file", $("#reportTarget").value, "reports", collection, file.id));
      if (serial !== state.reportLoadSerial) return;
      state.selectedReport = { ...selected, name: data.name };
      text($("#reportFileName"), `${data.name.toUpperCase()} · LOKAL · KREDENSIAL DISAMARKAN`);
      text($("#reportContent"), data.content || "File kosong.");
      $("#downloadReport").disabled = false;
    } catch (error) {
      if (serial === state.reportLoadSerial) { text($("#reportContent"), error.message); toast(error.message, "error"); }
    }
  }

  async function downloadArchive(kind, selected) {
    if (!selected) return;
    const url = archiveUrl("download", kind === "reports" ? $("#reportTarget").value : $("#logTarget").value, kind, selected.collection, selected.id);
    const headers = new Headers();
    if (state.token) headers.set("Authorization", `Bearer ${state.token}`);
    let response;
    try { response = await fetch(url, { headers, cache: "no-store", credentials: "omit" }); }
    catch (_error) { throw new Error("Backend lokal tidak merespons."); }
    if (!response.ok) {
      let payload = {};
      try { payload = await response.json(); } catch (_error) { /* handled below */ }
      if (response.status === 401) signOut(false);
      throw new Error(payload.error || `Unduhan gagal (${response.status}).`);
    }
    const blob = await response.blob();
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = selected.name;
    link.click();
    window.setTimeout(() => URL.revokeObjectURL(link.href), 1000);
  }

  async function downloadReport() {
    try { await downloadArchive("reports", state.selectedReport); }
    catch (error) { toast(error.message, "error"); }
  }

  function formatDuration(seconds) {
    const total = Number(seconds) || 0;
    if (total <= 0) return "—";
    if (total < 60) return `${total}s`;
    const minutes = Math.floor(total / 60);
    const rest = total % 60;
    return rest ? `${minutes}m ${rest}s` : `${minutes}m`;
  }

  function renderStages(stages) {
    const rows = $("#stageRows"); rows.replaceChildren();
    text($("#stageCount"), `${stages.length} stage`);
    if (!stages.length) {
      const tr = document.createElement("tr"); const td = document.createElement("td"); td.colSpan = 4; td.className = "table-empty"; td.textContent = "Tidak ada ringkasan stage untuk koleksi ini."; tr.appendChild(td); rows.appendChild(tr); return;
    }
    const slowest = stages.reduce((best, stage) => ((stage.duration || 0) > (best.duration || 0) ? stage : best), stages[0]);
    stages.forEach((stage) => {
      const tr = document.createElement("tr");
      const name = document.createElement("td"); name.className = "stage-name"; name.textContent = stage.name;
      const status = document.createElement("td");
      const chip = document.createElement("span"); chip.className = `stage-chip stage-${stage.status}`; chip.textContent = stage.status.toUpperCase(); status.appendChild(chip);
      const duration = document.createElement("td"); duration.className = "stage-duration"; duration.textContent = formatDuration(stage.duration);
      const note = document.createElement("td"); note.className = "stage-note"; note.textContent = stage.note || "—";
      if (stage === slowest && (stage.duration || 0) > 0) {
        tr.classList.add("stage-slowest");
        duration.title = "Stage paling lama pada run ini";
      }
      tr.append(name, status, duration, note); rows.appendChild(tr);
    });
  }

  async function loadLogs() {
    const serial = ++state.logLoadSerial;
    const target = $("#logTarget").value;
    if (!target) {
      fillArchiveSelect($("#logRun"), [], "Pilih run log");
      await loadLogFiles("");
      return;
    }
    try {
      const data = await request(archiveUrl("runs", target, "logs"));
      if (serial !== state.logLoadSerial) return;
      const collection = fillArchiveSelect($("#logRun"), data.items || [], "Pilih run log");
      await loadLogFiles(collection);
    } catch (error) { if (serial === state.logLoadSerial) toast(error.message, "error"); }
  }

  async function loadLogFiles(collection = $("#logRun").value) {
    const serial = ++state.logLoadSerial;
    const target = $("#logTarget").value;
    state.selectedLog = null;
    $("#downloadLog").disabled = true;
    if (!target || !collection) {
      fillFileSelect($("#logFile"), [], "Pilih file log");
      state.selectedLog = null; $("#downloadLog").disabled = true;
      renderStages([]); text($("#logCaption"), "Tidak ada run atau file log."); text($("#logContent"), "Belum ada log untuk target ini.");
      return;
    }
    try {
      const [filesData, logData] = await Promise.all([
        request(archiveUrl("files", target, "logs", collection)),
        request(`/api/logs?${new URLSearchParams({ target, run: collection })}`),
      ]);
      if (serial !== state.logLoadSerial) return;
      const files = filesData.files || [];
      const fileId = fillFileSelect($("#logFile"), files, "Pilih file log");
      renderStages(logData.stages || []);
      text($("#logCaption"), `${target} · ${collection === "toolkit" ? "log global/rotasi, bukan per-run" : collection}`);
      if (!fileId) {
        state.selectedLog = null; $("#downloadLog").disabled = true;
        text($("#logContent"), "Tidak ada file log yang tersedia pada koleksi ini.");
        return;
      }
      await loadLogDetails(collection, fileId);
    } catch (error) { if (serial === state.logLoadSerial) toast(error.message, "error"); }
  }

  async function loadLogDetails(collection = $("#logRun").value, fileId = $("#logFile").value) {
    const target = $("#logTarget").value;
    if (!target || !collection || !fileId) return;
    const serial = ++state.logLoadSerial;
    try {
      const file = $("#logFile").selectedOptions[0];
      const selected = { id: fileId, name: file ? file.textContent.split(" · ")[0] : fileId, collection, kind: "logs" };
      const data = await request(archiveUrl("file", target, "logs", collection, fileId));
      if (serial !== state.logLoadSerial) return;
      state.selectedLog = { ...selected, name: data.name };
      text($("#logContent"), data.content || "File log kosong.");
      $("#downloadLog").disabled = false;
    } catch (error) {
      if (serial === state.logLoadSerial) { text($("#logContent"), error.message); toast(error.message, "error"); }
    }
  }

  async function downloadLog() {
    try { await downloadArchive("logs", state.selectedLog); }
    catch (error) { toast(error.message, "error"); }
  }

  function appendOutput(lines, reset = false) {
    const output = $("#scanOutput");
    if (reset) { output.replaceChildren(); state.outputSeq = 0; }
    const placeholder = $(".console-placeholder", output);
    if (placeholder && lines.length) placeholder.remove();
    lines.forEach((item) => {
      const line = document.createElement("span");
      line.className = "console-line";
      line.textContent = item.line;
      output.appendChild(line);
      output.appendChild(document.createTextNode("\n"));
      state.outputSeq = Math.max(state.outputSeq, item.seq);
    });
    if (lines.length) output.scrollTop = output.scrollHeight;
  }

  async function refreshOutput() {
    try {
      const data = await request(`/api/scan/output?after=${state.outputSeq}`);
      if (state.scanId && data.scan_id !== state.scanId) appendOutput([], true);
      state.scanId = data.scan_id;
      appendOutput(data.lines || []);
    } catch (_error) { /* status poll presents the connection error */ }
  }

  function appendShellOutput(lines, reset = false) {
    const output = $("#shellOutput");
    if (reset) { output.replaceChildren(); state.shellSeq = 0; }
    const placeholder = $(".console-placeholder", output);
    if (placeholder && lines.length) placeholder.remove();
    lines.forEach((item) => {
      const line = document.createElement("span");
      line.className = "console-line";
      line.textContent = item.line;
      output.appendChild(line);
      output.appendChild(document.createTextNode("\n"));
      state.shellSeq = Math.max(state.shellSeq, item.seq);
    });
    if (lines.length) output.scrollTop = output.scrollHeight;
  }

  async function refreshShellOutput() {
    try {
      const data = await request(`/api/shell?after=${state.shellSeq}`);
      if (state.shellId !== data.shell.id) {
        appendShellOutput([], true);
        state.shellId = data.shell.id;
      }
      state.shellEnabled = data.enabled === true;
      state.shellRunning = data.shell.status === "running";
      appendShellOutput(data.lines || []);
      $("#shellIndicator").classList.toggle("console-running", state.shellRunning);
      $("#runShell").disabled = !state.shellEnabled || state.scanRunning || state.shellRunning;
      $("#stopShell").disabled = !state.shellRunning;
      if (!state.shellEnabled) text($("#shellStatus"), "Nonaktif · perlu opt-in dan bind localhost");
      else if (state.scanRunning) text($("#shellStatus"), "Dikunci selama scan dashboard");
      else if (state.shellRunning) text($("#shellStatus"), "Perintah berjalan di VPS");
      else if (data.shell.status === "completed") text($("#shellStatus"), "Perintah selesai · exit 0");
      else if (data.shell.status === "failed") text($("#shellStatus"), `Perintah gagal · exit ${data.shell.return_code ?? "?"}`);
      else text($("#shellStatus"), "Siap · command shell aktif");
    } catch (error) {
      state.shellEnabled = false;
      state.shellRunning = false;
      $("#runShell").disabled = true;
      $("#stopShell").disabled = true;
      text($("#shellStatus"), error.message.includes("Endpoint tidak ditemukan") ? "Backend belum diperbarui; update dan restart dashboard" : error.message);
    }
  }

  async function refreshLive() {
    try {
      await loadStatus();
      await Promise.all([refreshOutput(), refreshShellOutput()]);
      if (!document.querySelector('[data-view="overview"]') || document.querySelector('[data-view="overview"]:not(.hidden)')) await loadPassiveSummary();
      if ($("#logTarget").value && document.querySelector('[data-view="logs"]:not(.hidden)')) await loadLogs();
    } catch (error) {
      text($("#connectionText"), "Backend terputus");
      toast(error.message, "error");
    }
  }

  async function startScan(mode) {
    const target = $("#scanTarget").value;
    try {
      const result = await request("/api/scan", { method: "POST", body: JSON.stringify({ target, mode, authorized: true }) });
      state.scanId = result.scan.id;
      appendOutput([], true);
      $("#scanDialog").close();
      toast(`Scan ${target} dimulai pada mesin lokal.`, "success");
      goto("scan");
      await refreshLive();
    } catch (error) { $("#scanDialog").close(); toast(error.message, "error"); }
  }

  async function stopScan() {
    if (!window.confirm("Hentikan scan yang sedang berjalan beserta proses tool turunannya?")) return;
    try { await request("/api/scan/stop", { method: "POST", body: "{}" }); toast("Permintaan berhenti dikirim.", "success"); }
    catch (error) { toast(error.message, "error"); }
  }

  async function startShell(event) {
    event.preventDefault();
    const command = $("#shellCommand").value.trim();
    const cwd = $("#shellCwd").value.trim() || "/";
    if (!command) return;
    sessionStorage.setItem("reconpro-shell-cwd", cwd);
    if (!window.confirm(`Shell ini berjalan dengan hak akun Linux dashboard, dimulai dari ${cwd}, dan melewati scope check UI. Jalankan hanya command yang Anda pahami pada sistem yang berwenang Anda kelola. Lanjutkan?`)) return;
    $("#runShell").disabled = true;
    try {
      const result = await request("/api/shell/start", { method: "POST", body: JSON.stringify({ command, cwd, acknowledged: true }) });
      state.shellId = result.shell.id;
      state.shellSeq = 0;
      state.shellRunning = true;
      const output = $("#shellOutput");
      output.replaceChildren();
      const entered = document.createElement("span");
      entered.className = "console-line";
      entered.textContent = `${cwd} $ ${command}`;
      output.append(entered, document.createTextNode("\n"));
      $("#shellCommand").value = "";
      await refreshShellOutput();
      toast("Command dijalankan pada VPS.", "success");
    } catch (error) {
      toast(error.message, "error");
      await refreshShellOutput();
    }
  }

  async function stopShell() {
    if (!window.confirm("Hentikan command shell dan seluruh proses turunannya?")) return;
    try {
      await request("/api/shell/stop", { method: "POST", body: "{}" });
      toast("Sinyal berhenti dikirim ke command shell.", "success");
    } catch (error) { toast(error.message, "error"); }
  }

  async function saveProxies() {
    if (!window.confirm("Simpan ulang seluruh daftar proxy? Baris yang ada akan diganti dengan isi editor.")) return;
    try {
      await request("/api/proxies", { method: "POST", body: JSON.stringify({ proxies: $("#proxyEntries").value, confirm: true }) });
      await loadProxies(); await loadStatus(); toast("Daftar proxy tersimpan dengan izin file privat.", "success");
    } catch (error) { toast(error.message, "error"); }
  }

  function bindEvents() {
    const savedShellCwd = sessionStorage.getItem("reconpro-shell-cwd");
    if (savedShellCwd) $("#shellCwd").value = savedShellCwd;
    $("#shellCwd").addEventListener("input", () => sessionStorage.setItem("reconpro-shell-cwd", $("#shellCwd").value));
    $("#loginForm").addEventListener("submit", async (event) => {
      event.preventDefault();
      text(loginError, "Memeriksa token…");
      try { await login($("#accessToken").value.trim()); }
      catch (error) { state.token = ""; text(loginError, error.message); }
    });
    $("#toggleToken").addEventListener("click", () => {
      const input = $("#accessToken"); input.type = input.type === "password" ? "text" : "password";
      text($("#toggleToken"), input.type === "password" ? "Tampilkan" : "Sembunyikan");
    });
    $("#signOut").addEventListener("click", () => signOut(true));
    $$(".nav-item").forEach((item) => item.addEventListener("click", () => goto(item.dataset.page)));
    $$('[data-go]').forEach((item) => item.addEventListener("click", () => goto(item.dataset.go)));
    $("#refreshButton").addEventListener("click", () => refreshAll().then(() => toast("Data dashboard diperbarui.", "success")).catch((error) => toast(error.message, "error")));
    $("#scanForm").addEventListener("submit", (event) => {
      event.preventDefault();
      if (!$("#scanAuthorized").checked) return;
      const target = $("#scanTarget").value;
      if (!target) { toast("Pilih domain yang sudah masuk scope.", "error"); return; }
      const mode = $("input[name='scanMode']:checked").value;
      text($("#confirmDomain"), target);
      text($("#confirmMode"), mode === "full" ? "Pipeline lengkap · aktif + pasif" : "Passive saja · OSINT + header");
      text($("#scanConfirmText"), `Anda akan menjalankan ${mode === "full" ? "pipeline lengkap" : "pengumpulan pasif"} terhadap target yang dipilih. Pastikan izin tertulis dan aturan program masih berlaku.`);
      $("#scanDialog").showModal();
    });
    $("#confirmScan").addEventListener("click", () => startScan($("input[name='scanMode']:checked").value));
    $("#cancelScan").addEventListener("click", () => $("#scanDialog").close());
    $("#stopScanSmall").addEventListener("click", stopScan);
    $("#clearConsole").addEventListener("click", () => { $("#scanOutput").replaceChildren(); const note = document.createElement("span"); note.className = "console-placeholder"; note.textContent = "Tampilan output dibersihkan; log asli tetap tersimpan di host."; $("#scanOutput").appendChild(note); });
    $("#shellForm").addEventListener("submit", startShell);
    $("#stopShell").addEventListener("click", stopShell);
    $("#clearShellConsole").addEventListener("click", () => { $("#shellOutput").replaceChildren(); const note = document.createElement("span"); note.className = "console-placeholder"; note.textContent = "Tampilan terminal dibersihkan; output tersimpan sementara di sesi dashboard."; $("#shellOutput").appendChild(note); });
    $("#reportTarget").addEventListener("change", loadReports);
    $("#reportRun").addEventListener("change", () => loadReportFiles());
    $("#loadReports").addEventListener("click", loadReports);
    $("#downloadReport").addEventListener("click", downloadReport);
    $("#logTarget").addEventListener("change", loadLogs);
    $("#logRun").addEventListener("change", () => loadLogFiles());
    $("#logFile").addEventListener("change", () => loadLogDetails());
    $("#downloadLog").addEventListener("click", downloadLog);
    $("#loadLogs").addEventListener("click", loadLogs);
    $("#reloadTools").addEventListener("click", loadTools);
    $("#arsenalTarget").addEventListener("change", renderArsenal);
    document.addEventListener("keydown", (event) => {
      if (event.metaKey || event.ctrlKey || event.altKey) return;
      const tag = (event.target.tagName || "").toLowerCase();
      if (["input", "textarea", "select"].includes(tag) || appShell.classList.contains("hidden")) return;
      const order = ["overview", "scan", "reports", "logs", "tools", "terminal", "scope"];
      const index = Number(event.key) - 1;
      if (Number.isInteger(index) && index >= 0 && index < order.length) goto(order[index]);
    });
    $("#saveProxies").addEventListener("click", saveProxies);
    $("#scopeForm").addEventListener("submit", async (event) => {
      event.preventDefault();
      if (!$("#scopeAuthorized").checked) return;
      const domain = $("#scopeDomain").value.trim();
      await changeScope("add", domain);
      if (state.scope.includes(domain.toLowerCase())) { $("#scopeDomain").value = ""; $("#scopeAuthorized").checked = false; }
    });
    window.addEventListener("hashchange", () => goto(location.hash.slice(1)));
  }

  bindEvents();
  startClock();
  startMatrix();
  startTicker();
  startBootLog();
  if (previewHost) showLogin();
  else {
    const saved = sessionStorage.getItem(TOKEN_KEY);
    if (saved) login(saved).catch((error) => { state.token = ""; sessionStorage.removeItem(TOKEN_KEY); showLogin(error.message); });
    else showLogin();
  }
})();
