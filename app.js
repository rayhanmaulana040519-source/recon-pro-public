(() => {
  "use strict";

  const TOKEN_KEY = "reconpro-local-session";
  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));
  const state = { token: "", scope: [], targets: [], reports: [], selectedReport: null, selectedLog: null, outputSeq: 0, scanId: null, timer: null, reportLoadSerial: 0, logLoadSerial: 0 };
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
      throw new Error("Backend lokal tidak merespons. Pastikan web_ui/server.py masih berjalan pada mesin Recon Pro.");
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
    const valid = ["overview", "scan", "reports", "logs", "tools", "scope"].includes(page) ? page : "overview";
    $$(".page-view").forEach((item) => item.classList.toggle("hidden", item.dataset.view !== valid));
    $$(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.page === valid));
    const names = { overview: "IKHTISAR", scan: "PEMINDAIAN", reports: "LAPORAN", logs: "LOG AKTIVITAS", tools: "INVENTARIS TOOL", scope: "SCOPE & PROXY" };
    text($("#pageCrumb"), names[valid]);
    history.replaceState(null, "", `#${valid}`);
    if (valid === "scope") { loadScope(); loadProxies(); }
    if (valid === "tools") loadTools();
    if (valid === "reports") loadReports();
    if (valid === "logs") loadLogs();
    if (valid === "scan") refreshOutput();
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
    await refreshOutput();
  }

  async function loadStatus() {
    const data = await request("/api/status");
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
      const data = await request("/api/tools");
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
    } catch (error) { toast(error.message, "error"); }
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

  function renderStages(stages) {
    const rows = $("#stageRows"); rows.replaceChildren();
    text($("#stageCount"), `${stages.length} stage`);
    if (!stages.length) {
      const tr = document.createElement("tr"); const td = document.createElement("td"); td.colSpan = 3; td.className = "table-empty"; td.textContent = "Tidak ada ringkasan stage untuk koleksi ini."; tr.appendChild(td); rows.appendChild(tr); return;
    }
    stages.forEach((stage) => {
      const tr = document.createElement("tr");
      const name = document.createElement("td"); name.className = "stage-name"; name.textContent = stage.name;
      const status = document.createElement("td");
      const chip = document.createElement("span"); chip.className = `stage-chip stage-${stage.status}`; chip.textContent = stage.status.toUpperCase(); status.appendChild(chip);
      const note = document.createElement("td"); note.className = "stage-note"; note.textContent = stage.note || "—";
      tr.append(name, status, note); rows.appendChild(tr);
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

  async function refreshLive() {
    try {
      await loadStatus();
      await refreshOutput();
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

  async function saveProxies() {
    if (!window.confirm("Simpan ulang seluruh daftar proxy? Baris yang ada akan diganti dengan isi editor.")) return;
    try {
      await request("/api/proxies", { method: "POST", body: JSON.stringify({ proxies: $("#proxyEntries").value, confirm: true }) });
      await loadProxies(); await loadStatus(); toast("Daftar proxy tersimpan dengan izin file privat.", "success");
    } catch (error) { toast(error.message, "error"); }
  }

  function bindEvents() {
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
  if (previewHost) showLogin();
  else {
    const saved = sessionStorage.getItem(TOKEN_KEY);
    if (saved) login(saved).catch((error) => { state.token = ""; sessionStorage.removeItem(TOKEN_KEY); showLogin(error.message); });
    else showLogin();
  }
})();
