    const state = {
      token: localStorage.getItem("sftpguy_admin_token") || "",
      activeTab: "summary",
      timeRange: localStorage.getItem("sftpguy_admin_range") || "24h",
      pageSize: Number(localStorage.getItem("sftpguy_admin_page_size") || "50"),
      table: {},
      autoTimer: 0,
      liveLogTimer: 0,
      actions: [],
      summary: {},
      live: { connections: [], sessions: [], transfers: [], connection_count: 0, session_count: 0, transfer_count: 0 },
      insights: {},
	      summaryUploads: [],
	      users: [],
      files: { path: ".", entries: [] },
      fileSearch: { q: "", owner: "", results: [], total: 0, offset: 0, limit: 200 },
      audit: [],
      events: [],
	      authAttempts: [],
	      authCombos: [],
	      systemLogs: { panics: [], panicCount: 0, scannedLines: 0, levels: [], hasMore: false },
	      logCursorBefore: 0,
	      logHasMore: false,
      sessions: [],
	      uploads: [],
      downloadsSelectedPath: "",
      downloadsView: { q: "", summary: {}, files: [], downloaders: [], recent: [], selected_path: "", selected_file: null, selected_history: [], window: {} },
      banned: { hashes: [], ips: [] },
      actor: null,
      sessionTimeline: null,
      lastEventID: 0,
	      selfTest: { running: false, run_id: 0, started_at: "", running_for: "", last_report: null },
	      selfTestPollTimer: 0,
	      maintenance: {
	        running: false,
	        current_trigger: "",
	        current_started_at: "",
	        current_running_for: "",
	        last_run: null,
	        logs: [],
	        badFiles: { path: "", content: "", entries: 0, invalid_count: 0, invalid_lines: [] }
	      },
	      ipLists: {
	        whitelist: { path: "", content: "", entries: 0, invalid_count: 0, invalid_lines: [] },
	        blacklist: { path: "", content: "", entries: 0, invalid_count: 0, invalid_lines: [] },
	        test: null
	      },
	      adminKeys: { path: "", content: "", entries: 0, invalid_count: 0, invalid_lines: [], hashes: [] },
	      maintainers: { path: "", content: "", entries: 0, invalid_count: 0, invalid_lines: [], grants: [] },
	      oneTimeLogins: []
	    };

    function setStatus(msg) { document.getElementById("status").textContent = msg; }
    function esc(v) {
      return String(v == null ? "" : v).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
    }
    function shortHash(v) {
      const s = String(v || "");
      if (s.length <= 12) return s;
      return s.slice(0, 12);
    }
    function shortSession(v) {
      return shortHash(v);
    }
    function timestampToMs(v) {
      const n = Number(v || 0);
      if (!isFinite(n) || n <= 0) return 0;
      return n >= 1000000000000 ? n : (n * 1000);
    }
    function secondsToMs(v) {
      const n = Number(v || 0);
      if (!isFinite(n) || n <= 0) return 0;
      return n * 1000;
    }
    function formatMs(v) {
      const n = Number(v || 0);
      if (!isFinite(n) || n <= 0) return "0ms";
      if (n < 1) {
        const digits = n < 0.001 ? 6 : (n < 0.01 ? 5 : (n < 0.1 ? 4 : 3));
        return n.toFixed(digits).replace(/0+$/, "").replace(/\.$/, "") + "ms";
      }
      return Math.round(n) + "ms";
    }
    function formatBytes(n) {
      let x = Number(n || 0);
      if (!isFinite(x) || x <= 0) return "0 B";
      const units = ["B", "KB", "MB", "GB", "TB"];
      let i = 0;
      while (x >= 1024 && i < units.length - 1) { x /= 1024; i++; }
      return x.toFixed(i === 0 ? 0 : 1) + " " + units[i];
    }
    function formatRate(n) {
      return formatBytes(n || 0) + "/s";
    }
    function formatPercent(n) {
      const x = Number(n || 0);
      if (!isFinite(x) || x <= 0) return "0%";
      return x.toFixed(1).replace(/\.0$/, "") + "%";
    }
    function formatSeconds(v) {
      let n = Math.max(0, Math.floor(Number(v || 0)));
      if (!isFinite(n) || n <= 0) return "0s";
      const d = Math.floor(n / 86400);
      n -= d * 86400;
      const h = Math.floor(n / 3600);
      n -= h * 3600;
      const m = Math.floor(n / 60);
      const s = n - m * 60;
      if (d > 0) return d + "d " + h + "h";
      if (h > 0) return h + "h " + m + "m";
      if (m > 0) return m + "m " + s + "s";
      return s + "s";
    }
    function toast(msg) {
      const t = document.getElementById("toast");
      t.textContent = msg;
      t.classList.add("show");
      clearTimeout(t._timer);
      t._timer = setTimeout(function() { t.classList.remove("show"); }, 1800);
    }
    function addHistory(msg) {
      state.actions.unshift(new Date().toLocaleTimeString() + " - " + msg);
      state.actions = state.actions.slice(0, 40);
      document.getElementById("action-history").innerHTML = state.actions.map(function(x) {
        return "<li><code>" + esc(x) + "</code></li>";
      }).join("");
    }
    function csvEscape(v) {
      const s = String(v == null ? "" : v);
      if (s.includes(",") || s.includes("\"") || s.includes("\n")) {
        return "\"" + s.replaceAll("\"", "\"\"") + "\"";
      }
      return s;
    }
    function download(name, content) {
      const blob = new Blob([content], { type: "text/csv;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = name;
      a.click();
      URL.revokeObjectURL(url);
    }
    function copyText(v) {
      navigator.clipboard.writeText(String(v || "")).then(function() {
        toast("Copied");
      }).catch(function() {
        toast("Copy failed");
      });
    }

    function withRange(path) {
      const sep = path.includes("?") ? "&" : "?";
      return path + sep + "range=" + encodeURIComponent(state.timeRange);
    }

    function bootParams() {
      const params = new URLSearchParams(window.location.search || "");
      const tab = String(params.get("tab") || "").toLowerCase();
      const owner = String(params.get("owner") || "").trim();
      const q = String(params.get("q") || "").trim();
      return { tab: tab, owner: owner, q: q };
    }

    async function api(path, opts) {
      opts = opts || {};
      const headers = Object.assign({"Accept": "application/json"}, opts.headers || {});
      if (state.token) headers["Authorization"] = "Bearer " + state.token;
      if (opts.body && !headers["Content-Type"]) headers["Content-Type"] = "application/json";
      const res = await fetch(path, Object.assign({}, opts, { headers: headers }));
      if (res.status === 401) {
        const t = prompt("Admin token required");
        if (t) {
          state.token = t.trim();
          localStorage.setItem("sftpguy_admin_token", state.token);
          return api(path, opts);
        }
      }
      const raw = await res.text();
      let payload = null;
      if (raw) {
        try {
          payload = JSON.parse(raw);
        } catch (_) {
          payload = null;
        }
      }
      if (!res.ok) {
        const err = new Error(raw || ("HTTP " + res.status));
        err.status = res.status;
        err.payload = payload;
        throw err;
      }
      return payload || {};
    }

    function setTabCount(name, count) {
      const el = document.querySelector(".tab[data-tab='" + name + "']");
      if (!el) return;
      const base = name === "selftest" ? "Self Test" :
        name === "live" ? "Live" :
        name === "logins" ? "Login URLs" :
        name === "maintenance" ? "Maintenance" :
        name === "iplists" ? "IP Lists" :
        (name.charAt(0).toUpperCase() + name.slice(1));
      el.textContent = count == null ? base : (base + " (" + count + ")");
    }

    function tableState(key, defaultSort, defaultDir) {
      if (!state.table[key]) {
        state.table[key] = { sort: defaultSort || "", dir: defaultDir || "desc", page: 1 };
      }
      if (!state.table[key].sort && defaultSort) {
        state.table[key].sort = defaultSort;
      }
      return state.table[key];
    }
    function normalizeSort(v) {
      if (v == null) return "";
      if (typeof v === "number") return v;
      if (typeof v === "boolean") return v ? 1 : 0;
      const n = Number(v);
      if (!Number.isNaN(n) && String(v).trim() !== "") return n;
      return String(v).toLowerCase();
    }
    function compareSort(a, b) {
      const av = normalizeSort(a);
      const bv = normalizeSort(b);
      if (typeof av === "number" && typeof bv === "number") return av - bv;
      if (av < bv) return -1;
      if (av > bv) return 1;
      return 0;
    }
    function renderSmartTable(key, columns, rows, defaultSort, defaultDir) {
      const st = tableState(key, defaultSort || columns[0].key, defaultDir || "desc");
      if (!columns.find(function(c) { return c.key === st.sort; })) {
        st.sort = columns[0].key;
      }
      const sorted = rows.slice().sort(function(a, b) {
        const cmp = compareSort((a.sort || {})[st.sort], (b.sort || {})[st.sort]);
        return st.dir === "asc" ? cmp : -cmp;
      });

      const pageSize = Math.max(1, Number(state.pageSize || 50));
      const totalPages = Math.max(1, Math.ceil(sorted.length / pageSize));
      if (st.page > totalPages) st.page = totalPages;
      if (st.page < 1) st.page = 1;
      const start = (st.page - 1) * pageSize;
      const pageRows = sorted.slice(start, start + pageSize);

      const head = columns.map(function(col) {
        const isActive = st.sort === col.key;
        const marker = isActive ? (st.dir === "asc" ? " ▲" : " ▼") : "";
        return "<th><button class=\"sort-btn" + (isActive ? " active" : "") + "\" onclick=\"tableSort('" + esc(key) + "','" + esc(col.key) + "')\">" + esc(col.label) + marker + "</button></th>";
      }).join("");

      const body = pageRows.length ? pageRows.map(function(row) {
        return "<tr>" + row.cells.map(function(c) { return "<td>" + c + "</td>"; }).join("") + "</tr>";
      }).join("") : "<tr><td colspan=\"" + columns.length + "\" class=\"muted\">No rows</td></tr>";

      return "<div class=\"table-tools\">" +
        "<div class=\"muted\">Rows " + sorted.length + "</div>" +
        "<div class=\"pager\">" +
          "<button class=\"tiny\" onclick=\"tablePage('" + esc(key) + "',-1)\">Prev</button>" +
          "<span class=\"pill\">Page " + st.page + " / " + totalPages + "</span>" +
          "<button class=\"tiny\" onclick=\"tablePage('" + esc(key) + "',1)\">Next</button>" +
        "</div>" +
      "</div>" +
      "<div class=\"table-wrap\"><table><thead><tr>" + head + "</tr></thead><tbody>" + body + "</tbody></table></div>";
    }

    function tableSort(key, sortKey) {
      const st = tableState(key, sortKey, "desc");
      if (st.sort === sortKey) {
        st.dir = st.dir === "asc" ? "desc" : "asc";
      } else {
        st.sort = sortKey;
        st.dir = "desc";
      }
      st.page = 1;
      rerenderCurrent();
    }
    function tablePage(key, delta) {
      const st = tableState(key, "", "desc");
      st.page += delta;
      rerenderCurrent();
    }

    function ownerCell(hash) {
      if (!hash || hash === "-" || hash === "system") {
        return "<code>" + esc(hash || "-") + "</code>";
      }
      const enc = encodeURIComponent(hash);
      return "<button class=\"owner-link\" onclick=\"openActor('user', decodeURIComponent('" + enc + "'))\"><code title=\"" + esc(hash) + "\">" + esc(shortHash(hash)) + "</code></button>" +
        " <button class=\"tiny\" onclick=\"copyText('" + esc(hash) + "')\">Copy</button>";
    }
    function ipCell(ip) {
      const value = String(ip || "");
      const enc = encodeURIComponent(value);
      return "<button class=\"owner-link\" onclick=\"openActor('ip', decodeURIComponent('" + enc + "'))\"><code>" + esc(value) + "</code></button>" +
        " <button class=\"tiny\" onclick=\"copyText('" + esc(value) + "')\">Copy</button>";
    }
    function sessionCell(session) {
      const value = String(session || "");
      if (!value) return "<code>-</code>";
      const enc = encodeURIComponent(value);
      return "<button class=\"owner-link\" onclick=\"openSessionTimeline(decodeURIComponent('" + enc + "'))\"><code title=\"" + esc(value) + "\">" + esc(shortSession(value)) + "</code></button>" +
        " <button class=\"tiny\" onclick=\"copyText('" + esc(value) + "')\">Copy</button>";
    }
    function normalizeExplorerPath(path) {
      let rel = String(path == null ? "" : path).trim();
      if (!rel || rel === "." || rel === "/") return "";
      rel = rel.replaceAll("\\", "/");
      while (rel.startsWith("./")) rel = rel.slice(2);
      rel = rel.replace(/^\/+/, "");
      rel = rel.replace(/\/+/g, "/");
      rel = rel.replace(/\/+$/, "");
      return rel === "." ? "" : rel;
    }
    function encodeExplorerPath(relPath) {
      if (!relPath) return "";
      return relPath.split("/").filter(Boolean).map(function(seg) {
        return encodeURIComponent(seg);
      }).join("/");
    }
    function explorerHref(path, isDirHint) {
      const raw = String(path == null ? "" : path);
      const rel = normalizeExplorerPath(raw);
      if (!rel) return "/admin/explorer/";
      const hasTrailingSlash = /\/\s*$/.test(raw);
      const isDir = isDirHint === true || (isDirHint == null && hasTrailingSlash);
      if (isDir) {
        return "/admin/explorer/" + encodeExplorerPath(rel);
      }
      const parts = rel.split("/");
      const wanted = parts.pop() || "";
      const dir = parts.join("/");
      const base = dir ? ("/admin/explorer/" + encodeExplorerPath(dir)) : "/admin/explorer/";
      return base + "?wanted=" + encodeURIComponent(wanted);
    }
    function explorerLink(path, isDirHint) {
      const raw = String(path == null ? "" : path).trim();
      if (!raw) return "";
      return " <a class=\"tiny nav-link\" href=\"" + esc(explorerHref(raw, isDirHint)) + "\">Explorer</a>";
    }
    function pathWithExplorer(path, isDirHint, displayValue) {
      const raw = String(path == null ? "" : path);
      if (!raw) return "<code>-</code>";
      const shown = displayValue == null ? raw : String(displayValue);
      return "<code>" + esc(shown) + "</code>" + explorerLink(raw, isDirHint);
    }
	    function openPathButton(path, label) {
	      const raw = String(path == null ? "" : path);
	      const shown = String(label == null ? raw : label);
	      if (!raw) return esc(shown);
	      const enc = encodeURIComponent(raw);
	      return "<button onclick=\"openPath(decodeURIComponent('" + enc + "'))\">" + esc(shown) + "</button>";
	    }
	    function firstLine(value) {
	      const text = String(value == null ? "" : value).trim();
	      if (!text) return "";
	      const parts = text.split(/\r?\n/);
	      return String(parts[0] || "").trim();
	    }
	    function renderLogDetails(summary, body, emptyLabel) {
	      const summaryText = String(summary == null ? "" : summary).trim();
	      const bodyText = String(body == null ? "" : body).trim();
	      if (!summaryText && !bodyText) return "<span class=\"muted\">" + esc(emptyLabel || "-") + "</span>";
	      if (!bodyText || bodyText === summaryText) return "<code>" + esc(summaryText || bodyText) + "</code>";
	      return "<details class=\"log-details\"><summary><code>" + esc(summaryText || emptyLabel || "View") + "</code></summary><pre>" + esc(bodyText) + "</pre></details>";
	    }
	    function renderPanicStack(entry) {
	      const stack = String((entry && entry.stack) || "").trim();
	      const panicValue = String((entry && entry.panic) || "").trim();
	      const preview = firstLine(stack) || panicValue || String((entry && entry.msg) || "").trim();
	      return renderLogDetails(preview || "View stack", stack || panicValue, "No stack");
	    }
	    function renderRawLog(entry) {
	      const raw = String((entry && entry.raw) || "").trim();
	      const preview = firstLine(raw) || "View raw log";
	      return renderLogDetails(preview, raw, "No raw log");
	    }
	    function renderPanicTableRows(entries) {
	      return (entries || []).map(function(entry) {
	        return {
	          sort: {
	            time: String(entry.time || ""),
	            component: entry.component || "",
	            panic: entry.panic || entry.msg || "",
	            user: entry.user_id || "",
	            ip: entry.ip || ""
	          },
	          cells: [
	            "<code>" + esc(entry.time || "") + "</code>",
	            entry.component ? "<code>" + esc(entry.component) + "</code>" : "<span class=\"muted\">-</span>",
	            "<code>" + esc(entry.panic || entry.msg || "") + "</code>",
	            entry.user_id ? ownerCell(entry.user_id) : "<span class=\"muted\">-</span>",
	            entry.ip ? ipCell(entry.ip) : "<span class=\"muted\">-</span>",
	            renderPanicStack(entry),
	            renderRawLog(entry)
	          ]
	        };
	      });
	    }
	    function markBadButton(path, isDir) {
	      const raw = String(path == null ? "" : path);
	      if (!raw || isDir) return "";
	      const enc = encodeURIComponent(raw);
	      return "<button class=\"btn-danger tiny\" onclick=\"markBadFile(decodeURIComponent('" + enc + "'))\">Mark Bad</button>";
    }
    function renameButton(path) {
      const raw = String(path == null ? "" : path);
      if (!raw) return "";
      const enc = encodeURIComponent(raw);
      return "<button class=\"tiny\" onclick=\"renamePath(decodeURIComponent('" + enc + "'))\">Rename</button>";
    }
    function actionButtons() {
      return Array.from(arguments).filter(Boolean).join(" ");
    }
    function downloadHistoryButton(path, active, label) {
      const rel = normalizeExplorerPath(path);
      if (!rel) return "";
      const enc = encodeURIComponent(rel);
      const text = String(label == null ? (active ? "Viewing" : "History") : label);
      const klass = active ? "btn-live tiny" : "tiny";
      return "<button class=\"" + klass + "\" onclick=\"openDownloadHistory(decodeURIComponent('" + enc + "'))\">" + esc(text) + "</button>";
    }
    function fileDownloadsCell(path, downloads, isDir) {
      if (isDir) return "<span class=\"muted\">-</span>";
      const count = Number(downloads || 0);
      const rel = normalizeExplorerPath(path);
      const active = !!rel && rel === normalizeExplorerPath(state.downloadsSelectedPath || "");
      const button = count > 0 ? (" " + downloadHistoryButton(rel, active, "View")) : "";
      return "<div>" + esc(count) + button + "</div>";
    }
    async function openDownloadHistory(path) {
      const rel = normalizeExplorerPath(path);
      if (!rel) return;
      state.downloadsSelectedPath = rel;
      if (state.activeTab !== "downloads") {
        switchTab("downloads");
        return;
      }
      await loadDownloads(rel);
    }
    async function clearDownloadHistorySelection() {
      state.downloadsSelectedPath = "";
      await loadDownloads("");
    }

    function closeActorDrawer() {
      state.actor = null;
      document.getElementById("actor-drawer").classList.add("hidden");
    }
    function closeSessionTimeline() {
      state.sessionTimeline = null;
      document.getElementById("session-timeline").classList.add("hidden");
    }

    function renderSimpleTable(headers, rows) {
      const h = headers.map(function(x) { return "<th>" + esc(x) + "</th>"; }).join("");
      const b = rows.length ? rows.map(function(cols) {
        return "<tr>" + cols.map(function(c) { return "<td>" + c + "</td>"; }).join("") + "</tr>";
      }).join("") : "<tr><td colspan=\"" + headers.length + "\" class=\"muted\">No rows</td></tr>";
      return "<div class=\"table-wrap\"><table><thead><tr>" + h + "</tr></thead><tbody>" + b + "</tbody></table></div>";
    }

    function eventTone(eventName) {
      const ev = String(eventName || "").toLowerCase();
      if (ev === "session/start" || ev === "session/end" || ev === "login") return "tone-session";
      if (ev.startsWith("denied")) return "tone-denied";
      if (ev === "upload") return "tone-upload";
      if (ev === "download") return "tone-download";
      if (ev === "delete") return "tone-delete";
      if (ev === "rename") return "tone-rename";
      return "tone-other";
    }

    function renderActionTimeline(actions, opts) {
      opts = opts || {};
      const rows = (actions || []).slice().sort(function(a, b) {
        const ta = timestampToMs(a.timestamp);
        const tb = timestampToMs(b.timestamp);
        if (ta === tb) return Number(a.id || 0) - Number(b.id || 0);
        return ta - tb;
      });
      if (!rows.length) {
        return "<div class=\"muted\">" + esc(opts.empty || "No actions") + "</div>";
      }

      const startMs = timestampToMs(rows[0].timestamp);
      const endMs = timestampToMs(rows[rows.length - 1].timestamp);
      const spanMs = Math.max(0, endMs - startMs);
      const spanDivisor = Math.max(1, spanMs);
      const counts = {};
      rows.forEach(function(x) {
        const key = String(x.event || "unknown");
        counts[key] = (counts[key] || 0) + 1;
      });
      const topKinds = Object.keys(counts).sort(function(a, b) {
        if (counts[a] === counts[b]) return a.localeCompare(b);
        return counts[b] - counts[a];
      }).slice(0, 8);

      const markerHtml = rows.map(function(a) {
        const ts = timestampToMs(a.timestamp) || startMs;
        const left = ((ts - startMs) / spanDivisor) * 100;
        const tone = eventTone(a.event);
        return "<span class=\"timeline-dot " + tone + "\" style=\"left:" + left.toFixed(2) + "%\"></span>";
      }).join("");

      const rowHtml = rows.map(function(a) {
        const ts = timestampToMs(a.timestamp) || startMs;
        const offset = Math.max(0, ts - startMs);
        const tone = eventTone(a.event);
        const detail = a.path
          ? pathWithExplorer(String(a.path))
          : ("<code>" + esc(a.meta ? String(a.meta) : "") + "</code>");
        return "<div class=\"timeline-item\">" +
          "<code class=\"timeline-offset\">+" + esc(formatMs(offset)) + "</code>" +
          "<code class=\"timeline-time\">" + esc(a.time || "") + "</code>" +
          "<span class=\"evt-chip " + tone + "\">" + esc(String(a.event || "").toUpperCase()) + "</span>" +
          "<span class=\"timeline-detail\">" + detail + "</span>" +
        "</div>";
      }).join("");

      const summaryPills = topKinds.map(function(k) {
        return "<span class=\"pill\">" + esc(k) + " " + esc(counts[k]) + "</span>";
      }).join("");

      return "<div class=\"action-viz\">" +
        "<div class=\"row\"><span class=\"pill\">events " + esc(rows.length) + "</span><span class=\"pill\">span " + esc(formatMs(spanMs)) + "</span>" + summaryPills + "</div>" +
        "<div class=\"timeline-rail\">" + markerHtml + "</div>" +
        "<div class=\"timeline-list\">" + rowHtml + "</div>" +
      "</div>";
    }

    async function loadSummary() {
      const pair = await Promise.all([
        api("/admin/api/summary"),
        api(withRange("/admin/api/insights")),
        api(withRange("/admin/api/uploads/recent?limit=12"))
      ]);
      state.summary = pair[0] || {};
      state.insights = pair[1] || {};
      state.summaryUploads = (pair[2] || {}).uploads || [];
      renderSummary();
    }
    function renderSummary() {
      const d = state.summary || {};
      const insight = state.insights || {};
      const kpi = insight.kpi || {};
      const win = insight.window || {};
      setStatus("archive=" + (d.archive || "") + " version=" + (d.version || "") + " ssh=:" + (d.ssh_port || "") + " admin=" + (d.admin_http || "") + " uptime=" + (d.uptime || "") + " range=" + (win.label || state.timeRange));

      const entries = [
        ["Uptime", d.uptime || "0s"],
        ["Users", d.users || 0],
        ["Contributors", d.contributors || 0],
        ["Files", d.files || 0],
        ["Directories", d.directories || 0],
        ["Stored Bytes", d.formatted_bytes || "0 B"],
        ["Contrib Threshold", formatBytes(d.contributor_threshold || 0)]
      ];
      const storageRows = (d.storage || []).map(function(x) {
        const free = x.free || formatBytes(x.free_bytes || 0);
        const total = x.total || formatBytes(x.total_bytes || 0);
        const used = x.used || formatBytes(x.used_bytes || 0);
        const freePct = formatPercent(x.free_percent || 0) + " free";
        const status = x.error
          ? "<span class=\"tag bad\">" + esc(x.error) + "</span>"
          : "<span class=\"tag ok\">" + esc(freePct) + "</span>";
        return [
          esc(x.label || x.kind || x.id || ""),
          esc(free),
          esc(total),
          esc(used),
          status,
          "<code>" + esc(x.path || "") + "</code>"
        ];
      });
      const activity = [
        ["Events", kpi.events || 0],
        ["Users Active", kpi.users || 0],
        ["IPs Active", kpi.ips || 0],
        ["Logins", kpi.logins || 0],
        ["Uploads", kpi.uploads || 0],
        ["Downloads", kpi.downloads || 0],
        ["Denied", kpi.denied || 0],
        ["Conn Max Hits", kpi.conn_max_hits || 0],
        ["Admin Actions", kpi.admin_actions || 0],
        ["Maintainer Actions", kpi.maintainer_actions || 0],
        ["Session Starts", kpi.session_starts || 0],
        ["Session Ends", kpi.session_ends || 0]
      ];

      const topEventsRows = (insight.top_events || []).map(function(x) {
        return ["<code>" + esc(x.name) + "</code>", esc(x.count)];
      });
      const topUsersRows = (insight.top_users || []).map(function(x) {
        return [ownerCell(x.name), esc(x.count), esc(x.denied)];
      });
      const topIPRows = (insight.top_ips || []).map(function(x) {
        return [ipCell(x.name), esc(x.count), esc(x.denied), "<button class=\"btn-danger tiny\" onclick=\"banIPDirect('" + esc(x.name) + "')\">Ban</button>"];
      });
	      const quickUploadRows = (state.summaryUploads || []).slice(0, 12).map(function(x) {
	        return [
	          "<code>" + esc(x.time || "") + "</code>",
	          ownerCell(x.user_id),
	          pathWithExplorer(x.path || "", false),
	          esc(formatBytes(x.delta || 0)),
	          sessionCell(x.session)
	        ];
	      });
	      const recentPanics = insight.recent_panics || [];
	      const crashRows = renderPanicTableRows(recentPanics);
	      const crashWatch = recentPanics.length
	        ? renderSmartTable(
	            "summary-panics",
	            [
	              {label:"Time", key:"time"},
	              {label:"Component", key:"component"},
	              {label:"Panic", key:"panic"},
	              {label:"User", key:"user"},
	              {label:"IP", key:"ip"},
	              {label:"Stack", key:"panic"},
	              {label:"Raw", key:"panic"}
	            ],
	            crashRows,
	            "time",
	            "desc"
	          )
	        : "<div class=\"muted\">No recent panic entries found in the process log.</div>";

	      document.getElementById("tab-summary").innerHTML =
	        "<div class=\"row\"><span class=\"pill\">Window " + esc(win.label || state.timeRange) + "</span></div>" +
	        "<div class=\"grid\">" + entries.map(function(kv) {
          return "<div class=\"metric\"><div class=\"k\">" + esc(kv[0]) + "</div><div class=\"v\">" + esc(kv[1]) + "</div></div>";
	        }).join("") + "</div>" +
	        "<h3>Partition Free Space</h3>" + renderSimpleTable(["Target", "Free", "Total", "Used", "Status", "Path"], storageRows) +
	        "<h3>Activity</h3><div class=\"grid\">" + activity.map(function(kv) {
	          return "<div class=\"metric\"><div class=\"k\">" + esc(kv[0]) + "</div><div class=\"v\">" + esc(kv[1]) + "</div></div>";
	        }).join("") + "</div>" +
	        "<h3>Crash Watch</h3>" +
	        "<div class=\"row\"><span class=\"pill\">panic entries " + esc(insight.parsed_panics || 0) + "</span><span class=\"pill\">parsed log lines " + esc(insight.parsed_lines_considered || 0) + "</span><button class=\"tiny btn-danger\" onclick=\"switchTab('logs')\">Open Logs</button></div>" +
	        crashWatch +
	        "<h3>Top Events</h3>" + renderSimpleTable(["Event", "Count"], topEventsRows) +
	        "<h3>Top Users</h3>" + renderSimpleTable(["User", "Events", "Denied"], topUsersRows) +
	        "<h3>Top IPs</h3>" + renderSimpleTable(["IP", "Events", "Denied", "Action"], topIPRows) +
	        "<h3>Recent Uploads (Quick View)</h3>" + renderSimpleTable(["Time", "User", "Path", "Delta", "Session"], quickUploadRows);
	    }

    async function loadLive() {
      const d = await api("/admin/api/live");
      state.live = d || { connections: [], sessions: [], transfers: [] };
      setTabCount("live", Number(state.live.session_count || 0) || Number(state.live.connection_count || 0));
      renderLive();
    }
    function liveStateTag(label, klass) {
      return "<span class=\"tag " + esc(klass || "ok") + "\">" + esc(label) + "</span>";
    }
    function liveMatch(row, q) {
      if (!q) return true;
      const haystack = [
        row.id,
        row.session,
        row.connection_id,
        row.source,
        row.protocol,
        row.user_id,
        row.auth_user,
        row.ip,
        row.remote_addr,
        row.login_type,
        row.user_agent,
        row.client_version,
        row.direction,
        row.path,
        row.last_operation,
        row.last_path,
        row.state
      ].map(function(v) { return String(v || "").toLowerCase(); }).join(" ");
      return haystack.includes(q.toLowerCase());
    }
    function renderLive() {
      const live = state.live || {};
      const q = (document.getElementById("live-q") || {}).value || "";
      const connections = (live.connections || []).filter(function(row) { return liveMatch(row, q); });
      const sessions = (live.sessions || []).filter(function(row) { return liveMatch(row, q); });
      const transfers = (live.transfers || []).filter(function(row) { return liveMatch(row, q); });
      const metrics = [
        ["Connections", live.connection_count || 0],
        ["Sessions", live.session_count || 0],
        ["Transfers", live.transfer_count || 0],
        ["Upload Rate", formatRate(live.upload_rate_bps || 0)],
        ["Download Rate", formatRate(live.download_rate_bps || 0)],
        ["Total Rate", formatRate(live.total_rate_bps || 0)],
        ["Uploaded", formatBytes(live.upload_bytes || 0)],
        ["Downloaded", formatBytes(live.download_bytes || 0)]
      ];
      const transferRows = transfers.map(function(t) {
        return {
          sort: {
            source: t.source || "",
            direction: t.direction || "",
            path: t.path || "",
            user: t.user_id || "",
            ip: t.ip || "",
            age: Number(t.age_sec || 0),
            bytes: Number(t.bytes || 0),
            rate: Number(t.rate_bps || 0)
          },
          cells: [
            "<code>" + esc(t.source || "-") + "</code>",
            "<span class=\"tag " + (t.direction === "upload" ? "ok" : "warn") + "\">" + esc(String(t.direction || "").toUpperCase()) + "</span>",
            pathWithExplorer(t.path || "", false),
            ownerCell(t.user_id || ""),
            ipCell(t.ip || ""),
            sessionCell(t.session || ""),
            esc(formatSeconds(t.age_sec || 0)),
            esc(formatBytes(t.bytes || 0)),
            esc(formatRate(t.rate_bps || 0)),
            "<code title=\"" + esc(t.user_agent || "") + "\">" + esc(t.user_agent || "-") + "</code>"
          ]
        };
      });
      const sessionRows = sessions.map(function(s) {
        const lastPath = s.last_path ? pathWithExplorer(s.last_path, false) : "<span class=\"muted\">-</span>";
        const flags = [
          s.admin ? liveStateTag("ADMIN", "warn") : "",
          s.banned ? liveStateTag("BANNED", "bad") : ""
        ].filter(Boolean).join(" ");
        return {
          sort: {
            session: s.session || "",
            source: s.source || "",
            user: s.user_id || "",
            ip: s.ip || "",
            login: s.login_type || "",
            age: Number(s.age_sec || 0),
            idle: Number(s.idle_sec || 0),
            upload: Number(s.upload_bytes || 0),
            download: Number(s.download_bytes || 0),
            rate: Number(s.total_rate_bps || 0),
            transfers: Number(s.active_transfers || 0),
            requests: Number(s.requests_active || 0)
          },
          cells: [
            sessionCell(s.session || ""),
            "<code>" + esc(s.source || "-") + "</code>",
            ownerCell(s.user_id || ""),
            ipCell(s.ip || ""),
            "<code>" + esc(s.login_type || "") + "</code>",
            esc(formatSeconds(s.age_sec || 0)),
            esc(formatSeconds(s.idle_sec || 0)),
            esc(formatBytes(s.upload_bytes || 0)),
            esc(formatBytes(s.download_bytes || 0)),
            esc(formatRate(s.total_rate_bps || 0)),
            esc(s.requests_active || 0),
            esc(s.active_transfers || 0),
            "<code>" + esc(s.last_operation || "-") + "</code> " + lastPath,
            flags || "<span class=\"tag ok\">OPEN</span>",
            "<code title=\"" + esc(s.user_agent || "") + "\">" + esc(s.user_agent || "-") + "</code>"
          ]
        };
      });
      const connectionRows = connections.map(function(c) {
        const flags = [
          c.throttled ? liveStateTag("THROTTLED", "warn") : "",
          c.admin ? liveStateTag("ADMIN", "warn") : "",
          c.banned ? liveStateTag("BANNED", "bad") : ""
        ].filter(Boolean).join(" ");
        return {
          sort: {
            id: c.id || "",
            source: c.source || "",
            state: c.state || "",
            user: c.user_id || "",
            ip: c.ip || "",
            age: Number(c.age_sec || 0),
            idle: Number(c.idle_sec || 0),
            rate: Number(c.total_rate_bps || 0)
          },
          cells: [
            "<code>" + esc(c.id || "") + "</code>",
            "<code>" + esc(c.source || "-") + "</code>",
            "<span class=\"tag " + (c.state === "authenticated" ? "ok" : "warn") + "\">" + esc(String(c.state || "open").toUpperCase()) + "</span>",
            ipCell(c.ip || ""),
            "<code>" + esc(c.remote_addr || "") + "</code>",
            sessionCell(c.session || ""),
            c.user_id ? ownerCell(c.user_id) : "<span class=\"muted\">-</span>",
            esc(formatSeconds(c.age_sec || 0)),
            esc(formatSeconds(c.idle_sec || 0)),
            esc(formatRate(c.total_rate_bps || 0)),
            flags || "<span class=\"tag ok\">NORMAL</span>",
            "<code title=\"" + esc(c.user_agent || "") + "\">" + esc(c.user_agent || "-") + "</code>"
          ]
        };
      });

      document.getElementById("live-out").innerHTML =
        "<div class=\"row\"><span class=\"pill\">snapshot " + esc(live.now_time || "") + "</span><span class=\"pill\">rate window " + esc(live.rate_window_sec || 0) + "s</span></div>" +
        "<div class=\"grid\">" + metrics.map(function(kv) {
          return "<div class=\"metric\"><div class=\"k\">" + esc(kv[0]) + "</div><div class=\"v\">" + esc(kv[1]) + "</div></div>";
        }).join("") + "</div>" +
        "<h3>Active Transfers</h3>" +
        renderSmartTable(
          "live-transfers",
          [
            {label:"Source", key:"source"},
            {label:"Direction", key:"direction"},
            {label:"Path", key:"path"},
            {label:"User", key:"user"},
            {label:"IP", key:"ip"},
            {label:"Session", key:"session"},
            {label:"Age", key:"age"},
            {label:"Bytes", key:"bytes"},
            {label:"Rate", key:"rate"},
            {label:"User Agent", key:"user"}
          ],
          transferRows,
          "rate",
          "desc"
        ) +
        "<h3>Open Sessions</h3>" +
        renderSmartTable(
          "live-sessions",
          [
            {label:"Session", key:"session"},
            {label:"Source", key:"source"},
            {label:"User", key:"user"},
            {label:"IP", key:"ip"},
            {label:"Login", key:"login"},
            {label:"Age", key:"age"},
            {label:"Idle", key:"idle"},
            {label:"Uploaded", key:"upload"},
            {label:"Downloaded", key:"download"},
            {label:"Rate", key:"rate"},
            {label:"Req", key:"requests"},
            {label:"Xfers", key:"transfers"},
            {label:"Last", key:"idle"},
            {label:"Flags", key:"transfers"},
            {label:"User Agent", key:"user"}
          ],
          sessionRows,
          "rate",
          "desc"
        ) +
        "<h3>Open Connections</h3>" +
        renderSmartTable(
          "live-connections",
          [
            {label:"ID", key:"id"},
            {label:"Source", key:"source"},
            {label:"State", key:"state"},
            {label:"IP", key:"ip"},
            {label:"Remote", key:"ip"},
            {label:"Session", key:"id"},
            {label:"User", key:"user"},
            {label:"Age", key:"age"},
            {label:"Idle", key:"idle"},
            {label:"Rate", key:"rate"},
            {label:"Flags", key:"state"},
            {label:"User Agent", key:"user"}
          ],
          connectionRows,
          "age",
          "asc"
        );
    }

    async function loadUsers() {
      const q = document.getElementById("user-q").value.trim();
      const d = await api("/admin/api/users?q=" + encodeURIComponent(q) + "&limit=1200");
      state.users = d.users || [];
      setTabCount("users", state.users.length);
      renderUsers();
    }
    function renderUsers() {
      const rows = (state.users || []).map(function(u) {
        return {
          sort: {
            hash: u.hash || "",
            last_login: u.last_login || "",
            seen: Number(u.seen || 0),
            upload_bytes: Number(u.upload_bytes || 0),
            download_bytes: Number(u.download_bytes || 0),
            banned: u.is_banned ? 1 : 0
          },
          cells: [
            ownerCell(u.hash),
            esc(u.last_login || ""),
            esc(u.seen || 0),
            esc(formatBytes(u.upload_bytes || 0)),
            esc(formatBytes(u.download_bytes || 0)),
            "<span class=\"tag " + (u.is_banned ? "bad" : "ok") + "\">" + (u.is_banned ? "BANNED" : "ACTIVE") + "</span>",
            "<button onclick=\"userAction('" + esc(u.hash) + "','ban')\" class=\"btn-danger tiny\">Ban</button> " +
            "<button onclick=\"userAction('" + esc(u.hash) + "','unban')\" class=\"btn-good tiny\">Unban</button> " +
            "<button onclick=\"userAction('" + esc(u.hash) + "','purge')\" class=\"btn-danger tiny\">Purge</button> " +
            "<button onclick=\"openActor('user','" + esc(u.hash) + "')\" class=\"tiny\">Open</button>"
          ]
        };
      });
      document.getElementById("users-out").innerHTML = renderSmartTable(
        "users",
        [
          {label:"User", key:"hash"},
          {label:"Last Login", key:"last_login"},
          {label:"Seen", key:"seen"},
          {label:"Uploaded", key:"upload_bytes"},
          {label:"Downloaded", key:"download_bytes"},
          {label:"Status", key:"banned"},
          {label:"Actions", key:"hash"}
        ],
        rows,
        "upload_bytes",
        "desc"
      );
    }

	    async function loadFiles() {
	      const p = document.getElementById("files-path").value.trim() || ".";
	      const d = await api("/admin/api/files?path=" + encodeURIComponent(p));
	      state.files = { path: d.path || ".", entries: d.entries || [] };
	      const searchCount = (state.fileSearch.results || []).length;
	      setTabCount("files", searchCount || state.files.entries.length);
	      document.getElementById("files-path").value = state.files.path;
	      renderFiles();
	    }
	    function renderFiles() {
	      const searching = !!(state.fileSearch && (state.fileSearch.q || state.fileSearch.owner));
	      if (searching) {
	        const results = state.fileSearch.results || [];
          const owner = String((state.fileSearch && state.fileSearch.owner) || "");
          const ownerPill = owner ? ("<span class=\"pill\">owner=<code>" + esc(owner) + "</code></span>") : "";
	        const rows = results.map(function(e) {
	          return {
	            sort: {
	              path: e.path || "",
	              owner: e.owner || "",
	              downloads: Number(e.downloads || 0),
	              size: Number(e.size || 0),
	              is_dir: e.is_dir ? 1 : 0
	            },
	            cells: [
	              (e.is_dir ? (openPathButton(e.path, "Open") + " ") : "") + pathWithExplorer(e.path || "", !!e.is_dir, e.is_dir ? ((e.path || "") + "/") : (e.path || "")),
	              ownerCell(e.owner || "-"),
	              fileDownloadsCell(e.path || "", e.downloads || 0, !!e.is_dir),
	              esc(e.size_human || formatBytes(e.size || 0)),
	              e.is_dir ? "<span class=\"tag ok\">DIR</span>" : "<span class=\"tag\">FILE</span>",
	              actionButtons(renameButton(e.path || ""), markBadButton(e.path || "", !!e.is_dir))
	            ]
	          };
	        });
	        document.getElementById("files-out").innerHTML =
	          "<div class=\"row\"><span class=\"pill\">search=<code>" + esc(state.fileSearch.q || "*") + "</code></span>" + ownerPill + "<span class=\"pill\">results " + esc(state.fileSearch.total || results.length) + "</span></div>" +
	          renderSmartTable(
	            "file-search",
	            [
	              {label:"Path", key:"path"},
	              {label:"Owner", key:"owner"},
	              {label:"Downloads", key:"downloads"},
	              {label:"Size", key:"size"},
	              {label:"Type", key:"is_dir"},
	              {label:"Actions", key:"path"}
	            ],
	            rows,
	            "path",
	            "asc"
	        );
	        return;
	      }

	      const entries = (state.files.entries || []);
	      const rows = entries.map(function(e) {
	        return {
	          sort: {
	            name: e.name || "",
            owner: e.owner || "",
            downloads: Number(e.downloads || 0),
            size: Number(e.size || 0),
            is_dir: e.is_dir ? 1 : 0
          },
          cells: [
            e.is_dir
              ? (openPathButton(e.path, (e.name || "") + "/") + explorerLink(e.path || "", true))
              : (esc(e.name || "") + explorerLink(e.path || "", false)),
            ownerCell(e.owner || "-"),
            fileDownloadsCell(e.path || "", e.downloads || 0, !!e.is_dir),
            esc(e.size_human || formatBytes(e.size || 0)),
            e.is_dir ? "<span class=\"tag ok\">DIR</span>" : "<span class=\"tag\">FILE</span>",
            actionButtons(renameButton(e.path || ""), markBadButton(e.path || "", !!e.is_dir))
          ]
        };
      });
	      document.getElementById("files-out").innerHTML = "<div class=\"muted\">path=" + pathWithExplorer(state.files.path || ".", true) + "</div>" +
	        renderSmartTable(
	          "files",
	          [
	            {label:"Name", key:"name"},
            {label:"Owner", key:"owner"},
            {label:"Downloads", key:"downloads"},
            {label:"Size", key:"size"},
            {label:"Type", key:"is_dir"},
            {label:"Actions", key:"name"}
          ],
          rows,
          "name",
	          "asc"
	        );
	    }
	    async function runFileSearch(q, owner) {
	      const qValue = String(q || "").trim();
        const ownerValue = String(owner || "").trim();
	      if (!qValue && !ownerValue) {
	        clearFileSearch();
	        return;
	      }
        const params = new URLSearchParams();
        if (qValue) params.set("q", qValue);
        if (ownerValue) params.set("owner", ownerValue);
        params.set("limit", "500");
	      const d = await api("/admin/api/files/search?" + params.toString());
	      state.fileSearch = {
	        q: d.q || qValue,
          owner: d.owner || ownerValue,
	        results: d.results || [],
	        total: Number(d.total || 0),
	        offset: Number(d.offset || 0),
	        limit: Number(d.limit || 500)
	      };
	      setTabCount("files", state.fileSearch.results.length);
	      renderFiles();
	    }
	    async function searchFiles() {
	      const q = document.getElementById("files-q").value.trim();
        await runFileSearch(q, "");
	    }
      async function searchFilesByOwner(owner) {
        const value = String(owner || "").trim();
        if (!value) return;
        await runFileSearch("", value);
      }
	    function clearFileSearch() {
	      document.getElementById("files-q").value = "";
	      state.fileSearch = { q: "", owner: "", results: [], total: 0, offset: 0, limit: 200 };
	      setTabCount("files", (state.files.entries || []).length);
	      renderFiles();
	    }
	    function openPath(path) {
	      document.getElementById("files-path").value = path;
	      clearFileSearch();
	      loadFiles();
	    }
	    function filesUp() {
	      const p = document.getElementById("files-path").value.trim() || ".";
	      if (p === "." || p === "/") return;
	      const x = p.split("/").filter(Boolean);
	      x.pop();
	      document.getElementById("files-path").value = x.length ? x.join("/") : ".";
	      clearFileSearch();
	      loadFiles();
	    }
    async function renamePath(path) {
      const value = String(path || "").trim();
      if (!value || value === ".") return;
      const parts = value.split("/").filter(Boolean);
      const current = parts.length ? parts[parts.length - 1] : value;
      const next = prompt("Rename \"" + value + "\" to:", current);
      if (next == null) return;
      const name = String(next || "").trim();
      if (!name || name === current) return;
      try {
        const d = await api("/admin/api/explorer/rename", {
          method: "POST",
          body: JSON.stringify({ path: value, new_name: name })
        });
        addHistory("renamed " + value + " to " + ((d && d.target) || name));
        toast("Renamed");
        if (state.fileSearch && (state.fileSearch.q || state.fileSearch.owner)) {
          await runFileSearch(state.fileSearch.q || "", state.fileSearch.owner || "");
        } else {
          await loadFiles();
        }
      } catch (err) {
        alert("Rename failed: " + err.message);
      }
    }

    async function loadAudit() {
      const q = document.getElementById("audit-q").value.trim();
      const d = await api(withRange("/admin/api/audit?q=" + encodeURIComponent(q) + "&limit=1000"));
      state.audit = d.events || [];
      setTabCount("audit", state.audit.length);
      renderAudit();
    }
    function parseMeta(raw) {
      const text = String(raw || "").trim();
      if (!text) return null;
      try {
        const parsed = JSON.parse(text);
        return parsed && typeof parsed === "object" ? parsed : null;
      } catch (_) {
        return null;
      }
    }
    function nestedMeta(meta) {
      const nested = meta && meta.explorer_meta;
      return nested && typeof nested === "object" ? nested : {};
    }
    function metaField(meta, key) {
      if (!meta) return "";
      if (meta[key] != null && meta[key] !== "") return meta[key];
      const nested = nestedMeta(meta);
      return nested[key] == null ? "" : nested[key];
    }
    function isMaintainerMeta(meta, eventName) {
      const role = String(metaField(meta, "actor_role") || "").toLowerCase();
      const maintainer = String(metaField(meta, "maintainer") || "").toLowerCase();
      const action = String(metaField(meta, "action") || metaField(meta, "operation") || eventName || "").toLowerCase();
      return role === "maintainer" || maintainer === "true" || action.indexOf("maintainers") >= 0;
    }
    function eventMeta(row) {
      if (row && row.meta_obj && typeof row.meta_obj === "object") return row.meta_obj;
      return parseMeta(row && row.meta) || null;
    }
    function maintainerChip(row) {
      const meta = eventMeta(row);
      if (!isMaintainerMeta(meta, row && row.event)) return "";
      const scope = String(metaField(meta, "maintainer_scope") || "").trim();
      const title = scope ? "maintainer scope " + scope : "maintainer action";
      const label = scope ? "maintainer " + scope : "maintainer";
      return "<span class=\"meta-chip meta-maintainer\" title=\"" + esc(title) + "\">" + esc(label) + "</span>";
    }
    function metaNumber(meta, key) {
      const n = Number(metaField(meta, key));
      return isFinite(n) ? n : 0;
    }
    function metaHeaders(meta) {
      const headers = metaField(meta, "headers");
      return headers && typeof headers === "object" ? headers : null;
    }
    function renderHeaderList(headers) {
      if (!headers) return "";
      const names = Object.keys(headers).sort(function(a, b) { return a.localeCompare(b); });
      if (!names.length) return "";
      return "<div class=\"meta-section\"><div class=\"muted\">Headers</div>" +
        names.map(function(name) {
          const rawValues = Array.isArray(headers[name]) ? headers[name] : [headers[name]];
          const values = rawValues.map(function(v) { return String(v == null ? "" : v); }).join(", ");
          return "<div class=\"meta-kv\"><code>" + esc(name) + "</code><span>" + esc(values) + "</span></div>";
        }).join("") +
      "</div>";
    }
    function renderAuditMeta(raw, rowPath, eventName) {
      const text = String(raw || "").trim();
      if (!text) return "<span class=\"muted\">-</span>";
      const meta = parseMeta(text);
      if (!meta) return "<code>" + esc(text) + "</code>";

      const nested = nestedMeta(meta);
      const file = String(metaField(meta, "file") || rowPath || "").trim();
      const filename = String(metaField(meta, "filename") || (file ? file.split("/").pop() : "") || "").trim();
      const method = String(metaField(meta, "method") || "").trim();
      const urlPath = String(metaField(meta, "url_path") || "").trim();
      const query = String(metaField(meta, "query") || "").trim();
      const status = metaNumber(meta, "status");
      const bytes = metaNumber(meta, "bytes");
      const size = metaNumber(meta, "size");
      const delta = metaNumber(meta, "delta");
      const duration = metaNumber(meta, "duration_ms");
      const avg = metaNumber(meta, "avg_bytes_per_sec");
      const source = String(metaField(meta, "source") || "").trim();
      const headers = metaHeaders(meta);
      const headerCount = headers ? Object.keys(headers).length : 0;
      const hits = metaNumber(meta, "hits");
      const maxConnections = metaNumber(meta, "max_connections") || metaNumber(meta, "limit");
      const activeConnections = metaNumber(meta, "active_connections") || metaNumber(meta, "active");
      const firstTime = String(metaField(meta, "first_time") || "").trim();
      const lastTime = String(metaField(meta, "last_time") || "").trim();
      const windowSeconds = metaNumber(meta, "window_seconds");
      const maintainer = isMaintainerMeta(meta, eventName);
      const maintainerScope = String(metaField(meta, "maintainer_scope") || "").trim();
      const maintainerTargetScope = String(metaField(meta, "maintainer_target_scope") || "").trim();
      const maintainerScopes = metaField(meta, "maintainer_scopes");

      const chips = [];
      if (maintainer) chips.push("<span class=\"meta-chip meta-maintainer\">" + esc(maintainerScope ? "maintainer " + maintainerScope : "maintainer") + "</span>");
      if (hits) chips.push("<span class=\"meta-chip\">hits " + esc(hits) + "</span>");
      if (maxConnections) chips.push("<span class=\"meta-chip\">limit " + esc(maxConnections) + "</span>");
      if (activeConnections) chips.push("<span class=\"meta-chip\">active " + esc(activeConnections) + "</span>");
      if (firstTime) chips.push("<span class=\"meta-chip\">first " + esc(firstTime) + "</span>");
      if (lastTime && lastTime !== firstTime) chips.push("<span class=\"meta-chip\">last " + esc(lastTime) + "</span>");
      if (windowSeconds) chips.push("<span class=\"meta-chip\">window " + esc(formatSeconds(windowSeconds)) + "</span>");
      if (file) chips.push("<span class=\"meta-chip meta-file\" title=\"" + esc(file) + "\">file " + esc(filename || file) + "</span>");
      if (method) chips.push("<span class=\"meta-chip\">" + esc(method) + "</span>");
      if (status) chips.push("<span class=\"meta-chip\">HTTP " + esc(status) + "</span>");
      if (bytes) chips.push("<span class=\"meta-chip\">bytes " + esc(formatBytes(bytes)) + "</span>");
      if (size) chips.push("<span class=\"meta-chip\">size " + esc(formatBytes(size)) + "</span>");
      if (delta || String(eventName || "") === "upload") chips.push("<span class=\"meta-chip\">delta " + esc(formatBytes(delta)) + "</span>");
      if (duration) chips.push("<span class=\"meta-chip\">duration " + esc(formatMs(duration)) + "</span>");
      if (avg) chips.push("<span class=\"meta-chip\">avg " + esc(formatBytes(avg)) + "/s</span>");
      if (headerCount) chips.push("<span class=\"meta-chip\">headers " + esc(headerCount) + "</span>");
      if (source) chips.push("<span class=\"meta-chip\">" + esc(source) + "</span>");

      const url = urlPath ? (urlPath + (query ? "?" + query : "")) : "";
      const detailRows = [
        ["file", file],
        ["url", url],
        ["client_ip", metaField(meta, "client_ip")],
        ["remote_addr", metaField(meta, "remote_addr")],
        ["first_time", firstTime],
        ["last_time", lastTime],
        ["window_end", metaField(meta, "window_end_time")],
        ["actor_role", maintainer ? "maintainer" : ""],
        ["maintainer_scope", maintainerScope],
        ["maintainer_target_scope", maintainerTargetScope],
        ["maintainer_scopes", Array.isArray(maintainerScopes) ? maintainerScopes.join(", ") : maintainerScopes],
        ["hits", hits],
        ["active_connections", activeConnections],
        ["max_connections", maxConnections],
        ["user_agent", metaField(meta, "user_agent") || nested.user_agent]
      ].filter(function(pair) { return String(pair[1] == null ? "" : pair[1]).trim() !== ""; });
      const details = detailRows.length
        ? "<div class=\"meta-section\">" + detailRows.map(function(pair) {
            return "<div class=\"meta-kv\"><code>" + esc(pair[0]) + "</code><span>" + esc(pair[1]) + "</span></div>";
          }).join("") + "</div>"
        : "";
      const pretty = JSON.stringify(meta, null, 2);
      const summary = chips.length ? chips.join(" ") : "<span class=\"muted\">JSON meta</span>";
      return "<details class=\"audit-meta\"><summary>" + summary + "</summary>" +
        details +
        renderHeaderList(headers) +
        "<div class=\"meta-section\"><div class=\"muted\">Raw JSON</div><pre>" + esc(pretty) + "</pre></div>" +
      "</details>";
    }
    function renderAudit() {
      const rows = (state.audit || []).map(function(e) {
        return {
          sort: {
            id: Number(e.id || 0),
            time: Number(e.timestamp || 0),
            event: e.event || "",
            user: e.user_id || "",
            ip: e.ip || ""
          },
          cells: [
            "<code>" + esc(e.time || "") + "</code>",
            "<span class=\"event-with-tags\"><code>" + esc(e.event || "") + "</code>" + maintainerChip(e) + "</span>",
            ownerCell(e.user_id),
            ipCell(e.ip),
            sessionCell(e.session),
            pathWithExplorer(e.path || ""),
            renderAuditMeta(e.meta || "", e.path || "", e.event || "")
          ]
        };
      });
      document.getElementById("audit-out").innerHTML = renderSmartTable(
        "audit",
        [
          {label:"Time", key:"time"},
          {label:"Event", key:"event"},
          {label:"User", key:"user"},
          {label:"IP", key:"ip"},
          {label:"Session", key:"id"},
          {label:"Path", key:"event"},
          {label:"Meta", key:"id"}
        ],
        rows,
        "time",
        "desc"
      );
    }

	    async function loadLogs(opts) {
		      opts = opts || {};
		      const q = document.getElementById("log-q").value.trim();
		      const before = Number(opts.before || 0);
		      const pair = await Promise.all([
		        api(withRange("/admin/api/events?q=" + encodeURIComponent(q) + "&limit=600&before_id=" + encodeURIComponent(before))),
		        api("/admin/api/system-log/parsed?panic_only=1&limit=40&q=" + encodeURIComponent(q))
		      ]);
		      const d = pair[0] || {};
		      const panicLog = pair[1] || {};
		      state.events = d.events || [];
		      state.lastEventID = d.last_id || (state.events.length ? state.events[0].id : 0);
		      state.logCursorBefore = Number(d.next_before_id || 0);
		      state.logHasMore = !!d.has_more;
		      state.systemLogs = {
		        panics: panicLog.entries || [],
		        panicCount: Number(panicLog.panic_count || 0),
		        scannedLines: Number(panicLog.scanned_lines || 0),
		        levels: panicLog.levels || [],
		        hasMore: !!panicLog.has_more
		      };
		      setTabCount("logs", state.events.length);
		      renderLogs();
		    }
	    async function loadOlderLogs() {
	      if (!state.logHasMore || !state.logCursorBefore) {
	        toast("No older log rows");
	        return;
	      }
	      const live = document.getElementById("logs-live");
	      if (live && live.checked) {
	        live.checked = false;
	        toggleLogLive();
	      }
	      await loadLogs({ before: state.logCursorBefore });
	      addHistory("loaded older logs");
	    }
	    async function loadNewestLogs() {
	      await loadLogs({ before: 0 });
	      addHistory("jumped to newest logs");
	    }
	    function renderLogs() {
	      const rows = (state.events || []).map(function(e) {
	        const level = String((e.event || "").startsWith("denied") ? "WARN" : (e.event || "")).toUpperCase();
        return {
          sort: {
            id: Number(e.id || 0),
            time: Number(e.timestamp || 0),
            event: e.event || "",
            user: e.user_id || "",
            ip: e.ip || "",
            session: e.session || ""
          },
          cells: [
            "<code>" + esc(e.time || "") + "</code>",
            "<code>" + esc(level) + "</code>",
            "<span class=\"event-with-tags\"><code>" + esc(e.event || "") + "</code>" + maintainerChip(e) + "</span>",
            ownerCell(e.user_id),
            ipCell(e.ip),
            sessionCell(e.session),
            pathWithExplorer(e.path || ""),
            "<button class=\"btn-danger tiny\" onclick=\"banIPDirect('" + esc(e.ip || "") + "')\">Ban IP</button>"
          ]
	        };
	      });
	      const systemLogs = state.systemLogs || {};
	      const panicRows = renderPanicTableRows(systemLogs.panics || []);
	      const panicLevels = (systemLogs.levels || []).map(function(level) {
	        return "<span class=\"pill\">" + esc(level.name || "") + " " + esc(level.count || 0) + "</span>";
	      }).join("");
	      const panicSection = panicRows.length
	        ? renderSmartTable(
	            "panic-logs",
	            [
	              {label:"Time", key:"time"},
	              {label:"Component", key:"component"},
	              {label:"Panic", key:"panic"},
	              {label:"User", key:"user"},
	              {label:"IP", key:"ip"},
	              {label:"Stack", key:"panic"},
	              {label:"Raw", key:"panic"}
	            ],
	            panicRows,
	            "time",
	            "desc"
	          )
	        : "<div class=\"muted\">No panic entries matched the current filter.</div>";
	      document.getElementById("logs-out").innerHTML =
		        "<div class=\"row\"><span class=\"pill\">last_event_id=" + esc(state.lastEventID || 0) + "</span><span class=\"pill\">next_before_id=" + esc(state.logCursorBefore || 0) + "</span><span class=\"pill\">" + (state.logHasMore ? "older rows available" : "end reached") + "</span></div>" +
		        renderSmartTable(
	          "logs",
	          [
            {label:"Time", key:"time"},
            {label:"Level", key:"event"},
            {label:"Event", key:"event"},
            {label:"User", key:"user"},
            {label:"IP", key:"ip"},
            {label:"Session", key:"session"},
            {label:"Path", key:"event"},
            {label:"Action", key:"id"}
	          ],
	          rows,
	          "time",
	          "desc"
	        ) +
	        "<h3>Server Panic Log</h3>" +
	        "<div class=\"row\"><span class=\"pill\">panic matches " + esc(systemLogs.panicCount || 0) + "</span><span class=\"pill\">scanned log lines " + esc(systemLogs.scannedLines || 0) + "</span><span class=\"pill\">" + (systemLogs.hasMore ? "more panic entries exist" : "showing latest panic entries") + "</span>" + panicLevels + "</div>" +
	        panicSection;
	    }

    async function loadAuthAttempts() {
      const q = document.getElementById("auth-q").value.trim();
      const d = await api(withRange("/admin/api/auth-attempts?q=" + encodeURIComponent(q) + "&limit=1500&combo_limit=400"));
      state.authAttempts = d.attempts || [];
      state.authCombos = d.combos || [];
      setTabCount("auth", state.authAttempts.length);
      renderAuthAttempts();
    }
    function renderAuthAttempts() {
      const comboRows = (state.authCombos || []).map(function(c) {
        return {
          sort: {
            count: Number(c.count || 0),
            username: c.username || "",
            password: c.password || "",
            last_time: Number(c.last_timestamp || 0)
          },
          cells: [
            "<code>" + esc(c.username || "") + "</code>",
            "<code>" + esc(c.password || "") + "</code>",
            esc(c.count || 0),
            "<code>" + esc(c.last_time || "") + "</code>",
            ipCell(c.last_ip || ""),
            "<button class=\"tiny\" onclick=\"copyText('" + esc((c.username || "") + ":" + (c.password || "")) + "')\">Copy user:pass</button>"
          ]
        };
      });
      const attemptRows = (state.authAttempts || []).map(function(a) {
        return {
          sort: {
            time: Number(a.timestamp || 0),
            username: a.username || "",
            password: a.password || "",
            ip: a.ip || "",
            id: Number(a.id || 0)
          },
          cells: [
            "<code>" + esc(a.time || "") + "</code>",
            "<code>" + esc(a.username || "") + "</code>",
            "<code>" + esc(a.password || "") + "</code>",
            ipCell(a.ip || ""),
            sessionCell(a.session || ""),
            ownerCell(a.user_id || ""),
            "<button class=\"tiny\" onclick=\"copyText('" + esc((a.username || "") + ":" + (a.password || "")) + "')\">Copy user:pass</button>"
          ]
        };
      });

      document.getElementById("auth-out").innerHTML =
        "<h3>Top Username/Password Combos</h3>" +
        renderSmartTable(
          "auth-combos",
          [
            {label:"Username", key:"username"},
            {label:"Password", key:"password"},
            {label:"Count", key:"count"},
            {label:"Last Seen", key:"last_time"},
            {label:"Last IP", key:"username"},
            {label:"Action", key:"username"}
          ],
          comboRows,
          "count",
          "desc"
        ) +
        "<h3>Recent Attempts</h3>" +
        renderSmartTable(
          "auth-attempts",
          [
            {label:"Time", key:"time"},
            {label:"Username", key:"username"},
            {label:"Password", key:"password"},
            {label:"IP", key:"ip"},
            {label:"Session", key:"id"},
            {label:"Hash", key:"id"},
            {label:"Action", key:"id"}
          ],
          attemptRows,
          "time",
          "desc"
        );
    }

    async function streamLogs() {
	      if (state.activeTab !== "logs") return;
	      if (state.logCursorBefore > 0) return;
	      const q = document.getElementById("log-q").value.trim();
      const d = await api(withRange("/admin/api/events/stream?since_id=" + encodeURIComponent(state.lastEventID || 0) + "&q=" + encodeURIComponent(q) + "&limit=200"));
      const incoming = d.events || [];
      if (!incoming.length) return;
      state.lastEventID = d.last_id || state.lastEventID;
      state.events = incoming.concat(state.events || []);
      if (state.events.length > 1500) state.events = state.events.slice(0, 1500);
      setTabCount("logs", state.events.length);
      renderLogs();
      toast("+" + incoming.length + " live events");
    }
    function toggleLogLive() {
      clearInterval(state.liveLogTimer);
      state.liveLogTimer = 0;
      const enabled = document.getElementById("logs-live").checked;
      if (enabled) {
        state.liveLogTimer = setInterval(function() {
          streamLogs().catch(function(err) { setStatus("error: " + err.message); });
        }, 2000);
        addHistory("enabled live logs");
      } else {
        addHistory("paused live logs");
      }
    }

    async function loadSessions() {
      const q = document.getElementById("sessions-q").value.trim();
      const d = await api(withRange("/admin/api/sessions?q=" + encodeURIComponent(q) + "&limit=1200"));
      state.sessions = d.sessions || [];
      setTabCount("sessions", state.sessions.length);
      renderSessions();
    }
    function renderSessions() {
      const rows = (state.sessions || []).map(function(s) {
        return {
          sort: {
            session: s.session || "",
            time: Number(s.ended_at || 0),
            user: s.user_id || "",
            ip: s.ip || "",
            events: Number(s.event_count || 0),
            duration: Number(s.duration_sec || 0),
            denied: Number(s.denied_count || 0)
          },
          cells: [
            sessionCell(s.session),
            ownerCell(s.user_id),
            ipCell(s.ip),
            "<code>" + esc(s.start_time || "") + "</code>",
            "<code>" + esc(s.end_time || "") + "</code>",
            esc((s.duration_sec || 0) + "s"),
            esc(s.event_count || 0),
            esc(s.upload_count || 0),
            esc(s.download_count || 0),
            "<span class=\"tag " + ((s.denied_count || 0) > 0 ? "warn" : "ok") + "\">" + esc(s.denied_count || 0) + "</span>",
            "<span class=\"tag " + (s.has_end ? "ok" : "warn") + "\">" + (s.has_end ? "CLOSED" : "OPEN") + "</span>"
          ]
        };
      });
      document.getElementById("sessions-out").innerHTML = renderSmartTable(
        "sessions",
        [
          {label:"Session", key:"session"},
          {label:"User", key:"user"},
          {label:"IP", key:"ip"},
          {label:"Start", key:"time"},
          {label:"End", key:"time"},
          {label:"Duration", key:"duration"},
          {label:"Events", key:"events"},
          {label:"Uploads", key:"events"},
          {label:"Downloads", key:"events"},
          {label:"Denied", key:"denied"},
          {label:"State", key:"session"}
        ],
        rows,
        "time",
        "desc"
      );
    }

    async function openSessionTimeline(sessionID) {
      if (!sessionID) return;
      const d = await api("/admin/api/sessions/" + encodeURIComponent(sessionID) + "?limit=700");
      state.sessionTimeline = d || null;
      renderSessionTimeline();
      document.getElementById("session-timeline").classList.remove("hidden");
    }
    function renderSessionTimeline() {
      if (!state.sessionTimeline) return;
      const d = state.sessionTimeline;
      const events = (d.events || []).slice().sort(function(a, b) {
        const ta = Number(a.timestamp || 0);
        const tb = Number(b.timestamp || 0);
        if (ta === tb) return Number(a.id || 0) - Number(b.id || 0);
        return ta - tb;
      });
      document.getElementById("session-out").innerHTML =
        "<div class=\"row\"><h3>Session Timeline</h3><button class=\"tiny\" onclick=\"closeSessionTimeline()\">Close</button></div>" +
        "<div class=\"muted\">session=" + sessionCell(d.session || "") + " user=" + ownerCell(d.user_id) + " ip=" + ipCell(d.ip) + " start=<code>" + esc(d.start_time || "") + "</code> end=<code>" + esc(d.end_time || "") + "</code></div>" +
        renderActionTimeline(events, { empty: "No session events" });
    }

    async function loadUploads() {
      const q = document.getElementById("uploads-q").value.trim();
      const d = await api(withRange("/admin/api/uploads/recent?q=" + encodeURIComponent(q) + "&limit=1200"));
      state.uploads = d.uploads || [];
      setTabCount("uploads", state.uploads.length);
      renderUploads();
    }
    function renderUploads() {
      const rows = (state.uploads || []).map(function(u) {
        return {
          sort: {
            id: Number(u.id || 0),
            time: Number(u.timestamp || 0),
            user: u.user_id || "",
            ip: u.ip || "",
            delta: Number(u.delta || 0),
            size: Number(u.size || 0),
            path: u.path || "",
            meta: u.meta || ""
          },
          cells: [
            "<code>" + esc(u.time || "") + "</code>",
            ownerCell(u.user_id),
            ipCell(u.ip),
            pathWithExplorer(u.path || "", false),
            esc(formatBytes(u.delta || 0)),
            esc(formatBytes(u.size || 0)),
            sessionCell(u.session),
            renderAuditMeta(u.meta || "", u.path || "", "upload")
          ]
        };
      });
      document.getElementById("uploads-out").innerHTML = renderSmartTable(
        "uploads",
        [
          {label:"Time", key:"time"},
          {label:"User", key:"user"},
          {label:"IP", key:"ip"},
          {label:"Path", key:"path"},
          {label:"Delta", key:"delta"},
          {label:"Size", key:"size"},
          {label:"Session", key:"id"},
          {label:"Meta", key:"meta"}
        ],
        rows,
        "time",
        "desc"
      );
    }

    async function loadDownloads(selectedPath) {
      if (selectedPath !== undefined) {
        state.downloadsSelectedPath = normalizeExplorerPath(selectedPath);
      }
      const q = document.getElementById("downloads-q").value.trim();
      const params = new URLSearchParams();
      params.set("q", q);
      params.set("file_limit", "800");
      params.set("downloader_limit", "300");
      params.set("recent_limit", "400");
      params.set("download_history_limit", "400");
      if (state.downloadsSelectedPath) {
        params.set("path", state.downloadsSelectedPath);
      }
      const d = await api(withRange("/admin/api/downloads?" + params.toString()));
      state.downloadsSelectedPath = normalizeExplorerPath((d && d.selected_path) || state.downloadsSelectedPath || "");
      state.downloadsView = {
        q: d.q || q,
        summary: d.summary || {},
        files: d.files || [],
        downloaders: d.downloaders || [],
        recent: d.recent || [],
        selected_path: state.downloadsSelectedPath,
        selected_file: d.selected_file || null,
        selected_history: d.selected_history || [],
        window: d.window || {}
      };
      setTabCount("downloads", state.downloadsView.files.length);
      renderDownloads();
    }
    function renderDownloads() {
      const d = state.downloadsView || {};
      const summary = d.summary || {};
      const win = d.window || {};
      const selectedPath = normalizeExplorerPath((d && d.selected_path) || state.downloadsSelectedPath || "");
      const selectedFile = d.selected_file || null;
      const filterPill = d.q ? ("<span class=\"pill\">filter=<code>" + esc(d.q) + "</code></span>") : "";
      const summaryGrid = [
        ["Range Downloads", summary.range_downloads || 0],
        ["Range Unique Files", summary.range_unique_files || 0],
        ["Range Unique Users", summary.range_unique_users || 0],
        ["Range Unique IPs", summary.range_unique_ips || 0],
        ["Files Ever Downloaded", summary.files_ever_downloaded || 0],
        ["All-Time Downloads", summary.all_time_downloads || 0]
      ].map(function(kv) {
        return "<div class=\"metric\"><div class=\"k\">" + esc(kv[0]) + "</div><div class=\"v\">" + esc(kv[1]) + "</div></div>";
      }).join("");

      const fileRows = (d.files || []).map(function(f) {
        return {
          sort: {
            path: f.path || "",
            history: f.path || "",
            owner: f.owner || "",
            downloads_total: Number(f.downloads_total || 0),
            downloads_in_range: Number(f.downloads_in_range || 0),
            last_download_at: Number(f.last_download_at || 0),
            last_downloader: f.last_downloader || "",
            last_ip: f.last_ip || "",
            size: Number(f.size || 0)
          },
          cells: [
            pathWithExplorer(f.path || "", false),
            downloadHistoryButton(f.path || "", normalizeExplorerPath(f.path || "") === selectedPath, normalizeExplorerPath(f.path || "") === selectedPath ? "Viewing" : "Open"),
            ownerCell(f.owner || "-"),
            esc(f.downloads_total || 0),
            "<div>" + esc(f.downloads_in_range || 0) + "</div><div class=\"muted\">users " + esc(f.unique_users_in_range || 0) + " · ips " + esc(f.unique_ips_in_range || 0) + "</div>",
            f.last_download_time ? "<code>" + esc(f.last_download_time) + "</code>" : "<span class=\"muted\">-</span>",
            ownerCell(f.last_downloader || "-"),
            ipCell(f.last_ip || ""),
            esc(f.size_human || formatBytes(f.size || 0))
          ]
        };
      });

      const downloaderRows = (d.downloaders || []).map(function(row) {
        return {
          sort: {
            user_id: row.user_id || "",
            download_count: Number(row.download_count || 0),
            unique_files: Number(row.unique_files || 0),
            unique_ips: Number(row.unique_ips || 0),
            last_download_at: Number(row.last_download_at || 0),
            last_ip: row.last_ip || ""
          },
          cells: [
            ownerCell(row.user_id || "-"),
            esc(row.download_count || 0),
            esc(row.unique_files || 0),
            esc(row.unique_ips || 0),
            row.last_download ? "<code>" + esc(row.last_download) + "</code>" : "<span class=\"muted\">-</span>",
            ipCell(row.last_ip || "")
          ]
        };
      });

      const recentRows = (d.recent || []).map(function(row) {
        return {
          sort: {
            time: Number(row.timestamp || 0),
            user_id: row.user_id || "",
            ip: row.ip || "",
            path: row.path || "",
            size: Number(row.size || 0),
            duration_ms: Number(row.duration_ms || 0),
            avg_bytes_per_sec: Number(row.avg_bytes_per_sec || 0),
            session: row.session || "",
            meta: row.meta || ""
          },
          cells: [
            "<code>" + esc(row.time || "") + "</code>",
            ownerCell(row.user_id),
            ipCell(row.ip),
            pathWithExplorer(row.path || "", false),
            esc(formatBytes(row.size || 0)),
            esc(formatMs(row.duration_ms || 0)),
            esc(formatBytes(row.avg_bytes_per_sec || 0) + "/s"),
            sessionCell(row.session),
            renderAuditMeta(row.meta || "", row.path || "", "download")
          ]
        };
      });

      const selectedHistoryRows = (d.selected_history || []).map(function(row) {
        return {
          sort: {
            time: Number(row.timestamp || 0),
            user_id: row.user_id || "",
            ip: row.ip || "",
            size: Number(row.size || 0),
            duration_ms: Number(row.duration_ms || 0),
            avg_bytes_per_sec: Number(row.avg_bytes_per_sec || 0),
            session: row.session || "",
            meta: row.meta || ""
          },
          cells: [
            "<code>" + esc(row.time || "") + "</code>",
            ownerCell(row.user_id),
            ipCell(row.ip),
            esc(formatBytes(row.size || 0)),
            esc(formatMs(row.duration_ms || 0)),
            esc(formatBytes(row.avg_bytes_per_sec || 0) + "/s"),
            sessionCell(row.session),
            renderAuditMeta(row.meta || "", row.path || selectedPath || "", "download")
          ]
        };
      });

      let selectedHistoryBlock = "";
      if (selectedPath) {
        const selectedEnc = encodeURIComponent(selectedPath);
        const lastDownloadText = selectedFile && selectedFile.last_download_time ? "<code>" + esc(selectedFile.last_download_time) + "</code>" : "<code>-</code>";
        const lastUserText = selectedFile ? ownerCell(selectedFile.last_downloader || "-") : "<code>-</code>";
        const lastIPText = selectedFile && selectedFile.last_ip ? ipCell(selectedFile.last_ip) : "<code>-</code>";
        selectedHistoryBlock =
          "<h3>Selected File History</h3>" +
          "<div class=\"row\"><span class=\"pill\">File</span>" + pathWithExplorer(selectedPath, false) +
            "<button class=\"tiny\" onclick=\"copyText(decodeURIComponent('" + selectedEnc + "'))\">Copy Path</button>" +
            "<button class=\"tiny\" onclick=\"clearDownloadHistorySelection()\">Clear</button></div>" +
          "<div class=\"row\"><span class=\"pill\">Owner</span>" + ownerCell((selectedFile && selectedFile.owner) || "-") +
            "<span class=\"pill\">Size " + esc((selectedFile && (selectedFile.size_human || formatBytes(selectedFile.size || 0))) || "0 B") + "</span>" +
            "<span class=\"pill\">All Time " + esc((selectedFile && selectedFile.downloads_total) || 0) + "</span>" +
            "<span class=\"pill\">In Window " + esc((selectedFile && selectedFile.downloads_in_range) || 0) + "</span>" +
            "<span class=\"pill\">Users " + esc((selectedFile && selectedFile.unique_users_in_range) || 0) + "</span>" +
            "<span class=\"pill\">IPs " + esc((selectedFile && selectedFile.unique_ips_in_range) || 0) + "</span></div>" +
          "<div class=\"muted\">Last download " + lastDownloadText + " by " + lastUserText + " from " + lastIPText + ". Window " + esc(win.label || state.timeRange) + ".</div>" +
          renderSmartTable(
            "downloads-selected-history",
            [
              {label:"Time", key:"time"},
              {label:"User", key:"user_id"},
              {label:"IP", key:"ip"},
              {label:"Size", key:"size"},
              {label:"Duration", key:"duration_ms"},
              {label:"Rate", key:"avg_bytes_per_sec"},
              {label:"Session", key:"session"},
              {label:"Meta", key:"meta"}
            ],
            selectedHistoryRows,
            "time",
            "desc"
          );
      }

      document.getElementById("downloads-out").innerHTML =
        "<div class=\"row\"><span class=\"pill\">Window " + esc(win.label || state.timeRange) + "</span>" + filterPill + "</div>" +
        "<div class=\"grid\">" + summaryGrid + "</div>" +
        selectedHistoryBlock +
        "<h3>Top Files</h3>" +
        renderSmartTable(
          "downloads-files",
          [
            {label:"Path", key:"path"},
            {label:"History", key:"history"},
            {label:"Owner", key:"owner"},
            {label:"All Time", key:"downloads_total"},
            {label:"In Range", key:"downloads_in_range"},
            {label:"Last Download", key:"last_download_at"},
            {label:"Last User", key:"last_downloader"},
            {label:"Last IP", key:"last_ip"},
            {label:"Size", key:"size"}
          ],
          fileRows,
          "downloads_total",
          "desc"
        ) +
        "<h3>Top Downloaders</h3>" +
        renderSmartTable(
          "downloads-users",
          [
            {label:"User", key:"user_id"},
            {label:"Downloads", key:"download_count"},
            {label:"Unique Files", key:"unique_files"},
            {label:"Unique IPs", key:"unique_ips"},
            {label:"Last Download", key:"last_download_at"},
            {label:"Last IP", key:"last_ip"}
          ],
          downloaderRows,
          "download_count",
          "desc"
        ) +
        "<h3>Recent Downloads</h3>" +
        renderSmartTable(
          "downloads-recent",
          [
            {label:"Time", key:"time"},
            {label:"User", key:"user_id"},
            {label:"IP", key:"ip"},
            {label:"Path", key:"path"},
            {label:"Size", key:"size"},
            {label:"Duration", key:"duration_ms"},
            {label:"Rate", key:"avg_bytes_per_sec"},
            {label:"Session", key:"session"},
            {label:"Meta", key:"meta"}
          ],
          recentRows,
          "time",
          "desc"
        );
    }

    async function loadBanned() {
      const d = await api("/admin/api/banned");
      state.banned = { hashes: d.hashes || [], ips: d.ips || [] };
      setTabCount("banned", state.banned.hashes.length + state.banned.ips.length);
      renderBanned();
    }
    function renderBanned() {
      const hashRows = (state.banned.hashes || []).map(function(x) {
        return [ownerCell(x.hash), esc(x.banned_at || ""), "<button class=\"btn-good tiny\" onclick=\"userAction('" + esc(x.hash) + "','unban')\">Unban</button>"];
      });
      const ipRows = (state.banned.ips || []).map(function(x) {
        return [ipCell(x.ip), esc(x.banned_at || ""), "<button class=\"btn-good tiny\" onclick=\"unbanIP('" + esc(x.ip) + "')\">Unban</button>"];
      });
      document.getElementById("banned-out").innerHTML =
        "<h3>Pubkey bans</h3>" + renderSimpleTable(["Hash", "Banned At", "Action"], hashRows) +
        "<h3>IP bans</h3>" + renderSimpleTable(["IP", "Banned At", "Action"], ipRows);
    }

    async function loadMaintenance() {
      const qEl = document.getElementById("maintenance-log-q");
      const q = qEl ? qEl.value.trim() : "";
      const out = await Promise.all([
        api("/admin/api/maintenance"),
        api("/admin/api/maintenance/logs?limit=250&q=" + encodeURIComponent(q)),
        api("/admin/api/maintenance/bad-files")
      ]);
      const status = out[0] || {};
      const logs = (out[1] || {}).entries || [];
      const bad = out[2] || {};
      state.maintenance = {
        running: !!status.running,
        current_trigger: status.current_trigger || "",
        current_started_at: status.current_started_at || "",
        current_running_for: status.current_running_for || "",
        last_run: status.last_run || null,
        logs: logs,
        badFiles: {
          path: bad.path || "",
          content: bad.content || "",
          entries: Number(bad.entries || 0),
          invalid_count: Number(bad.invalid_count || 0),
          invalid_lines: bad.invalid_lines || []
        }
      };

      const editor = document.getElementById("maintenance-bad-files-content");
      if (editor && document.activeElement !== editor) editor.value = state.maintenance.badFiles.content || "";

      setTabCount("maintenance", null);
      renderMaintenance();
    }

    function renderMaintenance() {
      const m = state.maintenance || {};
      const bad = m.badFiles || {};
      const last = m.last_run || null;
      const runButton = document.getElementById("maintenance-run");
      if (runButton) runButton.disabled = !!m.running;

      const statusBits = [
        "<span class=\"tag " + (m.running ? "warn" : "ok") + "\">" + (m.running ? "RUNNING" : "IDLE") + "</span>"
      ];
      if (m.current_trigger) statusBits.push("<span class=\"pill\">trigger " + esc(m.current_trigger) + "</span>");
      if (m.current_started_at) statusBits.push("<span class=\"pill\">started <code>" + esc(m.current_started_at) + "</code></span>");
      if (m.current_running_for) statusBits.push("<span class=\"pill\">running_for " + esc(m.current_running_for) + "</span>");
      document.getElementById("maintenance-status").innerHTML = "<div class=\"row\">" + statusBits.join("") + "</div>";

      if (!last) {
        document.getElementById("maintenance-last-run").innerHTML = "<div class=\"muted\">No maintenance pass has completed yet.</div>";
      } else {
        const unorphaned = (last.result && last.result.reconcile_orphans && last.result.reconcile_orphans.unorphaned) || [];
        const badOrphans = (last.result && last.result.reconcile_orphans && last.result.reconcile_orphans.bad_files) || [];
        const sshdbotMatches = (last.result && last.result.purge_sshdbot && last.result.purge_sshdbot.matches) || [];
        const rows = [
          [
            "<code>clean_deleted</code>",
            esc(last.result && last.result.clean_deleted ? last.result.clean_deleted.stale_roots || 0 : 0),
            esc(last.result && last.result.clean_deleted ? last.result.clean_deleted.deleted || 0 : 0),
            "<code>" + esc(last.result && last.result.clean_deleted ? last.result.clean_deleted.error || "" : "") + "</code>"
          ],
          [
            "<code>reconcile_orphans</code>",
            esc(last.result && last.result.reconcile_orphans ? last.result.reconcile_orphans.candidates || 0 : 0),
            "<span class=\"pill\">kept " + esc(unorphaned.length) + "</span> <span class=\"pill\">bad " + esc(badOrphans.length) + "</span>",
            "<code>" + esc(last.result && last.result.reconcile_orphans ? last.result.reconcile_orphans.error || "" : "") + "</code>"
          ],
          [
            "<code>purge_sshdbot</code>",
            esc(sshdbotMatches.length),
            esc(last.result && last.result.purge_sshdbot ? last.result.purge_sshdbot.purges || 0 : 0),
            "<code>" + esc(last.result && last.result.purge_sshdbot ? last.result.purge_sshdbot.error || "" : "") + "</code>"
          ],
          [
            "<code>purge_blacklisted_files</code>",
            esc(last.result && last.result.purge_blacklisted_files ? last.result.purge_blacklisted_files.matches || 0 : 0),
            esc(last.result && last.result.purge_blacklisted_files ? last.result.purge_blacklisted_files.purges || 0 : 0),
            "<code>" + esc(last.result && last.result.purge_blacklisted_files ? last.result.purge_blacklisted_files.error || "" : "") + "</code>"
          ]
        ];
        const unorphanedTable = unorphaned.length
          ? "<h3>Newly Registered Orphans</h3>" + renderSimpleTable(
              ["Path", "Owner", "Size", "Type"],
              unorphaned.map(function(file) {
                return [
                  pathWithExplorer(file.path || "", !!file.is_dir, file.path || ""),
                  ownerCell(file.owner_hash || "-"),
                  esc(formatBytes(file.size || 0)),
                  file.is_dir ? "<span class=\"tag ok\">DIR</span>" : "<span class=\"tag\">FILE</span>"
                ];
              })
            )
          : "";
        const badOrphansTable = badOrphans.length
          ? "<h3>Purged Bad Orphans</h3>" + renderSimpleTable(
              ["Path", "Owner", "Size", "Type"],
              badOrphans.map(function(file) {
                return [
                  "<code>" + esc(file.path || "") + "</code>",
                  ownerCell(file.owner_hash || "-"),
                  esc(formatBytes(file.size || 0)),
                  file.is_dir ? "<span class=\"tag ok\">DIR</span>" : "<span class=\"tag warn\">FILE</span>"
                ];
              })
            )
          : "";
        const sshdbotTable = sshdbotMatches.length
          ? "<h3>SSHDBot Matches</h3>" + renderSimpleTable(
              ["Path", "Size", "Modified", "IP", "SHA-256"],
              sshdbotMatches.map(function(match) {
                return [
                  pathWithExplorer(match.path || "", false, match.path || ""),
                  esc(formatBytes(match.size || 0)),
                  "<code>" + esc(match.mod_time || "") + "</code>",
                  match.ip ? ipCell(match.ip) : "<span class=\"muted\">-</span>",
                  "<code>" + esc(match.sha256_hash || "") + "</code>"
                ];
              })
            )
          : "";
        document.getElementById("maintenance-last-run").innerHTML =
          "<div class=\"row\">" +
            "<span class=\"pill\">trigger " + esc(last.trigger || "") + "</span>" +
            "<span class=\"pill\">started <code>" + esc(last.started_at || "") + "</code></span>" +
            "<span class=\"pill\">finished <code>" + esc(last.finished_at || "") + "</code></span>" +
            "<span class=\"pill\">duration " + esc(last.duration || "") + "</span>" +
            "<span class=\"tag " + (last.halted ? "ok" : "warn") + "\">" + (last.halted ? "COMPLETE" : "INTERRUPTED") + "</span>" +
          "</div>" +
          renderSimpleTable(["Operation", "Observed", "Changes", "Error"], rows) +
          badOrphansTable +
          sshdbotTable +
          unorphanedTable;
      }

      const logRows = (m.logs || []).map(function(entry) {
        const fieldKeys = Object.keys(entry.fields || {}).filter(function(k) { return k !== "operation"; }).sort();
        const details = fieldKeys.length
          ? fieldKeys.map(function(k) {
              return "<span class=\"pill\"><code>" + esc(k) + "=" + esc((entry.fields || {})[k]) + "</code></span>";
            }).join(" ")
          : "<span class=\"muted\">-</span>";
        return {
          sort: {
            time: entry.time || "",
            level: entry.level || "",
            operation: entry.operation || "",
            message: entry.message || ""
          },
          cells: [
            "<code>" + esc(entry.time || "") + "</code>",
            "<code>" + esc(entry.level || "") + "</code>",
            "<code>" + esc(entry.operation || "") + "</code>",
            esc(entry.message || ""),
            details
          ]
        };
      });
      document.getElementById("maintenance-logs-out").innerHTML = renderSmartTable(
        "maintenance-logs",
        [
          {label:"Time", key:"time"},
          {label:"Level", key:"level"},
          {label:"Operation", key:"operation"},
          {label:"Message", key:"message"},
          {label:"Details", key:"operation"}
        ],
        logRows,
        "time",
        "desc"
      );

      const badMeta = "path=" + pathWithExplorer(bad.path || "") + " entries=" + esc(bad.entries || 0) + " invalid=" + esc(bad.invalid_count || 0);
      document.getElementById("maintenance-bad-files-meta").innerHTML = badMeta;
      document.getElementById("maintenance-bad-files-invalid").innerHTML = (bad.invalid_lines || []).length
        ? ("Invalid lines: <code>" + esc((bad.invalid_lines || []).join(", ")) + "</code>")
        : "";
    }

    async function runMaintenancePass() {
      try {
        await api("/admin/api/maintenance/run", { method: "POST" });
        addHistory("ran maintenance pass");
        toast("Maintenance pass complete");
      } catch (err) {
        if (Number(err.status || 0) === 409) {
          addHistory("maintenance already running");
          toast("Maintenance already running");
        } else {
          throw err;
        }
      }
      await loadMaintenance();
    }

    async function saveBadFiles() {
      const editor = document.getElementById("maintenance-bad-files-content");
      if (!editor) return;
      const content = editor.value || "";
      const d = await api("/admin/api/maintenance/bad-files", {
        method: "POST",
        body: JSON.stringify({ content: content })
      });
      const info = (d && d.bad_files) || {};
      state.maintenance.badFiles = {
        path: info.path || "",
        content: info.content || content,
        entries: Number(info.entries || 0),
        invalid_count: Number(info.invalid_count || 0),
        invalid_lines: info.invalid_lines || []
      };
      editor.value = state.maintenance.badFiles.content || "";
      addHistory("saved bad file list");
      toast("Saved bad files");
      renderMaintenance();
    }

    async function markBadFile(path) {
      const value = String(path || "").trim();
      if (!value) return;
      if (!confirm("Mark \"" + value + "\" as bad? This adds its hash to bad_files.txt.")) return;
      const d = await api("/admin/api/maintenance/mark-bad", {
        method: "POST",
        body: JSON.stringify({ path: value })
      });
      const hash = (d && d.hash) ? d.hash : "";
      const already = !!(d && d.already_present);
      if (d && d.bad_files) {
        state.maintenance.badFiles = {
          path: d.bad_files.path || "",
          content: d.bad_files.content || "",
          entries: Number(d.bad_files.entries || 0),
          invalid_count: Number(d.bad_files.invalid_count || 0),
          invalid_lines: d.bad_files.invalid_lines || []
        };
        const editor = document.getElementById("maintenance-bad-files-content");
        if (editor && document.activeElement !== editor) editor.value = state.maintenance.badFiles.content || "";
      }
      addHistory("marked bad file " + value);
      toast(already ? "Bad file already listed" : ("Marked bad " + shortHash(hash)));
      if (state.activeTab === "maintenance") {
        renderMaintenance();
      }
    }

	    async function loadIPLists() {
	      const out = await Promise.all([api("/admin/api/ip-lists"), api("/admin/api/admin-keys"), api("/admin/api/maintainers")]);
	      const d = out[0] || {};
	      const k = out[1] || {};
	      const m = out[2] || {};
	      state.ipLists = {
	        whitelist: (d && d.whitelist) || { path: "", content: "", entries: 0, invalid_count: 0, invalid_lines: [] },
	        blacklist: (d && d.blacklist) || { path: "", content: "", entries: 0, invalid_count: 0, invalid_lines: [] },
	        test: state.ipLists ? state.ipLists.test : null
	      };
	      state.adminKeys = {
	        path: k.path || "",
	        content: k.content || "",
	        entries: Number(k.entries || 0),
	        invalid_count: Number(k.invalid_count || 0),
	        invalid_lines: k.invalid_lines || [],
	        hashes: k.hashes || []
	      };
	      state.maintainers = {
	        path: m.path || "",
	        content: m.content || "",
	        entries: Number(m.entries || 0),
	        invalid_count: Number(m.invalid_count || 0),
	        invalid_lines: m.invalid_lines || [],
	        grants: m.grants || []
	      };

	      const wlEditor = document.getElementById("iplist-whitelist-content");
	      const blEditor = document.getElementById("iplist-blacklist-content");
	      const akEditor = document.getElementById("admin-keys-content");
	      const mtEditor = document.getElementById("maintainers-content");
	      if (wlEditor && document.activeElement !== wlEditor) wlEditor.value = state.ipLists.whitelist.content || "";
	      if (blEditor && document.activeElement !== blEditor) blEditor.value = state.ipLists.blacklist.content || "";
	      if (akEditor && document.activeElement !== akEditor) akEditor.value = state.adminKeys.content || "";
	      if (mtEditor && document.activeElement !== mtEditor) mtEditor.value = state.maintainers.content || "";

      setTabCount("iplists", null);
      renderIPLists();
    }

	    function renderIPLists() {
	      const wl = (state.ipLists || {}).whitelist || {};
	      const bl = (state.ipLists || {}).blacklist || {};
	      const test = (state.ipLists || {}).test || null;
	      const ak = state.adminKeys || {};
	      const mt = state.maintainers || {};

	      const wlMeta = "path=" + pathWithExplorer(wl.path || "") + " entries=" + esc(wl.entries || 0) + " invalid=" + esc(wl.invalid_count || 0);
	      const blMeta = "path=" + pathWithExplorer(bl.path || "") + " entries=" + esc(bl.entries || 0) + " invalid=" + esc(bl.invalid_count || 0);
	      const akMeta = "path=" + pathWithExplorer(ak.path || "") + " entries=" + esc(ak.entries || 0) + " invalid=" + esc(ak.invalid_count || 0);
	      const mtMeta = "path=" + pathWithExplorer(mt.path || "") + " entries=" + esc(mt.entries || 0) + " invalid=" + esc(mt.invalid_count || 0);
	      document.getElementById("iplist-whitelist-meta").innerHTML = wlMeta;
	      document.getElementById("iplist-blacklist-meta").innerHTML = blMeta;
	      document.getElementById("admin-keys-meta").innerHTML = akMeta;
	      document.getElementById("maintainers-meta").innerHTML = mtMeta;
	      document.getElementById("iplist-whitelist-invalid").innerHTML = (wl.invalid_lines || []).length
	        ? ("Invalid lines: <code>" + esc((wl.invalid_lines || []).join(", ")) + "</code>")
	        : "";
	      document.getElementById("iplist-blacklist-invalid").innerHTML = (bl.invalid_lines || []).length
	        ? ("Invalid lines: <code>" + esc((bl.invalid_lines || []).join(", ")) + "</code>")
	        : "";
	      document.getElementById("admin-keys-invalid").innerHTML = (ak.invalid_lines || []).length
	        ? ("Invalid lines: <code>" + esc((ak.invalid_lines || []).join(", ")) + "</code>")
	        : "";
	      document.getElementById("maintainers-invalid").innerHTML = (mt.invalid_lines || []).length
	        ? ("Invalid lines: <code>" + esc((mt.invalid_lines || []).join(", ")) + "</code>")
	        : "";

      if (!test) {
        document.getElementById("iplist-test-out").innerHTML = "<div class=\"muted\">Enter an IP to test effective ban behavior.</div>";
        return;
      }
      const m = test.matches || {};
      document.getElementById("iplist-test-out").innerHTML =
        "<div class=\"row\">" +
          "<span class=\"pill\">ip <code>" + esc(test.ip || "") + "</code></span>" +
          "<span class=\"tag " + (m.whitelist ? "ok" : "") + "\">whitelist=" + esc(m.whitelist ? "yes" : "no") + "</span>" +
          "<span class=\"tag " + (m.blacklist ? "bad" : "") + "\">blacklist=" + esc(m.blacklist ? "yes" : "no") + "</span>" +
          "<span class=\"tag " + (m.effective_banned ? "bad" : "ok") + "\">effective=" + esc(m.effective_banned ? "BANNED" : "ALLOWED") + "</span>" +
        "</div>" +
        "<div class=\"muted\">Whitelist has highest precedence.</div>";
    }

	    async function saveIPList(kind) {
      const editorID = kind === "whitelist" ? "iplist-whitelist-content" : "iplist-blacklist-content";
      const editor = document.getElementById(editorID);
      if (!editor) return;
      const content = editor.value || "";
      const d = await api("/admin/api/ip-lists/" + encodeURIComponent(kind), {
        method: "POST",
        body: JSON.stringify({ content: content })
      });
      const info = (d && d.list) || {};
      if (!state.ipLists) state.ipLists = {};
      state.ipLists[kind] = {
        path: info.path || "",
        content: info.content || content,
        entries: Number(info.entries || 0),
        invalid_count: Number(info.invalid_count || 0),
        invalid_lines: info.invalid_lines || []
      };
      editor.value = state.ipLists[kind].content || "";
      addHistory("saved " + kind + " ip list");
      toast("Saved " + kind);
	      renderIPLists();
	    }

	    async function saveAdminKeys() {
	      const editor = document.getElementById("admin-keys-content");
	      if (!editor) return;
	      const content = editor.value || "";
	      const d = await api("/admin/api/admin-keys", {
	        method: "POST",
	        body: JSON.stringify({ content: content })
	      });
	      const info = (d && d.keys) || {};
	      state.adminKeys = {
	        path: info.path || "",
	        content: info.content || content,
	        entries: Number(info.entries || 0),
	        invalid_count: Number(info.invalid_count || 0),
	        invalid_lines: info.invalid_lines || [],
	        hashes: info.hashes || []
	      };
	      editor.value = state.adminKeys.content || "";
	      addHistory("saved admin keys");
	      toast("Saved admin keys");
	      renderIPLists();
	    }

	    async function saveMaintainers() {
	      const editor = document.getElementById("maintainers-content");
	      if (!editor) return;
	      const content = editor.value || "";
	      const d = await api("/admin/api/maintainers", {
	        method: "POST",
	        body: JSON.stringify({ content: content })
	      });
	      const info = (d && d.maintainers) || {};
	      state.maintainers = {
	        path: info.path || "",
	        content: info.content || content,
	        entries: Number(info.entries || 0),
	        invalid_count: Number(info.invalid_count || 0),
	        invalid_lines: info.invalid_lines || [],
	        grants: info.grants || []
	      };
	      editor.value = state.maintainers.content || "";
	      addHistory("saved maintainers");
	      toast("Saved maintainers");
	      renderIPLists();
	    }

    async function testIPList() {
      const input = document.getElementById("iplist-test-ip");
      const ip = (input && input.value ? input.value : "").trim();
      if (!ip) return;
      const d = await api("/admin/api/ip-lists/test", {
        method: "POST",
        body: JSON.stringify({ ip: ip })
      });
      if (!state.ipLists) state.ipLists = {};
      state.ipLists.test = d || null;
      addHistory("tested ip list for " + ip);
      renderIPLists();
    }

    function clearSelfTestPoll() {
      clearTimeout(state.selfTestPollTimer);
      state.selfTestPollTimer = 0;
    }

    async function loadSelfTest() {
      const d = await api("/admin/api/self-test");
      state.selfTest = d || { running: false, run_id: 0, started_at: "", running_for: "", last_report: null };
      const report = (state.selfTest || {}).last_report || null;
      setTabCount("selftest", report ? Number(report.failed || 0) : null);
      renderSelfTest();

      clearSelfTestPoll();
      if (state.selfTest.running) {
        state.selfTestPollTimer = setTimeout(function() {
          loadSelfTest().catch(function(err) { setStatus("error: " + err.message); });
        }, 1500);
      }
    }

    async function runSelfTest() {
      try {
        await api("/admin/api/self-test/run", { method: "POST" });
        addHistory("started self test");
        toast("Self test started");
      } catch (err) {
        if (Number(err.status || 0) === 409) {
          addHistory("self test already running");
          toast("Self test already running");
        } else {
          throw err;
        }
      }
      await loadSelfTest();
    }

    function renderSelfTest() {
      const s = state.selfTest || {};
      const report = s.last_report || null;
      const runButton = document.getElementById("selftest-run");
      if (runButton) runButton.disabled = !!s.running;
      const runningTag = s.running ? "<span class=\"tag warn\">RUNNING</span>" : "<span class=\"tag ok\">IDLE</span>";
      const started = s.started_at ? "<code>" + esc(s.started_at) + "</code>" : "<code>-</code>";
      const runningFor = s.running_for ? "<span class=\"pill\">running_for " + esc(s.running_for) + "</span>" : "";

      if (!report) {
        document.getElementById("selftest-out").innerHTML =
          "<div class=\"row\"><span class=\"pill\">run_id " + esc(s.run_id || 0) + "</span>" + runningTag + "<span class=\"pill\">started " + started + "</span>" + runningFor + "</div>" +
          "<div class=\"muted\">No self-test results yet. Run a self test to capture suite output.</div>";
        return;
      }

      const summaryGrid = [
        ["Passed", report.passed || 0],
        ["Failed", report.failed || 0],
        ["Skipped", report.skipped || 0],
        ["Duration", report.duration || "0s"],
        ["Started", report.started_at || ""],
        ["Finished", report.finished_at || ""]
      ].map(function(kv) {
        return "<div class=\"metric\"><div class=\"k\">" + esc(kv[0]) + "</div><div class=\"v\">" + esc(kv[1]) + "</div></div>";
      }).join("");

      const suites = (report.suites || []).map(function(suite) {
        const stepRows = (suite.steps || []).map(function(step) {
          const cls = step.result === "FAIL" ? "bad" : (step.result === "SKIP" ? "warn" : "ok");
          const detail = step.error ? "<code>" + esc(step.error) + "</code>" : (step.note ? "<code>" + esc(step.note) + "</code>" : "");
          return [
            "<span class=\"tag " + cls + "\">" + esc(step.result || "") + "</span>",
            "<code>" + esc(step.name || "") + "</code>",
            "<code>" + esc(step.want || "") + "</code>",
            "<code>" + esc(step.got || "") + "</code>",
            "<code>" + esc(step.duration || "") + "</code>",
            detail
          ];
        });
        const activeUserActions = (suite.user_actions || []).map(function(userBlock) {
          const activeSessions = (userBlock.sessions || []).filter(function(sessionBlock) {
            return (sessionBlock.actions || []).length > 0;
          });
          if (!activeSessions.length) return null;
          return {
            user: userBlock,
            sessions: activeSessions
          };
        }).filter(Boolean);

        const userActionBlocks = activeUserActions.map(function(userEntry) {
          const userBlock = userEntry.user;
          const sessionBlocks = userEntry.sessions.map(function(sessionBlock) {
            const actions = (sessionBlock.actions || []).map(function(a) {
              return {
                id: a.id,
                timestamp: a.timestamp,
                time: a.time,
                event: a.event,
                path: a.path,
                meta: a.meta
              };
            });
            return "<div class=\"suite-session\">" +
              "<div class=\"muted\">session=" + sessionCell(sessionBlock.session || "") + " ip=" + ipCell(sessionBlock.ip || "") + " duration=<code>" + esc(formatMs(secondsToMs(sessionBlock.duration_sec))) + "</code></div>" +
              renderActionTimeline(actions, { empty: "No actions for this session" }) +
            "</div>";
          }).join("");

          return "<div class=\"suite-user\">" +
            "<h3>User " + ownerCell(userBlock.user_id) + " <span class=\"pill\">" + esc(userBlock.user_label || "") + "</span></h3>" +
            sessionBlocks +
          "</div>";
        }).join("");

        const suiteWindow = "<div class=\"muted\">started=<code>" + esc(suite.started_at || "") + "</code> finished=<code>" + esc(suite.finished_at || "") + "</code></div>";
        return "<h3>" + esc(suite.name || "") + " <span class=\"pill\">pass " + esc(suite.passed || 0) + "</span> <span class=\"pill\">fail " + esc(suite.failed || 0) + "</span> <span class=\"pill\">skip " + esc(suite.skipped || 0) + "</span> <span class=\"pill\">dur " + esc(suite.duration || "0s") + "</span></h3>" +
          suiteWindow +
          renderSimpleTable(["Result", "Step", "Want", "Got", "Duration", "Detail"], stepRows) +
          "<h3>Test User Actions</h3>" +
          (userActionBlocks || "<div class=\"muted\">No captured test-user actions for this suite.</div>");
      }).join("");

      const reportError = report.error ? "<div class=\"tag bad\">Run error: " + esc(report.error) + "</div>" : "";
      document.getElementById("selftest-out").innerHTML =
        "<div class=\"row\"><span class=\"pill\">run_id " + esc(s.run_id || 0) + "</span>" + runningTag + "<span class=\"pill\">started " + started + "</span>" + runningFor + "</div>" +
        reportError +
        "<h3>Latest Run Summary</h3><div class=\"grid\">" + summaryGrid + "</div>" +
        "<h3>Suites</h3>" + suites;
    }

    function loadOneTimeLogins() {
      setTabCount("logins", state.oneTimeLogins.length || null);
      renderOneTimeLogins();
      return Promise.resolve();
    }
    function renderOneTimeLogins() {
      const entries = state.oneTimeLogins || [];
      if (!entries.length) {
        document.getElementById("logins-out").innerHTML = "<div class=\"muted\">Generate a one-time login URL to get a link and QR code that logs in once.</div>";
        return;
      }
      const blocks = entries.map(function(item, idx) {
        const url = String(item.url || "");
        const qr = String(item.qr_png_data_url || "");
        const created = String(item.created_at || "");
        const encURL = encodeURIComponent(url);
        return "<div class=\"login-url-item\">" +
          "<div class=\"row\"><span class=\"pill\">URL " + esc(idx + 1) + "</span><span class=\"pill\">created <code>" + esc(created || "-") + "</code></span></div>" +
          "<div class=\"row\"><a class=\"nav-link\" href=\"" + esc(url) + "\" target=\"_blank\" rel=\"noopener noreferrer\">Open Link</a>" +
            "<button class=\"tiny\" onclick=\"copyText(decodeURIComponent('" + encURL + "'))\">Copy Link</button></div>" +
          "<div class=\"muted\"><code>" + esc(url) + "</code></div>" +
          (qr ? ("<div class=\"login-url-qr\"><img class=\"login-qr\" src=\"" + esc(qr) + "\" alt=\"one-time login qr code\" /></div>") : "") +
        "</div>";
      }).join("");
      document.getElementById("logins-out").innerHTML = blocks;
    }
    async function generateOneTimeLoginURL() {
      const d = await api("/admin/api/one-time-login", { method: "POST" });
      const item = {
        url: d.url || "",
        qr_png_data_url: d.qr_png_data_url || "",
        created_at: d.created_at || new Date().toISOString()
      };
      state.oneTimeLogins.unshift(item);
      if (state.oneTimeLogins.length > 30) state.oneTimeLogins = state.oneTimeLogins.slice(0, 30);
      setTabCount("logins", state.oneTimeLogins.length);
      renderOneTimeLogins();
      addHistory("generated one-time login URL");
      toast("Generated one-time login URL");
    }

    async function openActor(type, value) {
      if (!value) return;
      const d = await api(withRange("/admin/api/actor?type=" + encodeURIComponent(type) + "&value=" + encodeURIComponent(value)));
      state.actor = d || null;
      renderActorDrawer();
      document.getElementById("actor-drawer").classList.remove("hidden");
    }
    function renderActorDrawer() {
      if (!state.actor) return;
      const d = state.actor;
      const s = d.summary || {};
      const stats = s.user_stats || {};
      const isUser = d.actor_type === "user";
      const actorDisplay = isUser ? ownerCell(d.actor) : ipCell(d.actor);

      const uploadRows = (d.recent_uploads || []).slice(0, 20).map(function(u) {
        return ["<code>" + esc(u.time || "") + "</code>", pathWithExplorer(u.path || "", false), esc(formatBytes(u.delta || 0)), sessionCell(u.session), renderAuditMeta(u.meta || "", u.path || "", "upload")];
      });
      const sessionRows = (d.sessions || []).slice(0, 20).map(function(x) {
        return [sessionCell(x.session), esc((x.event_count || 0)), esc((x.duration_sec || 0) + "s"), esc(x.denied_count || 0)];
      });
      const eventRows = (d.events || []).slice(0, 30).map(function(e) {
        return ["<code>" + esc(e.time || "") + "</code>", "<code>" + esc(e.event || "") + "</code>", pathWithExplorer(e.path || ""), sessionCell(e.session), renderAuditMeta(e.meta || "", e.path || "", e.event || "")];
      });

      const actionButtons = isUser ?
        "<button class=\"btn-danger tiny\" onclick=\"userAction('" + esc(d.actor) + "','ban')\">Ban</button> " +
        "<button class=\"btn-good tiny\" onclick=\"userAction('" + esc(d.actor) + "','unban')\">Unban</button> " +
        "<button class=\"btn-danger tiny\" onclick=\"userAction('" + esc(d.actor) + "','purge')\">Purge</button>"
        :
        "<button class=\"btn-danger tiny\" onclick=\"banIPDirect('" + esc(d.actor) + "')\">Ban IP</button> " +
        "<button class=\"btn-good tiny\" onclick=\"unbanIP('" + esc(d.actor) + "')\">Unban IP</button>";

      document.getElementById("actor-out").innerHTML =
        "<div class=\"row\"><h3>Actor Drawer</h3><button class=\"tiny\" onclick=\"closeActorDrawer()\">Close</button></div>" +
        "<div class=\"row\"><span class=\"pill\">" + esc(d.actor_type || "") + "</span><b>" + actorDisplay + "</b>" +
          "<span class=\"tag " + (s.is_banned ? "bad" : "ok") + "\">" + (s.is_banned ? "BANNED" : "ACTIVE") + "</span>" +
          actionButtons +
        "</div>" +
        (isUser ? "<div class=\"muted\">seen=" + esc(stats.seen || 0) +
          " upload_count=" + esc(stats.upload_count || 0) + " upload_bytes=" + esc(formatBytes(stats.upload_bytes || 0)) +
          " download_count=" + esc(stats.download_count || 0) + " download_bytes=" + esc(formatBytes(stats.download_bytes || 0)) +
          " last_login=<code>" + esc(stats.last_login || "") + "</code>" +
          " last_address=<code>" + esc(stats.last_address || "") + "</code></div>" : "") +
        "<h3>Recent Uploads</h3>" + renderSimpleTable(["Time", "Path", "Delta", "Session", "Meta"], uploadRows) +
        "<h3>Sessions</h3>" + renderSimpleTable(["Session", "Events", "Duration", "Denied"], sessionRows) +
        "<h3>Recent Events</h3>" + renderSimpleTable(["Time", "Event", "Path", "Session", "Meta"], eventRows);
    }

    async function userAction(hash, action) {
      if (!hash || hash === "system") return;
      if (action === "purge" && !confirm("Purge " + hash + "? This deletes files and metadata.")) return;
      const resp = await api("/admin/api/users/" + encodeURIComponent(hash) + "/" + action, { method: "POST" });
      const userID = (resp && resp.user) ? resp.user : hash;
      toast((action + " " + shortHash(userID)).toUpperCase());
      addHistory(action + " owner " + userID);
      await Promise.all([loadUsers(), loadBanned(), loadAudit(), loadSessions(), loadUploads()]);
      if (state.actor && state.actor.actor_type === "user" && state.actor.actor === userID) {
        await openActor("user", userID);
      }
    }

    async function banIP() {
      const ip = document.getElementById("ban-ip").value.trim();
      if (!ip) return;
      await api("/admin/api/banned/ip", { method: "POST", body: JSON.stringify({ ip: ip }) });
      document.getElementById("ban-ip").value = "";
      toast("BANNED IP " + ip);
      addHistory("banned ip " + ip);
      await Promise.all([loadBanned(), loadAudit(), loadSessions()]);
    }
    async function banIPDirect(ip) {
      const value = String(ip || "").trim();
      if (!value) return;
      await api("/admin/api/banned/ip", { method: "POST", body: JSON.stringify({ ip: value }) });
      toast("BANNED IP " + value);
      addHistory("banned ip " + value);
      await Promise.all([loadBanned(), loadAudit(), loadSessions()]);
      if (state.actor && state.actor.actor_type === "ip" && state.actor.actor === value) {
        await openActor("ip", value);
      }
    }
    async function unbanIP(ip) {
      await api("/admin/api/banned/ip/" + encodeURIComponent(ip), { method: "DELETE" });
      toast("UNBANNED IP " + ip);
      addHistory("unbanned ip " + ip);
      await Promise.all([loadBanned(), loadAudit(), loadSessions()]);
      if (state.actor && state.actor.actor_type === "ip" && state.actor.actor === ip) {
        await openActor("ip", ip);
      }
    }

    async function quickBanOwner() {
      const hash = document.getElementById("quick-owner").value.trim();
      if (!hash) return;
      await userAction(hash, "ban");
    }
    async function quickUnbanOwner() {
      const hash = document.getElementById("quick-owner").value.trim();
      if (!hash) return;
      await userAction(hash, "unban");
    }
    function quickOpenOwner() {
      const hash = document.getElementById("quick-owner").value.trim();
      if (!hash) return;
      openActor("user", hash).catch(function(err) { setStatus("error: " + err.message); });
    }
    async function quickBanIP() {
      const ip = document.getElementById("quick-ip").value.trim();
      if (!ip) return;
      await banIPDirect(ip);
      document.getElementById("quick-ip").value = "";
    }
    function quickOpenIP() {
      const ip = document.getElementById("quick-ip").value.trim();
      if (!ip) return;
      openActor("ip", ip).catch(function(err) { setStatus("error: " + err.message); });
    }

    function exportUsersCSV() {
      const lines = ["hash,last_login,seen,upload_count,upload_bytes,download_count,download_bytes,is_banned"];
      (state.users || []).forEach(function(u) {
        lines.push([
          csvEscape(u.hash), csvEscape(u.last_login), csvEscape(u.seen), csvEscape(u.upload_count), csvEscape(u.upload_bytes),
          csvEscape(u.download_count), csvEscape(u.download_bytes), csvEscape(u.is_banned)
        ].join(","));
      });
      download("sftpguy-users.csv", lines.join("\n"));
      addHistory("exported users csv");
      toast("Exported users CSV");
    }
    function exportAuditCSV() {
      const lines = ["id,time,event,user_id,ip,session,path,meta"];
      (state.audit || []).forEach(function(e) {
        lines.push([
          csvEscape(e.id), csvEscape(e.time), csvEscape(e.event), csvEscape(e.user_id), csvEscape(e.ip),
          csvEscape(e.session), csvEscape(e.path), csvEscape(e.meta)
        ].join(","));
      });
      download("sftpguy-audit.csv", lines.join("\n"));
      addHistory("exported audit csv");
      toast("Exported audit CSV");
    }

    function changeRange() {
      state.timeRange = document.getElementById("time-range").value;
      localStorage.setItem("sftpguy_admin_range", state.timeRange);
      Object.keys(state.table).forEach(function(k) { state.table[k].page = 1; });
      addHistory("changed range to " + state.timeRange);
      refreshAll();
    }
    function changePageSize() {
      state.pageSize = Number(document.getElementById("table-page-size").value || "50");
      localStorage.setItem("sftpguy_admin_page_size", String(state.pageSize));
      Object.keys(state.table).forEach(function(k) { state.table[k].page = 1; });
      addHistory("changed rows/page to " + state.pageSize);
      rerenderCurrent();
    }

    function rerenderCurrent() {
      if (state.activeTab === "summary") renderSummary();
      if (state.activeTab === "live") renderLive();
      if (state.activeTab === "users") renderUsers();
      if (state.activeTab === "files") renderFiles();
      if (state.activeTab === "audit") renderAudit();
      if (state.activeTab === "logs") renderLogs();
      if (state.activeTab === "auth") renderAuthAttempts();
      if (state.activeTab === "sessions") renderSessions();
      if (state.activeTab === "uploads") renderUploads();
      if (state.activeTab === "downloads") renderDownloads();
      if (state.activeTab === "banned") renderBanned();
      if (state.activeTab === "selftest") renderSelfTest();
      if (state.activeTab === "logins") renderOneTimeLogins();
      if (state.activeTab === "maintenance") renderMaintenance();
      if (state.activeTab === "iplists") renderIPLists();
      renderActorDrawer();
      renderSessionTimeline();
    }

    const adminTabs = ["summary","live","users","files","audit","logs","auth","sessions","uploads","downloads","banned","selftest","logins","iplists","maintenance"];

    function isAdminTab(name) {
      return adminTabs.includes(name);
    }

    function loaderForTab(name) {
      return name === "summary" ? loadSummary :
        name === "live" ? loadLive :
        name === "users" ? loadUsers :
        name === "files" ? loadFiles :
        name === "audit" ? loadAudit :
        name === "logs" ? loadLogs :
        name === "auth" ? loadAuthAttempts :
        name === "sessions" ? loadSessions :
        name === "uploads" ? loadUploads :
        name === "downloads" ? loadDownloads :
        name === "banned" ? loadBanned :
        name === "selftest" ? loadSelfTest :
        name === "logins" ? loadOneTimeLogins :
        name === "maintenance" ? loadMaintenance : loadIPLists;
    }

    function loadTab(name) {
      return loaderForTab(name)().catch(function(err) { setStatus("error: " + err.message); });
    }

    async function refreshAll() {
      try {
        await Promise.all([loadSummary(), loadLive(), loadUsers(), loadFiles(), loadAudit(), loadLogs(), loadAuthAttempts(), loadSessions(), loadUploads(), loadDownloads(), loadBanned(), loadSelfTest()]);
        if (state.activeTab === "logins") {
          await loadOneTimeLogins();
        }
        if (state.activeTab === "maintenance") {
          await loadMaintenance();
        }
        if (state.activeTab === "iplists") {
          await loadIPLists();
        }
        if (state.fileSearch && (state.fileSearch.q || state.fileSearch.owner)) {
          await runFileSearch(state.fileSearch.q, state.fileSearch.owner);
        }
        if (state.actor) {
	          await openActor(state.actor.actor_type, state.actor.actor);
	        }
        if (state.sessionTimeline && state.sessionTimeline.session) {
          await openSessionTimeline(state.sessionTimeline.session);
        }
        toast("Refreshed");
      } catch (err) {
        setStatus("error: " + err.message);
      }
    }

    function toggleAutoRefresh() {
      const enabled = document.getElementById("auto-refresh").checked;
      const seconds = Number(document.getElementById("auto-seconds").value || "30");
      clearInterval(state.autoTimer);
      state.autoTimer = 0;
      if (enabled) {
        state.autoTimer = setInterval(function() {
          const fn = state.activeTab === "summary" ? loadSummary :
            state.activeTab === "live" ? loadLive :
            state.activeTab === "users" ? loadUsers :
            state.activeTab === "files" ? loadFiles :
            state.activeTab === "audit" ? loadAudit :
            state.activeTab === "logs" ? loadLogs :
            state.activeTab === "auth" ? loadAuthAttempts :
            state.activeTab === "sessions" ? loadSessions :
          state.activeTab === "uploads" ? loadUploads :
          state.activeTab === "downloads" ? loadDownloads :
          state.activeTab === "banned" ? loadBanned :
          state.activeTab === "selftest" ? loadSelfTest :
          state.activeTab === "logins" ? loadOneTimeLogins :
          state.activeTab === "maintenance" ? loadMaintenance : loadIPLists;
          fn().catch(function(err) { setStatus("error: " + err.message); });
        }, seconds * 1000);
        addHistory("enabled auto-refresh every " + seconds + "s");
      } else {
        addHistory("disabled auto-refresh");
      }
    }

    function switchTab(name) {
      state.activeTab = name;
      document.querySelectorAll(".tab").forEach(function(btn) {
        btn.classList.toggle("active", btn.dataset.tab === name);
      });
      adminTabs.forEach(function(p) {
        document.getElementById("tab-" + p).classList.toggle("hidden", p !== name);
      });
      if (name !== "selftest") {
        clearSelfTestPoll();
      }
      return loadTab(name);
    }

    document.getElementById("tabs").addEventListener("click", function(e) {
      const tab = e.target.closest(".tab");
      if (tab) switchTab(tab.dataset.tab);
    });

    window.addEventListener("keydown", function(e) {
      if (e.altKey && ["1","2","3","4","5","6","7","8","9","0","-","=","]","["].includes(e.key)) {
        const map = {"1":"summary","2":"users","3":"files","4":"audit","5":"logs","6":"auth","7":"sessions","8":"uploads","9":"banned","0":"selftest","-":"logins","=":"iplists","]":"maintenance","[":"downloads"};
        switchTab(map[e.key]);
      }
      if (e.key === "Escape") {
        closeActorDrawer();
        closeSessionTimeline();
      }
      if (e.shiftKey && e.key.toLowerCase() === "r") {
        refreshAll();
      }
      if (e.shiftKey && e.key.toLowerCase() === "l") {
        const cb = document.getElementById("logs-live");
        cb.checked = !cb.checked;
        toggleLogLive();
      }
    });

    (async function boot() {
      const startup = bootParams();
      document.getElementById("time-range").value = state.timeRange;
      document.getElementById("table-page-size").value = String(state.pageSize);
      try {
        if (startup.owner) {
          await switchTab("files");
          await searchFilesByOwner(startup.owner);
          return;
        }
        const startupTab = isAdminTab(startup.tab) ? startup.tab : "summary";
        await switchTab(startupTab);
        if (startupTab === "files" && startup.q) {
          document.getElementById("files-q").value = startup.q;
          await searchFiles();
        }
      } catch (err) {
        setStatus("error: " + err.message);
      }
    })();
