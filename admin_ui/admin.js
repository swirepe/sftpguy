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
      insights: {},
	      summaryUploads: [],
	      users: [],
      files: { path: ".", entries: [] },
      fileSearch: { q: "", owner: "", results: [], total: 0, offset: 0, limit: 200 },
      audit: [],
      events: [],
      authAttempts: [],
      authCombos: [],
      logCursorBefore: 0,
      logHasMore: false,
	      sessions: [],
	      uploads: [],
      banned: { hashes: [], ips: [] },
      actor: null,
      sessionTimeline: null,
      lastEventID: 0,
	      selfTest: { running: false, run_id: 0, started_at: "", running_for: "", last_report: null },
	      selfTestPollTimer: 0,
	      ipLists: {
	        whitelist: { path: "", content: "", entries: 0, invalid_count: 0, invalid_lines: [] },
	        blacklist: { path: "", content: "", entries: 0, invalid_count: 0, invalid_lines: [] },
	        test: null
	      },
	      adminKeys: { path: "", content: "", entries: 0, invalid_count: 0, invalid_lines: [], hashes: [] }
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
        const detail = a.path ? String(a.path) : (a.meta ? String(a.meta) : "");
        return "<div class=\"timeline-item\">" +
          "<code class=\"timeline-offset\">+" + esc(formatMs(offset)) + "</code>" +
          "<code class=\"timeline-time\">" + esc(a.time || "") + "</code>" +
          "<span class=\"evt-chip " + tone + "\">" + esc(String(a.event || "").toUpperCase()) + "</span>" +
          "<code class=\"timeline-detail\">" + esc(detail) + "</code>" +
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
        ["Total Disk", d.formatted_bytes || "0 B"],
        ["Contrib Threshold", formatBytes(d.contributor_threshold || 0)]
      ];
      const activity = [
        ["Events", kpi.events || 0],
        ["Users Active", kpi.users || 0],
        ["IPs Active", kpi.ips || 0],
        ["Logins", kpi.logins || 0],
        ["Uploads", kpi.uploads || 0],
        ["Downloads", kpi.downloads || 0],
        ["Denied", kpi.denied || 0],
        ["Admin Actions", kpi.admin_actions || 0],
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
          "<code>" + esc(x.path || "") + "</code>",
          esc(formatBytes(x.delta || 0)),
          sessionCell(x.session)
        ];
      });

      document.getElementById("tab-summary").innerHTML =
        "<div class=\"row\"><span class=\"pill\">Window " + esc(win.label || state.timeRange) + "</span></div>" +
        "<div class=\"grid\">" + entries.map(function(kv) {
          return "<div class=\"metric\"><div class=\"k\">" + esc(kv[0]) + "</div><div class=\"v\">" + esc(kv[1]) + "</div></div>";
        }).join("") + "</div>" +
        "<h3>Activity</h3><div class=\"grid\">" + activity.map(function(kv) {
          return "<div class=\"metric\"><div class=\"k\">" + esc(kv[0]) + "</div><div class=\"v\">" + esc(kv[1]) + "</div></div>";
        }).join("") + "</div>" +
        "<h3>Top Events</h3>" + renderSimpleTable(["Event", "Count"], topEventsRows) +
        "<h3>Top Users</h3>" + renderSimpleTable(["User", "Events", "Denied"], topUsersRows) +
        "<h3>Top IPs</h3>" + renderSimpleTable(["IP", "Events", "Denied", "Action"], topIPRows) +
        "<h3>Recent Uploads (Quick View)</h3>" + renderSimpleTable(["Time", "User", "Path", "Delta", "Session"], quickUploadRows);
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
            upload_bytes: Number(u.upload_bytes || 0),
            download_bytes: Number(u.download_bytes || 0),
            banned: u.is_banned ? 1 : 0
          },
          cells: [
            ownerCell(u.hash),
            esc(u.last_login || ""),
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
	              size: Number(e.size || 0),
	              is_dir: e.is_dir ? 1 : 0
	            },
	            cells: [
	              e.is_dir ? "<button onclick=\"openPath('" + esc(e.path) + "')\"><code>" + esc(e.path) + "/</code></button>" : "<code>" + esc(e.path) + "</code>",
	              ownerCell(e.owner || "-"),
	              esc(e.size_human || formatBytes(e.size || 0)),
	              e.is_dir ? "<span class=\"tag ok\">DIR</span>" : "<span class=\"tag\">FILE</span>"
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
	              {label:"Size", key:"size"},
	              {label:"Type", key:"is_dir"}
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
            size: Number(e.size || 0),
            is_dir: e.is_dir ? 1 : 0
          },
          cells: [
            e.is_dir ? "<button onclick=\"openPath('" + esc(e.path) + "')\">" + esc(e.name) + "/</button>" : esc(e.name),
            ownerCell(e.owner || "-"),
            esc(e.size_human || formatBytes(e.size || 0)),
            e.is_dir ? "<span class=\"tag ok\">DIR</span>" : "<span class=\"tag\">FILE</span>"
          ]
        };
      });
	      document.getElementById("files-out").innerHTML = "<div class=\"muted\">path=<code>" + esc(state.files.path) + "</code></div>" +
	        renderSmartTable(
	          "files",
	          [
	            {label:"Name", key:"name"},
            {label:"Owner", key:"owner"},
            {label:"Size", key:"size"},
            {label:"Type", key:"is_dir"}
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

    async function loadAudit() {
      const q = document.getElementById("audit-q").value.trim();
      const d = await api(withRange("/admin/api/audit?q=" + encodeURIComponent(q) + "&limit=1000"));
      state.audit = d.events || [];
      setTabCount("audit", state.audit.length);
      renderAudit();
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
            "<code>" + esc(e.event || "") + "</code>",
            ownerCell(e.user_id),
            ipCell(e.ip),
            sessionCell(e.session),
            "<code>" + esc(e.path || "") + "</code>",
            "<code>" + esc(e.meta || "") + "</code>"
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
	      const d = await api(withRange("/admin/api/events?q=" + encodeURIComponent(q) + "&limit=600&before_id=" + encodeURIComponent(before)));
	      state.events = d.events || [];
	      state.lastEventID = d.last_id || (state.events.length ? state.events[0].id : 0);
	      state.logCursorBefore = Number(d.next_before_id || 0);
	      state.logHasMore = !!d.has_more;
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
            "<code>" + esc(e.event || "") + "</code>",
            ownerCell(e.user_id),
            ipCell(e.ip),
            sessionCell(e.session),
            "<code>" + esc(e.path || "") + "</code>",
            "<button class=\"btn-danger tiny\" onclick=\"banIPDirect('" + esc(e.ip || "") + "')\">Ban IP</button>"
          ]
        };
      });
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
        );
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
            path: u.path || ""
          },
          cells: [
            "<code>" + esc(u.time || "") + "</code>",
            ownerCell(u.user_id),
            ipCell(u.ip),
            "<code>" + esc(u.path || "") + "</code>",
            esc(formatBytes(u.delta || 0)),
            esc(formatBytes(u.size || 0)),
            sessionCell(u.session)
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
          {label:"Session", key:"id"}
        ],
        rows,
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

	    async function loadIPLists() {
	      const out = await Promise.all([api("/admin/api/ip-lists"), api("/admin/api/admin-keys")]);
	      const d = out[0] || {};
	      const k = out[1] || {};
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

	      const wlEditor = document.getElementById("iplist-whitelist-content");
	      const blEditor = document.getElementById("iplist-blacklist-content");
	      const akEditor = document.getElementById("admin-keys-content");
	      if (wlEditor && document.activeElement !== wlEditor) wlEditor.value = state.ipLists.whitelist.content || "";
	      if (blEditor && document.activeElement !== blEditor) blEditor.value = state.ipLists.blacklist.content || "";
	      if (akEditor && document.activeElement !== akEditor) akEditor.value = state.adminKeys.content || "";

      setTabCount("iplists", null);
      renderIPLists();
    }

	    function renderIPLists() {
	      const wl = (state.ipLists || {}).whitelist || {};
	      const bl = (state.ipLists || {}).blacklist || {};
	      const test = (state.ipLists || {}).test || null;
	      const ak = state.adminKeys || {};

	      const wlMeta = "path=<code>" + esc(wl.path || "") + "</code> entries=" + esc(wl.entries || 0) + " invalid=" + esc(wl.invalid_count || 0);
	      const blMeta = "path=<code>" + esc(bl.path || "") + "</code> entries=" + esc(bl.entries || 0) + " invalid=" + esc(bl.invalid_count || 0);
	      const akMeta = "path=<code>" + esc(ak.path || "") + "</code> entries=" + esc(ak.entries || 0) + " invalid=" + esc(ak.invalid_count || 0);
	      document.getElementById("iplist-whitelist-meta").innerHTML = wlMeta;
	      document.getElementById("iplist-blacklist-meta").innerHTML = blMeta;
	      document.getElementById("admin-keys-meta").innerHTML = akMeta;
	      document.getElementById("iplist-whitelist-invalid").innerHTML = (wl.invalid_lines || []).length
	        ? ("Invalid lines: <code>" + esc((wl.invalid_lines || []).join(", ")) + "</code>")
	        : "";
	      document.getElementById("iplist-blacklist-invalid").innerHTML = (bl.invalid_lines || []).length
	        ? ("Invalid lines: <code>" + esc((bl.invalid_lines || []).join(", ")) + "</code>")
	        : "";
	      document.getElementById("admin-keys-invalid").innerHTML = (ak.invalid_lines || []).length
	        ? ("Invalid lines: <code>" + esc((ak.invalid_lines || []).join(", ")) + "</code>")
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
          "<span class=\"tag " + (m.db_banned ? "warn" : "") + "\">db_banned=" + esc(m.db_banned ? "yes" : "no") + "</span>" +
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
        return ["<code>" + esc(u.time || "") + "</code>", "<code>" + esc(u.path || "") + "</code>", esc(formatBytes(u.delta || 0)), sessionCell(u.session)];
      });
      const sessionRows = (d.sessions || []).slice(0, 20).map(function(x) {
        return [sessionCell(x.session), esc((x.event_count || 0)), esc((x.duration_sec || 0) + "s"), esc(x.denied_count || 0)];
      });
      const eventRows = (d.events || []).slice(0, 30).map(function(e) {
        return ["<code>" + esc(e.time || "") + "</code>", "<code>" + esc(e.event || "") + "</code>", "<code>" + esc(e.path || "") + "</code>", sessionCell(e.session)];
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
        (isUser ? "<div class=\"muted\">upload_count=" + esc(stats.upload_count || 0) + " upload_bytes=" + esc(formatBytes(stats.upload_bytes || 0)) +
          " download_count=" + esc(stats.download_count || 0) + " download_bytes=" + esc(formatBytes(stats.download_bytes || 0)) +
          " last_login=<code>" + esc(stats.last_login || "") + "</code></div>" : "") +
        "<h3>Recent Uploads</h3>" + renderSimpleTable(["Time", "Path", "Delta", "Session"], uploadRows) +
        "<h3>Sessions</h3>" + renderSimpleTable(["Session", "Events", "Duration", "Denied"], sessionRows) +
        "<h3>Recent Events</h3>" + renderSimpleTable(["Time", "Event", "Path", "Session"], eventRows);
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
      const lines = ["hash,last_login,upload_count,upload_bytes,download_count,download_bytes,is_banned"];
      (state.users || []).forEach(function(u) {
        lines.push([
          csvEscape(u.hash), csvEscape(u.last_login), csvEscape(u.upload_count), csvEscape(u.upload_bytes),
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
      if (state.activeTab === "users") renderUsers();
      if (state.activeTab === "files") renderFiles();
      if (state.activeTab === "audit") renderAudit();
      if (state.activeTab === "logs") renderLogs();
      if (state.activeTab === "auth") renderAuthAttempts();
      if (state.activeTab === "sessions") renderSessions();
      if (state.activeTab === "uploads") renderUploads();
      if (state.activeTab === "banned") renderBanned();
      if (state.activeTab === "selftest") renderSelfTest();
      if (state.activeTab === "iplists") renderIPLists();
      renderActorDrawer();
      renderSessionTimeline();
    }

    async function refreshAll() {
      try {
        await Promise.all([loadSummary(), loadUsers(), loadFiles(), loadAudit(), loadLogs(), loadAuthAttempts(), loadSessions(), loadUploads(), loadBanned(), loadSelfTest()]);
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
            state.activeTab === "users" ? loadUsers :
            state.activeTab === "files" ? loadFiles :
            state.activeTab === "audit" ? loadAudit :
            state.activeTab === "logs" ? loadLogs :
            state.activeTab === "auth" ? loadAuthAttempts :
            state.activeTab === "sessions" ? loadSessions :
            state.activeTab === "uploads" ? loadUploads :
            state.activeTab === "banned" ? loadBanned :
            state.activeTab === "selftest" ? loadSelfTest : loadIPLists;
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
      ["summary","users","files","audit","logs","auth","sessions","uploads","banned","selftest","iplists"].forEach(function(p) {
        document.getElementById("tab-" + p).classList.toggle("hidden", p !== name);
      });
      if (name !== "selftest") {
        clearSelfTestPoll();
      }
      const fn = name === "summary" ? loadSummary :
        name === "users" ? loadUsers :
        name === "files" ? loadFiles :
        name === "audit" ? loadAudit :
        name === "logs" ? loadLogs :
        name === "auth" ? loadAuthAttempts :
        name === "sessions" ? loadSessions :
        name === "uploads" ? loadUploads :
        name === "banned" ? loadBanned :
        name === "selftest" ? loadSelfTest : loadIPLists;
      fn().catch(function(err) { setStatus("error: " + err.message); });
    }

    document.getElementById("tabs").addEventListener("click", function(e) {
      const tab = e.target.closest(".tab");
      if (tab) switchTab(tab.dataset.tab);
    });

    window.addEventListener("keydown", function(e) {
      if (e.altKey && ["1","2","3","4","5","6","7","8","9","0","-"].includes(e.key)) {
        const map = {"1":"summary","2":"users","3":"files","4":"audit","5":"logs","6":"auth","7":"sessions","8":"uploads","9":"banned","0":"selftest","-":"iplists"};
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
        await refreshAll();
        if (startup.owner) {
          switchTab("files");
          await searchFilesByOwner(startup.owner);
          return;
        }
        if (startup.tab && ["summary","users","files","audit","logs","auth","sessions","uploads","banned","selftest","iplists"].includes(startup.tab)) {
          switchTab(startup.tab);
          if (startup.tab === "files" && startup.q) {
            document.getElementById("files-q").value = startup.q;
            await searchFiles();
          }
        }
      } catch (err) {
        setStatus("error: " + err.message);
      }
    })();
