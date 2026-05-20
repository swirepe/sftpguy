import type { ComponentChildren } from "preact";
import { useEffect, useMemo, useState } from "preact/hooks";
import { useMutation, useQuery, useQueryClient } from "@tanstack/preact-query";
import {
  api,
  fetchBlobURL,
  postJSON,
  previewURL,
  type DownloadFileRow,
  type EventRow,
  type LivePayload,
  type PreviewPayload,
  type SummaryPayload,
  type UploadRow
} from "./api";

type View = "overview" | "activity" | "thumbnails" | "users" | "security";
type SourceFilter = "all" | "sftp" | "admin" | "explorer";
type ActivityKind = "all" | "attention" | "denied" | "transfer" | "mutating" | "session" | "exec";
type ActorType = "ip" | "user";
type LiveTargetKind = "connection" | "session" | "transfer" | "request";
type MetricTarget = {
  title: string;
  value: string;
  summary?: string;
  rows: InsightRow[];
};
type InspectorTarget =
  | { type: "none" }
  | { type: "path"; path: string }
  | { type: "event"; event: EventRow }
  | { type: "user"; user: UserRow }
  | { type: "actor"; actorType: ActorType; value: string }
  | { type: "live"; liveType: LiveTargetKind; row: Record<string, unknown> }
  | { type: "metric"; metric: MetricTarget };
type ThumbnailKind = "image" | "video" | "pdf" | "archive" | "text" | "model" | "directory" | "other";
type ThumbnailFilter = "all" | "visual" | ThumbnailKind;
type ThumbnailSort = "recent" | "kind" | "source" | "name";
type ThumbnailSize = "compact" | "normal" | "large";
type ThumbnailMode = "grid" | "list";
type UserFilter = "all" | "active" | "uploaders" | "downloaders" | "banned" | "quiet";
type UserSort = "activity" | "uploads" | "downloads" | "sessions" | "last_login";
type InsightRow = { label: string; value?: string };

type EventsPayload = {
  events?: EventRow[];
  window?: { label?: string };
};

type UploadsPayload = {
  uploads?: UploadRow[];
};

type DownloadsPayload = {
  files?: DownloadFileRow[];
  recent?: EventRow[];
  summary?: Record<string, number>;
};

type NamedCount = {
  name: string;
  count: number;
};

type NamedPair = NamedCount & {
  denied?: number;
};

type DeviceStat = NamedCount & {
  uploads?: number;
  downloads?: number;
  denied?: number;
  mutations?: number;
  sessions?: number;
  explorer?: number;
  top_event?: string;
};

type UserAgentStat = {
  user_agent: string;
  device?: string;
  browser?: string;
  os?: string;
  count?: number;
  uploads?: number;
  downloads?: number;
  denied?: number;
  mutations?: number;
  sessions?: number;
  explorer?: number;
  last_time?: string;
  last_ip?: string;
  top_event?: string;
};

type ThumbnailCandidate = {
  path: string;
  source: string;
  detail: string;
  meta?: string;
  kind: ThumbnailKind;
};

type InsightsPayload = {
  kpi?: Record<string, number>;
  top_events?: NamedCount[];
  top_users?: NamedPair[];
  top_ips?: NamedPair[];
  suspicious_ips?: NamedPair[];
  user_agents?: UserAgentStat[];
  device_types?: DeviceStat[];
  parsed_levels?: NamedCount[];
  parsed_panics?: number;
  recent_panics?: unknown[];
};

type UserRow = {
  hash: string;
  last_login?: string;
  seen?: number;
  upload_count?: number;
  upload_bytes?: number;
  download_count?: number;
  download_bytes?: number;
  is_banned?: boolean;
};

type UsersPayload = {
  users?: UserRow[];
};

type UserStatsPayload = {
  last_login?: string;
  last_address?: string;
  seen?: number;
  upload_count?: number;
  upload_bytes?: number;
  download_count?: number;
  download_bytes?: number;
  first_timer?: boolean;
  is_banned?: boolean;
};

type UserFileRow = {
  path?: string;
  name?: string;
  owner?: string;
  downloads?: number;
  size?: number;
  size_human?: string;
  is_dir?: boolean;
};

type UserEventRow = {
  timestamp?: number;
  time?: string;
  event?: string;
  path?: string;
  meta?: string;
  ip?: string;
};

type UserDetailPayload = {
  hash?: string;
  is_banned?: boolean;
  stats?: UserStatsPayload;
  files?: UserFileRow[];
  events?: UserEventRow[];
};

type SessionRow = {
  session: string;
  user_id?: string;
  ip?: string;
  started_at?: number;
  ended_at?: number;
  start_time?: string;
  end_time?: string;
  duration_sec?: number;
  event_count?: number;
  upload_count?: number;
  download_count?: number;
  denied_count?: number;
  has_end?: boolean;
};

type SessionsPayload = {
  sessions?: SessionRow[];
};

type SessionTimelinePayload = {
  session?: string;
  user_id?: string;
  ip?: string;
  started_at?: number;
  ended_at?: number;
  start_time?: string;
  end_time?: string;
  events?: EventRow[];
};

type ActorFileRow = {
  path?: string;
  name?: string;
  owner?: string;
  size?: number;
  size_human?: string;
  is_dir?: boolean;
  event_count?: number;
  upload_count?: number;
  download_count?: number;
  denied_count?: number;
  last_time?: string;
  last_event?: string;
  last_user?: string;
  last_ip?: string;
};

type ActorDetailPayload = {
  actor_type?: ActorType;
  actor?: string;
  summary?: Record<string, unknown>;
  events?: EventRow[];
  recent_uploads?: UploadRow[];
  sessions?: SessionRow[];
  files?: ActorFileRow[];
  window?: { label?: string };
};

type BannedPayload = {
  hashes?: Array<{ hash: string; banned_at?: string }>;
  ips?: Array<{ ip: string; banned_at?: string; comment?: string }>;
};

type AuthAttemptRow = {
  id: number;
  timestamp?: number;
  time?: string;
  ip?: string;
  user_id?: string;
  session?: string;
  username?: string;
  password?: string;
  generated_hash?: string;
};

type AuthComboRow = {
  username?: string;
  password?: string;
  count?: number;
  last_timestamp?: number;
  last_time?: string;
  last_ip?: string;
};

type AuthAttemptsPayload = {
  attempts?: AuthAttemptRow[];
  combos?: AuthComboRow[];
  window?: { label?: string };
};

type InspectorAction =
  | { type: "delete"; path: string }
  | { type: "rename"; path: string; newName: string }
  | { type: "mark-bad"; path: string }
  | { type: "ban-owner"; path: string };

type UserInspectorAction = { type: "ban" | "unban"; hash: string };

const defaultHue = 174;
const rangeOptions = ["15m", "1h", "6h", "24h", "48h", "7d", "30d", "all"];

export function App() {
  const queryClient = useQueryClient();
  const initialHueParam = hasHueParam();
  const [view, setView] = useState<View>(parseViewParam());
  const [inspectorTarget, setInspectorTarget] = useState<InspectorTarget>({ type: "none" });
  const [range, setRange] = useState(readURLParam("range") || "24h");
  const [query, setQuery] = useState(readURLParam("q"));
  const [sourceFilter, setSourceFilter] = useState<SourceFilter>(parseSourceParam());
  const [activityKind, setActivityKind] = useState<ActivityKind>("all");
  const [userFilter, setUserFilter] = useState<UserFilter>("all");
  const [userSort, setUserSort] = useState<UserSort>("activity");
  const [hue, setHue] = useState(parseHueParam());
  const [hueInURL, setHueInURL] = useState(initialHueParam);

  useEffect(() => {
    document.documentElement.style.setProperty("--hue", String(hue));
    const params = {
      view: view === "overview" ? "" : view,
      range: range === "24h" ? "" : range,
      q: query,
      source: sourceFilter === "all" ? "" : sourceFilter
    };
    if (hueInURL) {
      replaceURLParams({ ...params, hue: String(hue) });
    } else {
      replaceURLParams(params);
    }
  }, [hue, hueInURL, query, range, sourceFilter, view]);

  const summary = useQuery({
    queryKey: ["summary"],
    queryFn: () => api<SummaryPayload>("/admin/api/summary"),
    refetchInterval: 30_000
  });
  const live = useQuery({
    queryKey: ["live"],
    queryFn: () => api<LivePayload>("/admin/api/live"),
    refetchInterval: 10_000
  });
  const insights = useQuery({
    queryKey: ["insights", range],
    queryFn: () => api<InsightsPayload>(adminPath("/admin/api/insights", { range })),
    refetchInterval: 30_000
  });
  const events = useQuery({
    queryKey: ["events", range, query],
    queryFn: () => api<EventsPayload>(adminPath("/admin/api/events", { limit: 160, range, q: query })),
    refetchInterval: 20_000
  });
  const uploads = useQuery({
    queryKey: ["uploads", range, query],
    queryFn: () => api<UploadsPayload>(adminPath("/admin/api/uploads/recent", { limit: 10, range, q: query })),
    refetchInterval: 20_000
  });
  const downloads = useQuery({
    queryKey: ["downloads", range, query],
    queryFn: () =>
      api<DownloadsPayload>(
        adminPath("/admin/api/downloads", {
          file_limit: 10,
          recent_limit: 12,
          downloader_limit: 10,
          range,
          q: query
        })
      ),
    refetchInterval: 30_000
  });
  const users = useQuery({
    queryKey: ["users", query],
    queryFn: () => api<UsersPayload>(adminPath("/admin/api/users", { limit: 120, q: query })),
    refetchInterval: 45_000
  });
  const sessions = useQuery({
    queryKey: ["sessions", range, query],
    queryFn: () => api<SessionsPayload>(adminPath("/admin/api/sessions", { limit: 12, range, q: query })),
    refetchInterval: 30_000
  });
  const banned = useQuery({
    queryKey: ["banned"],
    queryFn: () => api<BannedPayload>("/admin/api/banned"),
    refetchInterval: 60_000
  });
  const authAttempts = useQuery({
    queryKey: ["auth-attempts", range, query],
    queryFn: () => api<AuthAttemptsPayload>(adminPath("/admin/api/auth-attempts", { limit: 600, combo_limit: 180, range, q: query })),
    refetchInterval: 30_000
  });
  const maintenance = useQuery({
    queryKey: ["maintenance"],
    queryFn: () => api<Record<string, unknown>>("/admin/api/maintenance"),
    refetchInterval: 30_000
  });

  const runMaintenance = useMutation({
    mutationFn: () => postJSON("/admin/api/maintenance/run", {}),
    onSettled: async () => {
      await queryClient.invalidateQueries({ queryKey: ["maintenance"] });
      await queryClient.invalidateQueries({ queryKey: ["events"] });
    }
  });
  const banIP = useMutation({
    mutationFn: (ip: string) => postJSON("/admin/api/banned/ip", { ip }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["banned"] });
      await queryClient.invalidateQueries({ queryKey: ["events"] });
    }
  });

  const eventRows = events.data?.events ?? [];
  const filteredEventRows = useMemo(
    () => eventRows.filter((row) => sourceFilter === "all" || sourceFor(row) === sourceFilter),
    [eventRows, sourceFilter]
  );
  const explorerEvents = eventRows.filter((row) => sourceFor(row) === "explorer");
  const liveCount = countLive(live.data);

  function openInspector(path: string | undefined) {
    const clean = cleanPath(path);
    if (clean) {
      setInspectorTarget({ type: "path", path: clean });
    }
  }

  function inspectEvent(event: EventRow) {
    setInspectorTarget({ type: "event", event });
  }

  function inspectSession(session: SessionRow) {
    setInspectorTarget({ type: "event", event: eventFromSession(session) });
  }

  function inspectUser(user: UserRow) {
    setInspectorTarget({ type: "user", user });
  }

  function inspectActor(actorType: ActorType, value: string) {
    if (value.trim() !== "") {
      setInspectorTarget({ type: "actor", actorType, value });
    }
  }

  function inspectLive(liveType: LiveTargetKind, row: Record<string, unknown>) {
    setInspectorTarget({ type: "live", liveType, row });
  }

  function inspectMetric(metric: MetricTarget) {
    setInspectorTarget({ type: "metric", metric });
  }

  function drillSearch(value: string, nextView: View = "activity") {
    setQuery(value);
    setView(nextView);
  }

  function openActivity(kind: ActivityKind, source: SourceFilter = "all", nextQuery = "") {
    setActivityKind(kind);
    setSourceFilter(source);
    setQuery(nextQuery);
    setView("activity");
  }

  function openUsers(filter: UserFilter = "all", sort: UserSort = "activity") {
    setUserFilter(filter);
    setUserSort(sort);
    setQuery("");
    setView("users");
  }

  function updateHueFromColor(hex: string) {
    setHue(hexToHue(hex));
    setHueInURL(true);
  }

  function confirmedBanIP(ip: string) {
    const clean = ip.trim();
    if (!clean) {
      return;
    }
    if (window.confirm(`Ban IP ${clean}? This will block future access from this address.`)) {
      banIP.mutate(clean);
    }
  }

  return (
    <div class="admin-shell">
      <header class="topbar">
        <div>
          <p class="eyebrow">sftpguy admin</p>
          <h1>{summary.data?.archive || "Administration"}</h1>
        </div>
        <nav class="top-actions" aria-label="Admin navigation">
          <a href="/admin">Legacy</a>
          <a href="/admin/explorer/">Explorer</a>
          <a href="/admin/stats/">Stats</a>
        </nav>
      </header>

      <main class="workspace">
        <section class="primary">
          <Toolbar
            view={view}
            range={range}
            query={query}
            sourceFilter={sourceFilter}
            hue={hue}
            onView={setView}
            onRange={setRange}
            onQuery={setQuery}
            onSourceFilter={setSourceFilter}
            onHue={updateHueFromColor}
            onRefresh={() => queryClient.invalidateQueries()}
          />

          {view === "overview" ? (
            <Overview
              summary={summary.data}
              insights={insights.data}
              live={live.data}
              liveCount={liveCount}
              eventRows={eventRows}
              explorerEvents={explorerEvents}
              uploads={uploads.data?.uploads ?? []}
              downloads={downloads.data}
              users={users.data?.users ?? []}
              sessions={sessions.data?.sessions ?? []}
              banned={banned.data}
              maintenance={maintenance.data}
              maintenancePending={runMaintenance.isPending}
              banIPPending={banIP.isPending}
              loading={summary.isLoading || events.isLoading || insights.isLoading}
              onOpenPath={openInspector}
              onInspectEvent={inspectEvent}
              onInspectSession={inspectSession}
              onInspectUser={inspectUser}
              onInspectActor={inspectActor}
              onInspectLive={inspectLive}
              onInspectMetric={inspectMetric}
              onOpenActivity={openActivity}
              onOpenUsers={openUsers}
              onDrillSearch={drillSearch}
              onRunMaintenance={() => runMaintenance.mutate()}
              onBanIP={confirmedBanIP}
            />
          ) : view === "activity" ? (
            <Activity
              rows={filteredEventRows}
              loading={events.isLoading}
              sourceFilter={sourceFilter}
              kind={activityKind}
              onKind={setActivityKind}
              onInspectEvent={inspectEvent}
              onInspectActor={inspectActor}
            />
          ) : view === "thumbnails" ? (
            <ThumbnailView
              eventRows={filteredEventRows}
              uploads={uploads.data?.uploads ?? []}
              downloads={downloads.data}
              loading={events.isLoading || uploads.isLoading || downloads.isLoading}
              onOpenPath={openInspector}
            />
          ) : view === "users" ? (
            <UsersView
              users={users.data?.users ?? []}
              loading={users.isLoading}
              filter={userFilter}
              sort={userSort}
              onFilter={setUserFilter}
              onSort={setUserSort}
              onInspectUser={inspectUser}
            />
          ) : (
            <Security
              insights={insights.data}
              banned={banned.data}
              auth={authAttempts.data}
              loading={authAttempts.isLoading || insights.isLoading}
              banIPPending={banIP.isPending}
              onBanIP={confirmedBanIP}
              onInspectMetric={inspectMetric}
              onOpenActivity={openActivity}
              onInspectEvent={inspectEvent}
              onInspectActor={inspectActor}
            />
          )}
        </section>

        <Inspector
          target={inspectorTarget}
          range={range}
          banIPPending={banIP.isPending}
          onBanIP={confirmedBanIP}
          onInspectEvent={inspectEvent}
          onInspectUser={inspectUser}
          onInspectActor={inspectActor}
          onOpenPath={openInspector}
          onClose={() => setInspectorTarget({ type: "none" })}
        />
      </main>
    </div>
  );
}

function Toolbar(props: {
  view: View;
  range: string;
  query: string;
  sourceFilter: SourceFilter;
  hue: number;
  onView: (view: View) => void;
  onRange: (range: string) => void;
  onQuery: (query: string) => void;
  onSourceFilter: (source: SourceFilter) => void;
  onHue: (hex: string) => void;
  onRefresh: () => void;
}) {
  const [filtersOpen, setFiltersOpen] = useState(false);
  return (
    <div class="toolbar">
      <div class="toolbar-head">
        <div class="segmented" role="tablist" aria-label="Admin v2 views">
          <button class={props.view === "overview" ? "active" : ""} type="button" onClick={() => props.onView("overview")}>
            Overview
          </button>
          <button class={props.view === "activity" ? "active" : ""} type="button" onClick={() => props.onView("activity")}>
            Activity
          </button>
          <button class={props.view === "thumbnails" ? "active" : ""} type="button" onClick={() => props.onView("thumbnails")}>
            Thumbnails
          </button>
          <button class={props.view === "users" ? "active" : ""} type="button" onClick={() => props.onView("users")}>
            Users
          </button>
          <button class={props.view === "security" ? "active" : ""} type="button" onClick={() => props.onView("security")}>
            Security
          </button>
        </div>
        <div class="mobile-filter-actions">
          <button type="button" class="filter-toggle" aria-expanded={filtersOpen} onClick={() => setFiltersOpen((value) => !value)}>
            {filtersOpen ? "Hide" : "Filters"}
          </button>
          <button type="button" class="refresh-button mobile-refresh" onClick={props.onRefresh}>
            Refresh
          </button>
        </div>
      </div>

      <div class="mobile-filter-summary" aria-live="polite">
        <span>{rangeLabel(props.range)}</span>
        <span>{sourceFilterLabel(props.sourceFilter)}</span>
        <span>{props.query.trim() ? props.query.trim() : "No search"}</span>
      </div>

      <div class={`control-cluster ${filtersOpen ? "open" : ""}`}>
        <label class="control">
          <span>Range</span>
          <select value={props.range} onInput={(event) => props.onRange((event.currentTarget as HTMLSelectElement).value)}>
            {rangeOptions.map((option) => (
              <option key={option} value={option}>
                {rangeLabel(option)}
              </option>
            ))}
          </select>
        </label>
        <label class="control search-control">
          <span>Search</span>
          <input
            value={props.query}
            placeholder="path, user, IP, session"
            onInput={(event) => props.onQuery((event.currentTarget as HTMLInputElement).value)}
          />
        </label>
        <label class="control">
          <span>Source</span>
          <select
            value={props.sourceFilter}
            onInput={(event) => props.onSourceFilter((event.currentTarget as HTMLSelectElement).value as SourceFilter)}
          >
            <option value="all">All</option>
            <option value="sftp">SFTP</option>
            <option value="admin">Admin</option>
            <option value="explorer">Explorer</option>
          </select>
        </label>
        <label class="control hue-control">
          <span>Hue</span>
          <input type="color" value={hslToHex(props.hue, 72, 54)} onInput={(event) => props.onHue((event.currentTarget as HTMLInputElement).value)} />
        </label>
        <button type="button" class="refresh-button desktop-refresh" onClick={props.onRefresh}>
          Refresh
        </button>
      </div>
    </div>
  );
}

function Overview(props: {
  summary?: SummaryPayload;
  insights?: InsightsPayload;
  live?: LivePayload;
  liveCount: number;
  eventRows: EventRow[];
  explorerEvents: EventRow[];
  uploads: UploadRow[];
  downloads?: DownloadsPayload;
  users: UserRow[];
  sessions: SessionRow[];
  banned?: BannedPayload;
  maintenance?: Record<string, unknown>;
  maintenancePending: boolean;
  banIPPending: boolean;
  loading: boolean;
  onOpenPath: (path?: string) => void;
  onInspectEvent: (event: EventRow) => void;
  onInspectSession: (session: SessionRow) => void;
  onInspectUser: (user: UserRow) => void;
  onInspectActor: (actorType: ActorType, value: string) => void;
  onInspectLive: (liveType: LiveTargetKind, row: Record<string, unknown>) => void;
  onInspectMetric: (metric: MetricTarget) => void;
  onOpenActivity: (kind: ActivityKind, source?: SourceFilter, query?: string) => void;
  onOpenUsers: (filter?: UserFilter, sort?: UserSort) => void;
  onDrillSearch: (value: string, view?: View) => void;
  onRunMaintenance: () => void;
  onBanIP: (ip: string) => void;
}) {
  const downloads = props.downloads?.files ?? [];
  const summary = props.summary;
  const kpi = props.insights?.kpi ?? {};
  const totalEvents = props.eventRows.length;
  const explorerShare = totalEvents > 0 ? Math.round((props.explorerEvents.length / totalEvents) * 100) : 0;
  const bannedHashes = props.banned?.hashes?.length ?? 0;
  const bannedIPs = props.banned?.ips?.length ?? 0;
  const [showUploadThumbs, setShowUploadThumbs] = useState(false);
  const [showDownloadThumbs, setShowDownloadThumbs] = useState(false);

  return (
    <div class="overview-grid">
      <section class="metric-strip" aria-label="Summary">
        <Metric label="Files" value={formatNumber(summary?.files)} onClick={() => props.onInspectMetric(filesMetric(summary))} />
        <Metric label="Stored" value={summary?.formatted_bytes || formatBytes(summary?.bytes)} onClick={() => props.onInspectMetric(storageMetric(summary))} />
        <Metric label="Uptime" value={summary?.uptime || formatDuration(summary?.uptime_seconds)} onClick={() => props.onInspectMetric(uptimeMetric(summary))} />
        <Metric label="Dirs" value={formatNumber(summary?.directories)} onClick={() => props.onInspectMetric(directoriesMetric(summary))} />
        <Metric label="Users" value={formatNumber(summary?.users)} onClick={() => props.onOpenUsers("all", "activity")} />
        <Metric label="Contrib" value={formatNumber(summary?.contributors)} onClick={() => props.onOpenUsers("uploaders", "uploads")} />
        <Metric label="Events" value={formatNumber(kpi.events)} onClick={() => props.onOpenActivity("all")} />
        <Metric label="Uploads" value={formatNumber(kpi.uploads)} onClick={() => props.onOpenActivity("transfer", "all", "upload")} />
        <Metric label="Downloads" value={formatNumber(kpi.downloads)} onClick={() => props.onOpenActivity("transfer", "all", "download")} />
        <Metric
          label="Denied"
          value={formatNumber(kpi.denied)}
          tone={Number(kpi.denied || 0) > 0 ? "warn" : "normal"}
          onClick={() => props.onOpenActivity("denied")}
        />
        <Metric label="Live" value={formatNumber(props.liveCount)} onClick={() => props.onInspectMetric(liveMetric(props.live, props.liveCount))} />
        <Metric label="Explorer" value={`${explorerShare}%`} onClick={() => props.onOpenActivity("all", "explorer")} />
      </section>

      <section class="insights-band">
        <div>
          <h2>Operational Pulse</h2>
          <p>{props.loading ? "Loading current activity..." : pulseCopy(props.eventRows, props.explorerEvents, props.insights)}</p>
        </div>
        <div class="release">
          <span>Version</span>
          <strong>{summary?.version || "unknown"}</strong>
        </div>
      </section>

      <section class="split">
        <SystemPanel summary={summary} />
        <KPIBars kpi={kpi} liveCount={props.liveCount} />
      </section>

      <section class="split">
        <SourceMixPanel rows={props.eventRows} />
        <EventTimelinePanel rows={props.eventRows} />
      </section>

      <section class="split">
        <DevicePanel rows={props.insights?.device_types ?? []} />
        <UserAgentPanel rows={props.insights?.user_agents ?? []} onDrill={(ua) => props.onDrillSearch(ua, "activity")} />
      </section>

      <section class="split">
        <DataPanel
          title="Recent Uploads"
          empty="No uploads in this window"
          action={<ToggleButton active={showUploadThumbs} label="Thumbnails" onClick={() => setShowUploadThumbs((value) => !value)} />}
        >
          {props.uploads.map((row) => (
            <PathRow
              key={row.id}
              title={row.path || "(no path)"}
              detail={`${row.time || ""} ${row.user_id || ""}`}
              meta={formatBytes(row.size)}
              path={row.path}
              thumbnail={showUploadThumbs}
              onClick={() => props.onOpenPath(row.path)}
            />
          ))}
        </DataPanel>

        <DataPanel
          title="Downloaded Files"
          empty="No download activity yet"
          action={<ToggleButton active={showDownloadThumbs} label="Thumbnails" onClick={() => setShowDownloadThumbs((value) => !value)} />}
        >
          {downloads.map((row) => (
            <PathRow
              key={row.path}
              title={row.path}
              detail={`${row.downloads_total ?? 0} total, ${row.downloads_in_range ?? 0} in range`}
              meta={row.size_human || ""}
              path={row.path}
              thumbnail={showDownloadThumbs}
              onClick={() => props.onOpenPath(row.path)}
            />
          ))}
        </DataPanel>
      </section>

      <section class="triple">
        <CountPanel title="Top Events" rows={props.insights?.top_events ?? []} onSelect={(name) => props.onDrillSearch(name, "activity")} />
        <CountPanel title="Top Users" rows={props.insights?.top_users ?? []} denied onSelect={(name) => props.onInspectActor("user", name)} />
        <CountPanel title="Top IPs" rows={props.insights?.top_ips ?? []} denied onSelect={(name) => props.onInspectActor("ip", name)} />
      </section>

      <section class="split">
        <UsersPanel users={props.users.slice(0, 10)} onInspectUser={props.onInspectUser} />
        <SessionsPanel sessions={props.sessions} onInspectSession={props.onInspectSession} />
      </section>

      <section class="split">
        <LivePanel live={props.live} onInspectLive={props.onInspectLive} />
        <RiskPanel
          insights={props.insights}
          bannedHashes={bannedHashes}
          bannedIPs={bannedIPs}
          maintenance={props.maintenance}
          maintenancePending={props.maintenancePending}
          banIPPending={props.banIPPending}
          onRunMaintenance={props.onRunMaintenance}
          onBanIP={props.onBanIP}
          onInspectActor={props.onInspectActor}
        />
      </section>

      <section class="wide-panel">
        <div class="panel-heading">
          <h2>Explorer-Origin Activity</h2>
          <span>{props.explorerEvents.length} events</span>
        </div>
        <EventTable rows={props.explorerEvents.slice(0, 10)} onInspectEvent={props.onInspectEvent} />
      </section>
    </div>
  );
}

function Activity(props: {
  rows: EventRow[];
  loading: boolean;
  sourceFilter: SourceFilter;
  kind: ActivityKind;
  onKind: (kind: ActivityKind) => void;
  onInspectEvent: (event: EventRow) => void;
  onInspectActor: (actorType: ActorType, value: string) => void;
}) {
  const rows = useMemo(() => props.rows.filter((row) => matchesActivityKind(row, props.kind)), [props.rows, props.kind]);
  const profile = useMemo(() => activityProfile(props.rows), [props.rows]);

  return (
    <div class="activity-grid">
      <section class="metric-strip activity-metrics" aria-label="Activity summary">
        <Metric label="Rows" value={formatNumber(props.rows.length)} active={props.kind === "all"} onClick={() => props.onKind("all")} />
        <Metric
          label="Attention"
          value={formatNumber(profile.attention)}
          tone={profile.attention > 0 ? "warn" : "normal"}
          active={props.kind === "attention"}
          onClick={() => props.onKind("attention")}
        />
        <Metric
          label="Denied"
          value={formatNumber(profile.denied)}
          tone={profile.denied > 0 ? "warn" : "normal"}
          active={props.kind === "denied"}
          onClick={() => props.onKind("denied")}
        />
        <Metric label="Transfers" value={formatNumber(profile.transfer)} active={props.kind === "transfer"} onClick={() => props.onKind("transfer")} />
        <Metric label="Mutations" value={formatNumber(profile.mutating)} active={props.kind === "mutating"} onClick={() => props.onKind("mutating")} />
        <Metric label="Sessions" value={formatNumber(profile.session)} active={props.kind === "session"} onClick={() => props.onKind("session")} />
        <Metric
          label="Exec"
          value={formatNumber(profile.exec)}
          tone={profile.exec > 0 ? "warn" : "normal"}
          active={props.kind === "exec"}
          onClick={() => props.onKind("exec")}
        />
      </section>

      <section class="split">
        <ActivityBreakdownPanel profile={profile} />
        <ActorBreakdownPanel rows={props.rows} onInspectActor={props.onInspectActor} />
      </section>

      <section class="wide-panel">
        <div class="panel-heading">
          <h2>Event Stream</h2>
          <span>{props.loading ? "Refreshing" : `${rows.length} of ${props.rows.length} ${props.sourceFilter} rows`}</span>
        </div>
        <ActivityKindTabs value={props.kind} onChange={props.onKind} />
        <EventTable rows={rows} onInspectEvent={props.onInspectEvent} />
      </section>
    </div>
  );
}

function ThumbnailView(props: {
  eventRows: EventRow[];
  uploads: UploadRow[];
  downloads?: DownloadsPayload;
  loading: boolean;
  onOpenPath: (path?: string) => void;
}) {
  const [kindFilter, setKindFilter] = useState<ThumbnailFilter>("visual");
  const [sort, setSort] = useState<ThumbnailSort>("recent");
  const [size, setSize] = useState<ThumbnailSize>(() => (isSmallViewport() ? "compact" : "normal"));
  const [mode, setMode] = useState<ThumbnailMode>(() => (isSmallViewport() ? "list" : "grid"));
  const [folder, setFolder] = useState("all");
  const [localQuery, setLocalQuery] = useState("");
  const [selectedPaths, setSelectedPaths] = useState<string[]>([]);
  const rawCandidates = useMemo(
    () => collectThumbnailCandidates(props.eventRows, props.uploads, props.downloads),
    [props.downloads, props.eventRows, props.uploads]
  );
  const scopedCandidates = useMemo(
    () => filterThumbnailSearch(filterThumbnailFolder(filterThumbnailCandidates(rawCandidates, kindFilter), folder), localQuery),
    [folder, kindFilter, localQuery, rawCandidates]
  );
  const mobileLimit = isSmallViewport() ? 48 : mode === "list" ? 120 : 72;
  const candidates = useMemo(() => sortThumbnailCandidates(scopedCandidates, sort).slice(0, mobileLimit), [mobileLimit, scopedCandidates, sort]);
  const sourceCounts = topCountsFromStrings(rawCandidates.map((candidate) => candidate.source), 6);
  const kindCounts = topCountsFromStrings(rawCandidates.map((candidate) => candidate.kind), 8);
  const folderCounts = useMemo(() => thumbnailFolders(rawCandidates, 12), [rawCandidates]);
  const selectedSet = useMemo(() => new Set(selectedPaths), [selectedPaths]);

  function toggleSelected(path: string) {
    setSelectedPaths((current) => (current.includes(path) ? current.filter((item) => item !== path) : [...current, path]));
  }

  function clearSelected() {
    setSelectedPaths([]);
  }

  async function copySelected() {
    if (selectedPaths.length === 0) {
      return;
    }
    await navigator.clipboard.writeText(selectedPaths.join("\n"));
  }

  return (
    <div class="activity-grid">
      <section class="insights-band">
        <div>
          <h2>Explorer Gallery</h2>
          <p>
            {props.loading
              ? "Loading candidate paths..."
              : `${candidates.length} visible of ${rawCandidates.length} recent paths, scoped to ${folder === "all" ? "all folders" : folder}.`}
          </p>
        </div>
        <div class="release">
          <span>Selected</span>
          <strong>{selectedPaths.length}</strong>
        </div>
      </section>

      <section class="split">
        <DataPanel title="Sources" empty="No thumbnail sources">
          <BarList rows={sourceCounts} />
        </DataPanel>
        <DataPanel title="Media Types" empty="No media types">
          <BarList rows={kindCounts} />
        </DataPanel>
      </section>

      <section class="split gallery-browser">
        <ThumbnailFolders folders={folderCounts} total={rawCandidates.length} active={folder} onSelect={setFolder} />
        <ThumbnailSelection paths={selectedPaths} onCopy={copySelected} onClear={clearSelected} />
      </section>

      <section class="wide-panel">
        <div class="panel-heading">
          <h2>Gallery</h2>
          <span>{props.loading ? "Refreshing" : `${candidates.length} of ${scopedCandidates.length} matches`}</span>
        </div>
        <ThumbnailControls
          filter={kindFilter}
          sort={sort}
          size={size}
          mode={mode}
          query={localQuery}
          onFilter={setKindFilter}
          onSort={setSort}
          onSize={setSize}
          onMode={setMode}
          onQuery={setLocalQuery}
        />
        {candidates.length > 0 ? (
          <div class={`thumbnail-grid ${size} ${mode}`}>
            {candidates.map((candidate) => (
              <ThumbnailCard
                key={candidate.path}
                candidate={candidate}
                selected={selectedSet.has(candidate.path)}
                mode={mode}
                onOpenPath={props.onOpenPath}
                onToggleSelected={toggleSelected}
              />
            ))}
          </div>
        ) : (
          <div class="empty">No paths with preview candidates in the current window.</div>
        )}
      </section>
    </div>
  );
}

function ThumbnailControls(props: {
  filter: ThumbnailFilter;
  sort: ThumbnailSort;
  size: ThumbnailSize;
  mode: ThumbnailMode;
  query: string;
  onFilter: (filter: ThumbnailFilter) => void;
  onSort: (sort: ThumbnailSort) => void;
  onSize: (size: ThumbnailSize) => void;
  onMode: (mode: ThumbnailMode) => void;
  onQuery: (query: string) => void;
}) {
  const filters: Array<{ value: ThumbnailFilter; label: string }> = [
    { value: "visual", label: "Visual" },
    { value: "all", label: "All" },
    { value: "image", label: "Images" },
    { value: "video", label: "Videos" },
    { value: "pdf", label: "PDFs" },
    { value: "archive", label: "Archives" },
    { value: "text", label: "Text" },
    { value: "model", label: "Models" },
    { value: "other", label: "Other" }
  ];
  return (
    <div class="gallery-controls">
      <div class="filter-tabs" aria-label="Thumbnail filters">
        {filters.map((option) => (
          <button class={props.filter === option.value ? "active" : ""} type="button" key={option.value} onClick={() => props.onFilter(option.value)}>
            {option.label}
          </button>
        ))}
      </div>
      <div class="control-pair gallery-control-pair">
        <label class="control">
          <span>Find</span>
          <input value={props.query} placeholder="filter paths" onInput={(event) => props.onQuery((event.currentTarget as HTMLInputElement).value)} />
        </label>
        <label class="control">
          <span>Sort</span>
          <select value={props.sort} onInput={(event) => props.onSort((event.currentTarget as HTMLSelectElement).value as ThumbnailSort)}>
            <option value="recent">Recent</option>
            <option value="kind">Kind</option>
            <option value="source">Source</option>
            <option value="name">Name</option>
          </select>
        </label>
        <label class="control">
          <span>Size</span>
          <select value={props.size} onInput={(event) => props.onSize((event.currentTarget as HTMLSelectElement).value as ThumbnailSize)}>
            <option value="compact">Compact</option>
            <option value="normal">Normal</option>
            <option value="large">Large</option>
          </select>
        </label>
        <label class="control">
          <span>Mode</span>
          <select value={props.mode} onInput={(event) => props.onMode((event.currentTarget as HTMLSelectElement).value as ThumbnailMode)}>
            <option value="grid">Grid</option>
            <option value="list">List</option>
          </select>
        </label>
      </div>
    </div>
  );
}

function ThumbnailFolders(props: { folders: NamedCount[]; total: number; active: string; onSelect: (folder: string) => void }) {
  return (
    <DataPanel title="Folders" empty="No folders in this window">
      <button class={`dense-row folder-row ${props.active === "all" ? "active" : ""}`} type="button" onClick={() => props.onSelect("all")}>
        <div>
          <strong>All folders</strong>
          <small>Everything in the current activity window</small>
        </div>
        <span>{formatNumber(props.total)}</span>
      </button>
      {props.folders.map((row) => (
        <button class={`dense-row folder-row ${props.active === row.name ? "active" : ""}`} type="button" key={row.name} onClick={() => props.onSelect(row.name)}>
          <div>
            <strong>{row.name}</strong>
            <small>{row.name === "/" ? "archive root" : `/${row.name}`}</small>
          </div>
          <span>{formatNumber(row.count)}</span>
        </button>
      ))}
    </DataPanel>
  );
}

function ThumbnailSelection(props: { paths: string[]; onCopy: () => void; onClear: () => void }) {
  return (
    <DataPanel title="Selection" empty="No selected paths">
      {props.paths.length > 0 ? (
        <>
          <div class="selection-actions">
            <button type="button" onClick={props.onCopy}>
              Copy Paths
            </button>
            <button type="button" onClick={props.onClear}>
              Clear
            </button>
          </div>
          <div class="selection-list">
            {props.paths.slice(0, 8).map((path) => (
              <a href={explorerURL(path)} key={path}>
                {path}
              </a>
            ))}
            {props.paths.length > 8 ? <small>{props.paths.length - 8} more selected</small> : null}
          </div>
        </>
      ) : null}
    </DataPanel>
  );
}

function ThumbnailCard(props: {
  candidate: ThumbnailCandidate;
  selected: boolean;
  mode: ThumbnailMode;
  onOpenPath: (path?: string) => void;
  onToggleSelected: (path: string) => void;
}) {
  const preview = useQuery({
    queryKey: ["thumbnail-card-preview", props.candidate.path],
    queryFn: () => api<PreviewPayload>(previewURL(props.candidate.path)),
    staleTime: 60_000
  });
  const thumb = useQuery({
    queryKey: ["thumbnail-card-image", preview.data?.thumb_url],
    queryFn: () => fetchBlobURL(preview.data?.thumb_url || ""),
    enabled: Boolean(preview.data?.thumb_url),
    staleTime: 60_000
  });
  const data = preview.data;
  const label = data?.name || basename(props.candidate.path);
  return (
    <article class={`thumbnail-card ${props.selected ? "selected" : ""} ${props.mode}`}>
      <button class="thumbnail-frame" type="button" onClick={() => props.onOpenPath(props.candidate.path)} aria-label={`Inspect ${label}`}>
        {thumb.data ? (
          <img src={thumb.data} alt={label} loading="lazy" />
        ) : (
          <span class={`thumbnail-placeholder ${preview.isError ? "error-state" : ""}`}>
            {preview.isLoading ? "loading" : preview.isError ? "unavailable" : <FileIcon kind={data ? kindForPreview(data) : props.candidate.kind} label={label} />}
          </span>
        )}
      </button>
      <span class="thumbnail-body">
        <strong>{label}</strong>
        <small>{props.candidate.path}</small>
        <em>
          <SourcePill source={props.candidate.source} />
          <span>{props.candidate.kind}{props.candidate.meta ? ` / ${props.candidate.meta}` : ""}</span>
        </em>
        <span class="thumbnail-meta-line">{thumbnailMetaLine(data, props.candidate.detail)}</span>
        <span class="thumbnail-meta-line">{thumbnailDetailLine(data)}</span>
      </span>
      <span class="thumbnail-actions">
        <button type="button" class={props.selected ? "active" : ""} onClick={() => props.onToggleSelected(props.candidate.path)}>
          {props.selected ? "Selected" : "Select"}
        </button>
        <button type="button" onClick={() => props.onOpenPath(props.candidate.path)}>
          Inspect
        </button>
        <a class="button-link" href={explorerURL(props.candidate.path)}>
          Explorer
        </a>
        {data?.download_url ? (
          <a class="button-link" href={data.download_url}>
            Download
          </a>
        ) : null}
      </span>
    </article>
  );
}

function UsersView(props: {
  users: UserRow[];
  loading: boolean;
  filter: UserFilter;
  sort: UserSort;
  onFilter: (filter: UserFilter) => void;
  onSort: (sort: UserSort) => void;
  onInspectUser: (user: UserRow) => void;
}) {
  const profile = useMemo(() => userProfile(props.users), [props.users]);
  const filteredUsers = useMemo(() => filterUsers(props.users, props.filter), [props.filter, props.users]);
  const visibleUsers = useMemo(() => sortUsers(filteredUsers, props.sort).slice(0, 100), [filteredUsers, props.sort]);
  const uploadLeaders = useMemo(() => sortUsers(props.users, "uploads"), [props.users]);
  const downloadLeaders = useMemo(() => sortUsers(props.users, "downloads"), [props.users]);
  const sessionLeaders = useMemo(() => sortUsers(props.users, "sessions"), [props.users]);

  function setUserLens(filter: UserFilter, sort: UserSort) {
    props.onFilter(filter);
    props.onSort(sort);
  }

  return (
    <div class="activity-grid users-view">
      <section class="metric-strip activity-metrics" aria-label="User summary">
        <Metric label="Users" value={formatNumber(profile.total)} active={props.filter === "all"} onClick={() => setUserLens("all", "activity")} />
        <Metric label="Active" value={formatNumber(profile.active)} active={props.filter === "active"} onClick={() => setUserLens("active", "activity")} />
        <Metric label="Quiet" value={formatNumber(profile.quiet)} active={props.filter === "quiet"} onClick={() => setUserLens("quiet", "activity")} />
        <Metric
          label="Banned"
          value={formatNumber(profile.banned)}
          tone={profile.banned > 0 ? "warn" : "normal"}
          active={props.filter === "banned"}
          onClick={() => setUserLens("banned", "activity")}
        />
        <Metric label="Sessions" value={formatNumber(profile.sessions)} active={props.sort === "sessions"} onClick={() => setUserLens("all", "sessions")} />
        <Metric label="Uploads" value={formatNumber(profile.uploadCount)} active={props.filter === "uploaders"} onClick={() => setUserLens("uploaders", "uploads")} />
        <Metric label="Uploaded" value={formatBytes(profile.uploadBytes)} active={props.sort === "uploads"} onClick={() => setUserLens("uploaders", "uploads")} />
        <Metric label="Downloaded" value={formatBytes(profile.downloadBytes)} active={props.sort === "downloads"} onClick={() => setUserLens("downloaders", "downloads")} />
      </section>

      <section class="insights-band">
        <div>
          <h2>User Workbench</h2>
          <p>{props.loading ? "Loading user ledger..." : userWorkbenchCopy(profile, visibleUsers.length, props.users.length)}</p>
        </div>
        <div class="release">
          <span>Sort</span>
          <strong>{sortLabel(props.sort)}</strong>
        </div>
      </section>

      <section class="split">
        <UserMeterPanel
          title="Upload Weight"
          empty="No upload volume yet"
          users={uploadLeaders}
          value={(user) => user.upload_bytes ?? 0}
          detail={(user) => `${formatNumber(user.upload_count)} uploads`}
          valueLabel={formatBytes}
          onInspectUser={props.onInspectUser}
        />
        <UserMeterPanel
          title="Download Weight"
          empty="No download volume yet"
          users={downloadLeaders}
          value={(user) => user.download_bytes ?? 0}
          detail={(user) => `${formatNumber(user.download_count)} downloads`}
          valueLabel={formatBytes}
          onInspectUser={props.onInspectUser}
        />
      </section>

      <section class="split">
        <UserMeterPanel
          title="Session Footprint"
          empty="No sessions tracked"
          users={sessionLeaders}
          value={(user) => user.seen ?? 0}
          detail={(user) => user.last_login || "no login time"}
          valueLabel={formatNumber}
          onInspectUser={props.onInspectUser}
        />
        <UserStatusPanel profile={profile} />
      </section>

      <section class="wide-panel">
        <div class="panel-heading">
          <h2>Users</h2>
          <span>{props.loading ? "Refreshing" : `${visibleUsers.length} of ${props.users.length} users`}</span>
        </div>
        <UserControls filter={props.filter} sort={props.sort} onFilter={props.onFilter} onSort={props.onSort} />
        <UserTable users={visibleUsers} onInspectUser={props.onInspectUser} />
      </section>
    </div>
  );
}

function UserControls(props: { filter: UserFilter; sort: UserSort; onFilter: (filter: UserFilter) => void; onSort: (sort: UserSort) => void }) {
  const filters: Array<{ value: UserFilter; label: string }> = [
    { value: "all", label: "All" },
    { value: "active", label: "Active" },
    { value: "uploaders", label: "Uploaders" },
    { value: "downloaders", label: "Downloaders" },
    { value: "banned", label: "Banned" },
    { value: "quiet", label: "Quiet" }
  ];
  return (
    <div class="gallery-controls">
      <div class="filter-tabs" aria-label="User filters">
        {filters.map((option) => (
          <button class={props.filter === option.value ? "active" : ""} type="button" key={option.value} onClick={() => props.onFilter(option.value)}>
            {option.label}
          </button>
        ))}
      </div>
      <div class="control-pair single">
        <label class="control">
          <span>Sort</span>
          <select value={props.sort} onInput={(event) => props.onSort((event.currentTarget as HTMLSelectElement).value as UserSort)}>
            <option value="activity">Activity</option>
            <option value="uploads">Uploaded bytes</option>
            <option value="downloads">Downloaded bytes</option>
            <option value="sessions">Sessions</option>
            <option value="last_login">Last login</option>
          </select>
        </label>
      </div>
    </div>
  );
}

function UserTable({ users, onInspectUser }: { users: UserRow[]; onInspectUser: (user: UserRow) => void }) {
  if (users.length === 0) {
    return <div class="empty">No users match this filter.</div>;
  }
  return (
    <div class="user-table" role="table">
      <div class="user-head" role="row">
        <span>User</span>
        <span>Sessions</span>
        <span>Uploads</span>
        <span>Uploaded</span>
        <span>Downloads</span>
        <span>Downloaded</span>
        <span>Status</span>
      </div>
      {users.map((user) => (
        <button class={`user-list-row ${user.is_banned ? "banned" : ""}`} type="button" role="row" key={user.hash} onClick={() => onInspectUser(user)}>
          <span class="user-primary" data-label="User">
            <strong>{shortValue(user.hash, 24)}</strong>
            <small>{user.last_login || "no login time"}</small>
          </span>
          <span data-label="Sessions">{formatNumber(user.seen)}</span>
          <span data-label="Uploads">{formatNumber(user.upload_count)}</span>
          <span data-label="Uploaded">{formatBytes(user.upload_bytes)}</span>
          <span data-label="Downloads">{formatNumber(user.download_count)}</span>
          <span data-label="Downloaded">{formatBytes(user.download_bytes)}</span>
          <span data-label="Status">
            <span class={user.is_banned ? "status-chip hot" : "status-chip"}>{user.is_banned ? "banned" : userActivityScore(user) > 0 ? "active" : "quiet"}</span>
          </span>
        </button>
      ))}
    </div>
  );
}

function UserMeterPanel(props: {
  title: string;
  empty: string;
  users: UserRow[];
  value: (user: UserRow) => number;
  valueLabel: (value: number) => string;
  detail: (user: UserRow) => string;
  onInspectUser: (user: UserRow) => void;
}) {
  const rows = props.users.filter((user) => props.value(user) > 0).slice(0, 10);
  const max = Math.max(...rows.map((user) => props.value(user)), 1);
  return (
    <DataPanel title={props.title} empty={props.empty}>
      {rows.map((user) => {
        const value = props.value(user);
        return (
          <button class="dense-row user-meter-row" type="button" key={user.hash} onClick={() => props.onInspectUser(user)}>
            <div>
              <strong>{shortValue(user.hash, 22)}</strong>
              <small>{props.detail(user)}</small>
              <div class="mini-track">
                <i style={{ width: `${Math.max(3, Math.round((value / max) * 100))}%` }} />
              </div>
            </div>
            <span>{props.valueLabel(value)}</span>
          </button>
        );
      })}
    </DataPanel>
  );
}

function UserStatusPanel({ profile }: { profile: ReturnType<typeof userProfile> }) {
  return (
    <DataPanel title="Account Status" empty="No status data">
      <BarList
        rows={[
          { name: "Active", count: profile.active },
          { name: "Quiet", count: profile.quiet },
          { name: "Uploaders", count: profile.uploaders },
          { name: "Downloaders", count: profile.downloaders },
          { name: "Banned", count: profile.banned }
        ]}
      />
    </DataPanel>
  );
}

function Security(props: {
  insights?: InsightsPayload;
  banned?: BannedPayload;
  auth?: AuthAttemptsPayload;
  loading: boolean;
  banIPPending: boolean;
  onBanIP: (ip: string) => void;
  onInspectMetric: (metric: MetricTarget) => void;
  onOpenActivity: (kind: ActivityKind, source?: SourceFilter, query?: string) => void;
  onInspectEvent: (event: EventRow) => void;
  onInspectActor: (actorType: ActorType, value: string) => void;
}) {
  const attempts = props.auth?.attempts ?? [];
  const combos = props.auth?.combos ?? [];
  const suspicious = props.insights?.suspicious_ips ?? [];
  const bannedIPs = props.banned?.ips ?? [];
  const bannedHashes = props.banned?.hashes ?? [];
  const denied = props.insights?.kpi?.denied ?? 0;
  const panics = props.insights?.parsed_panics ?? 0;
  return (
    <div class="activity-grid">
      <section class="metric-strip activity-metrics" aria-label="Security summary">
        <Metric
          label="Auth"
          value={formatNumber(attempts.length)}
          tone={attempts.length > 0 ? "warn" : "normal"}
          onClick={() => props.onInspectMetric(authMetric(props.auth))}
        />
        <Metric
          label="Combos"
          value={formatNumber(combos.length)}
          tone={combos.length > 0 ? "warn" : "normal"}
          onClick={() => props.onInspectMetric(authCombosMetric(props.auth))}
        />
        <Metric
          label="Suspicious"
          value={formatNumber(suspicious.length)}
          tone={suspicious.length > 0 ? "warn" : "normal"}
          onClick={() => props.onInspectMetric(suspiciousMetric(suspicious))}
        />
        <Metric
          label="Denied"
          value={formatNumber(denied)}
          tone={denied > 0 ? "warn" : "normal"}
          onClick={() => props.onOpenActivity("denied")}
        />
        <Metric label="Panics" value={formatNumber(panics)} tone={panics > 0 ? "warn" : "normal"} onClick={() => props.onInspectMetric(panicMetric(props.insights))} />
        <Metric label="Banned IPs" value={formatNumber(bannedIPs.length)} onClick={() => props.onInspectMetric(bannedIPMetric(props.banned))} />
        <Metric label="Banned Users" value={formatNumber(bannedHashes.length)} onClick={() => props.onInspectMetric(bannedUserMetric(props.banned))} />
      </section>

      <section class="insights-band">
        <div>
          <h2>Security Posture</h2>
          <p>{props.loading ? "Loading security signals..." : securityCopy(attempts, suspicious, denied, panics)}</p>
        </div>
        <div class="release">
          <span>Auth Window</span>
          <strong>{props.auth?.window?.label || "current"}</strong>
        </div>
      </section>

      <section class="split">
        <SuspiciousPanel rows={suspicious} banIPPending={props.banIPPending} onBanIP={props.onBanIP} onInspectActor={props.onInspectActor} />
        <AuthCombosPanel combos={combos} banIPPending={props.banIPPending} onBanIP={props.onBanIP} />
      </section>

      <section class="split">
        <AuthAttemptsPanel attempts={attempts} onInspectEvent={props.onInspectEvent} />
        <BannedPanel banned={props.banned} />
      </section>

      <section class="split">
        <LogLevelsPanel rows={props.insights?.parsed_levels ?? []} />
        <PanicPanel rows={props.insights?.recent_panics ?? []} />
      </section>
    </div>
  );
}

function SuspiciousPanel(props: {
  rows: NamedPair[];
  banIPPending: boolean;
  onBanIP: (ip: string) => void;
  onInspectActor: (actorType: ActorType, value: string) => void;
}) {
  return (
    <DataPanel title="Suspicious IPs" empty="No suspicious IPs in this window">
      {props.rows.slice(0, 12).map((row) => (
        <div class="dense-row risk-row" key={row.name}>
          <button class="dense-row-main" type="button" onClick={() => props.onInspectActor("ip", row.name)}>
            <strong>{row.name}</strong>
            <small>{row.count} events, {row.denied ?? 0} denied</small>
            <div class="mini-track">
              <i style={{ width: `${Math.max(5, Math.min(100, (row.denied ?? 0) * 12))}%` }} />
            </div>
          </button>
          <button type="button" onClick={() => props.onBanIP(row.name)} disabled={props.banIPPending}>
            Ban IP
          </button>
        </div>
      ))}
    </DataPanel>
  );
}

function AuthCombosPanel(props: { combos: AuthComboRow[]; banIPPending: boolean; onBanIP: (ip: string) => void }) {
  return (
    <DataPanel title="Credential Combos" empty="No auth attempts in this window">
      {props.combos.slice(0, 14).map((combo, index) => (
        <div class="dense-row auth-combo-row" key={`${combo.username || ""}:${combo.password || ""}:${index}`}>
          <div>
            <strong>{credentialLabel(combo.username, combo.password)}</strong>
            <small>{combo.last_time || ""} {combo.last_ip || ""}</small>
          </div>
          <span>{formatNumber(combo.count)} tries</span>
          {combo.last_ip ? (
            <button type="button" onClick={() => props.onBanIP(combo.last_ip || "")} disabled={props.banIPPending}>
              Ban
            </button>
          ) : null}
        </div>
      ))}
    </DataPanel>
  );
}

function AuthAttemptsPanel({ attempts, onInspectEvent }: { attempts: AuthAttemptRow[]; onInspectEvent: (event: EventRow) => void }) {
  return (
    <DataPanel title="Recent Auth Attempts" empty="No auth attempts">
      {attempts.slice(0, 18).map((attempt) => (
        <button class="dense-row auth-attempt-row" type="button" key={attempt.id} onClick={() => onInspectEvent(eventFromAuthAttempt(attempt))}>
          <div>
            <strong>{credentialLabel(attempt.username, attempt.password)}</strong>
            <small>{attempt.time || ""} {attempt.ip || ""}</small>
          </div>
          <span>{shortValue(attempt.generated_hash, 14)}</span>
          <span>{shortValue(attempt.session, 14)}</span>
        </button>
      ))}
    </DataPanel>
  );
}

function BannedPanel({ banned }: { banned?: BannedPayload }) {
  const ips = banned?.ips ?? [];
  const hashes = banned?.hashes ?? [];
  return (
    <DataPanel title="Banned" empty="No banned actors">
      {ips.slice(0, 8).map((row) => (
        <div class="dense-row banned-row" key={`ip-${row.ip}`}>
          <div>
            <strong>{row.ip}</strong>
            <small>{row.comment || "IP"} {row.banned_at || ""}</small>
          </div>
          <span>ip</span>
        </div>
      ))}
      {hashes.slice(0, 8).map((row) => (
        <div class="dense-row banned-row" key={`hash-${row.hash}`}>
          <div>
            <strong>{shortValue(row.hash, 22)}</strong>
            <small>{row.banned_at || ""}</small>
          </div>
          <span>user</span>
        </div>
      ))}
    </DataPanel>
  );
}

function LogLevelsPanel({ rows }: { rows: NamedCount[] }) {
  return (
    <DataPanel title="Log Levels" empty="No parsed log levels">
      <BarList rows={rows.slice(0, 8)} />
    </DataPanel>
  );
}

function PanicPanel({ rows }: { rows: unknown[] }) {
  return (
    <DataPanel title="Recent Panics" empty="No recent panics">
      {rows.slice(0, 8).map((row, index) => (
        <div class="panic-row" key={index}>
          <code>{shortValue(panicText(row), 96)}</code>
        </div>
      ))}
    </DataPanel>
  );
}

function ActivityKindTabs(props: { value: ActivityKind; onChange: (kind: ActivityKind) => void }) {
  const options: Array<{ value: ActivityKind; label: string }> = [
    { value: "all", label: "All" },
    { value: "attention", label: "Attention" },
    { value: "denied", label: "Denied" },
    { value: "transfer", label: "Transfers" },
    { value: "mutating", label: "Mutations" },
    { value: "session", label: "Sessions" },
    { value: "exec", label: "Exec" }
  ];
  return (
    <div class="filter-tabs" aria-label="Activity filters">
      {options.map((option) => (
        <button class={props.value === option.value ? "active" : ""} type="button" key={option.value} onClick={() => props.onChange(option.value)}>
          {option.label}
        </button>
      ))}
    </div>
  );
}

function ActivityBreakdownPanel({ profile }: { profile: ReturnType<typeof activityProfile> }) {
  return (
    <DataPanel title="Activity Types" empty="No activity">
      <BarList
        rows={[
          { name: "Attention", count: profile.attention },
          { name: "Denied", count: profile.denied },
          { name: "Transfer", count: profile.transfer },
          { name: "Mutating", count: profile.mutating },
          { name: "Session", count: profile.session },
          { name: "Exec", count: profile.exec }
        ]}
      />
    </DataPanel>
  );
}

function ActorBreakdownPanel({ rows, onInspectActor }: { rows: EventRow[]; onInspectActor: (actorType: ActorType, value: string) => void }) {
  const users = topCounts(rows, (row) => row.user_id || "anonymous", 5);
  const ips = topCounts(rows, (row) => row.ip || "unknown", 5);
  return (
    <DataPanel title="Actors" empty="No actor data">
      <div class="actor-columns">
        <div>
          <h3>Users</h3>
          <BarList rows={users} onSelect={(name) => onInspectActor("user", name)} />
        </div>
        <div>
          <h3>IPs</h3>
          <BarList rows={ips} onSelect={(name) => onInspectActor("ip", name)} />
        </div>
      </div>
    </DataPanel>
  );
}

function EventTable(props: { rows: EventRow[]; onInspectEvent: (event: EventRow) => void }) {
  if (props.rows.length === 0) {
    return <div class="empty">No events to show.</div>;
  }

  return (
    <div class="event-table" role="table">
      <div class="event-head" role="row">
        <span>Time</span>
        <span>Source</span>
        <span>Event</span>
        <span>Status</span>
        <span>Path</span>
        <span>User</span>
        <span>IP</span>
        <span>Session</span>
      </div>
      {props.rows.map((row) => {
        const rowPath = targetPath({ type: "event", event: row });
        return (
          <button
            class={`event-row ${isMutatingEvent(row) ? "mutating" : ""} ${isAttentionEvent(row) ? "attention" : ""}`}
            type="button"
            role="row"
            key={row.id}
            onClick={() => props.onInspectEvent(row)}
          >
            <span class="event-cell" data-label="Time">{row.time || row.timestamp || ""}</span>
            <span class="event-cell" data-label="Source">
              <SourcePill source={sourceFor(row)} />
            </span>
            <span class="event-cell event-name" data-label="Event">{row.event || ""}</span>
            <span class="event-cell" data-label="Status">
              <span class={statusClass(row)}>{statusFor(row)}</span>
            </span>
            <span class="event-cell path-cell" data-label="Path">{rowPath}</span>
            <span class="event-cell" data-label="User">{shortValue(eventUser(row))}</span>
            <span class="event-cell" data-label="IP">{row.ip || ""}</span>
            <span class="event-cell truncate" data-label="Session">{row.session || ""}</span>
          </button>
        );
      })}
    </div>
  );
}

function SystemPanel({ summary }: { summary?: SummaryPayload }) {
  const storage = summary?.storage ?? [];
  return (
    <DataPanel title="System" empty="Summary unavailable">
      <dl class="system-grid">
        <Meta label="Archive" value={summary?.archive} />
        <Meta label="Version" value={summary?.version} />
        <Meta label="SSH" value={summary?.ssh_port ? `:${summary.ssh_port}` : ""} />
        <Meta label="Admin HTTP" value={summary?.admin_http || ""} />
        <Meta label="Uptime" value={summary?.uptime || formatDuration(summary?.uptime_seconds)} />
        <Meta label="Contributor Min" value={formatBytes(summary?.contributor_threshold)} />
      </dl>
      {storage.length > 0 ? (
        <div class="storage-list">
          {storage.map((volume) => (
            <StorageRow volume={volume} key={volume.id || volume.label || volume.path} />
          ))}
        </div>
      ) : null}
    </DataPanel>
  );
}

function StorageRow({ volume }: { volume: NonNullable<SummaryPayload["storage"]>[number] }) {
  const free = volume.free || formatBytes(volume.free_bytes);
  const total = volume.total || formatBytes(volume.total_bytes);
  const usedPercent = clampPercent(volume.used_percent);
  const sidecars = volume.sidecars ?? [];
  return (
    <div class={`storage-row ${volume.error ? "warning" : ""}`}>
      <div class="storage-row-head">
        <strong>{volume.label || volume.kind || "Storage"}</strong>
        <span>{volume.error ? "Unavailable" : `${formatPercent(volume.free_percent)} free`}</span>
      </div>
      {!volume.error ? (
        <>
          <div class="storage-meter" aria-label={`${volume.label || "Storage"} usage`}>
            <i style={{ width: `${usedPercent}%` }} />
          </div>
          <small>
            {free} free of {total}
          </small>
          {volume.file_exists ? <small>{volume.file_size || formatBytes(volume.file_bytes)} file</small> : volume.kind === "log" || volume.kind === "database" ? <small>file not present yet</small> : null}
          {sidecars.length > 0 ? (
            <div class="storage-sidecars">
              {sidecars.map((file) => (
                <span key={file.path || file.label}>
                  {file.label}: {file.size || formatBytes(file.size_bytes)}
                </span>
              ))}
            </div>
          ) : null}
        </>
      ) : (
        <small>{volume.error}</small>
      )}
      <code>{volume.path || ""}</code>
    </div>
  );
}

function KPIBars({ kpi, liveCount }: { kpi: Record<string, number>; liveCount: number }) {
  const rows: NamedCount[] = [
    { name: "Events", count: kpi.events ?? 0 },
    { name: "Uploads", count: kpi.uploads ?? 0 },
    { name: "Downloads", count: kpi.downloads ?? 0 },
    { name: "Denied", count: kpi.denied ?? 0 },
    { name: "Admin", count: kpi.admin_actions ?? 0 },
    { name: "Sessions", count: kpi.session_starts ?? 0 },
    { name: "Live", count: liveCount }
  ];
  return (
    <DataPanel title="Window Mix" empty="No activity">
      <BarList rows={rows} />
    </DataPanel>
  );
}

function SourceMixPanel({ rows }: { rows: EventRow[] }) {
  const counts = countBySource(rows);
  const total = rows.length;
  const mixRows: NamedCount[] = [
    { name: "SFTP", count: counts.sftp },
    { name: "Admin", count: counts.admin },
    { name: "Explorer", count: counts.explorer }
  ];
  return (
    <DataPanel title="Source Mix" empty="No source data">
      <div class="donut-row">
        <SourceDonut counts={counts} />
        <div class="donut-legend">
          <strong>{formatNumber(total)} events</strong>
          <span>SFTP, admin, and explorer-origin activity in the current window.</span>
        </div>
      </div>
      <BarList rows={mixRows} />
    </DataPanel>
  );
}

function EventTimelinePanel({ rows }: { rows: EventRow[] }) {
  const buckets = eventBuckets(rows, 18);
  const max = Math.max(...buckets, 1);
  return (
    <DataPanel title="Event Shape" empty="No events">
      <div class="spark-bars" aria-label="Event distribution">
        {buckets.map((count, index) => (
          <span key={index} style={{ height: `${Math.max(6, (count / max) * 100)}%` }} title={`${count} events`} />
        ))}
      </div>
      <div class="timeline-caption">
        <span>Older</span>
        <strong>{formatNumber(rows.length)} events</strong>
        <span>Newer</span>
      </div>
    </DataPanel>
  );
}

function DevicePanel({ rows }: { rows: DeviceStat[] }) {
  return (
    <DataPanel title="Device Types" empty="No user-agent data in this window">
      {rows.slice(0, 8).map((row) => (
        <div class="dense-row device-row" key={row.name}>
          <div>
            <strong>{row.name}</strong>
            <small>
              {formatNumber(row.uploads)} up / {formatNumber(row.downloads)} down / {formatNumber(row.sessions)} sessions
            </small>
            <div class="mini-track">
              <i style={{ width: `${Math.max(4, Math.min(100, percentOf(row.explorer ?? 0, row.count || 1)))}%` }} />
            </div>
          </div>
          <span>{formatNumber(row.count)}</span>
          <span>{row.top_event || "events"}</span>
        </div>
      ))}
    </DataPanel>
  );
}

function UserAgentPanel({ rows, onDrill }: { rows: UserAgentStat[]; onDrill: (ua: string) => void }) {
  return (
    <DataPanel title="User Agents" empty="No user-agent strings captured">
      {rows.slice(0, 8).map((row) => (
        <button class="dense-row ua-row" type="button" key={row.user_agent} onClick={() => onDrill(row.user_agent)}>
          <div>
            <strong>{shortUserAgent(row.user_agent)}</strong>
            <small>
              {[row.device, row.browser, row.os].filter(Boolean).join(" / ")} {row.last_ip ? `from ${row.last_ip}` : ""}
            </small>
          </div>
          <span>{formatNumber(row.count)} hits</span>
          <span>{uaActivityLabel(row)}</span>
        </button>
      ))}
    </DataPanel>
  );
}

function BarList({ rows, onSelect }: { rows: NamedCount[]; onSelect?: (name: string) => void }) {
  const max = Math.max(...rows.map((row) => row.count), 1);
  return (
    <div class="bar-list">
      {rows.map((row) => {
        const width = Math.max(2, Math.round((row.count / max) * 100));
        const content = (
          <>
            <span>{row.name}</span>
            <div class="bar-track">
              <i style={{ width: `${width}%` }} />
            </div>
            <strong>{formatNumber(row.count)}</strong>
          </>
        );
        return onSelect ? (
          <button class="bar-row clickable" type="button" key={row.name} onClick={() => onSelect(row.name)}>
            {content}
          </button>
        ) : (
          <div class="bar-row" key={row.name}>
            {content}
          </div>
        );
      })}
    </div>
  );
}

function SourceDonut({ counts }: { counts: Record<SourceFilter, number> }) {
  const total = counts.sftp + counts.admin + counts.explorer;
  const sftp = percentOf(counts.sftp, total);
  const admin = percentOf(counts.admin, total);
  const explorer = percentOf(counts.explorer, total);
  const gradient =
    total === 0
      ? "conic-gradient(var(--line) 0 100%)"
      : `conic-gradient(var(--accent) 0 ${sftp}%, var(--gold) ${sftp}% ${sftp + admin}%, var(--rose) ${sftp + admin}% ${
          sftp + admin + explorer
        }%, var(--line) ${sftp + admin + explorer}% 100%)`;
  return (
    <div class="source-donut" style={{ background: gradient }}>
      <span>{total === 0 ? "0" : `${Math.round(explorer)}%`}</span>
      <small>explorer</small>
    </div>
  );
}

function UsersPanel({ users, onInspectUser }: { users: UserRow[]; onInspectUser: (user: UserRow) => void }) {
  return (
    <DataPanel title="Users" empty="No users match the current filter">
      {users.map((user) => (
        <button class="dense-row user-row" type="button" key={user.hash} onClick={() => onInspectUser(user)}>
          <div>
            <strong>{shortValue(user.hash)}</strong>
            <small>{user.last_login || "no login time"}</small>
          </div>
          <span>{formatBytes(user.upload_bytes)} up</span>
          <span>{formatBytes(user.download_bytes)} down</span>
        </button>
      ))}
    </DataPanel>
  );
}

function SessionsPanel({ sessions, onInspectSession }: { sessions: SessionRow[]; onInspectSession: (session: SessionRow) => void }) {
  return (
    <DataPanel title="Sessions" empty="No sessions in this window">
      {sessions.map((session) => (
        <button class="dense-row session-row" type="button" key={session.session} onClick={() => onInspectSession(session)}>
          <div>
            <strong>{shortValue(session.session, 18)}</strong>
            <small>{session.user_id || "unknown user"} {session.ip || ""}</small>
          </div>
          <span>{formatDuration(session.duration_sec)}</span>
          <span>{session.event_count ?? 0} events</span>
        </button>
      ))}
    </DataPanel>
  );
}

function LivePanel({ live, onInspectLive }: { live?: LivePayload; onInspectLive: (liveType: LiveTargetKind, row: Record<string, unknown>) => void }) {
  const connections = recordArray(live?.connections).slice(0, 6);
  const sessions = recordArray(live?.sessions).slice(0, 6);
  const transfers = recordArray(live?.transfers).slice(0, 8);
  const requests = recordArray(live?.requests).slice(0, 4);
  return (
    <DataPanel title="Live" empty="No live activity">
      {connections.map((row, index) => (
        <LiveRow key={`conn-${liveRowID(row, index)}`} liveType="connection" row={row} onInspectLive={onInspectLive} />
      ))}
      {sessions.map((row, index) => (
        <LiveRow key={`session-${liveRowID(row, index)}`} liveType="session" row={row} onInspectLive={onInspectLive} />
      ))}
      {transfers.map((row, index) => (
        <LiveRow key={`transfer-${liveRowID(row, index)}`} liveType="transfer" row={row} onInspectLive={onInspectLive} />
      ))}
      {requests.map((row, index) => (
        <LiveRow key={`request-${liveRowID(row, index)}`} liveType="request" row={row} onInspectLive={onInspectLive} />
      ))}
    </DataPanel>
  );
}

function LiveRow({
  liveType,
  row,
  onInspectLive
}: {
  liveType: LiveTargetKind;
  row: Record<string, unknown>;
  onInspectLive: (liveType: LiveTargetKind, row: Record<string, unknown>) => void;
}) {
  return (
    <button class={`dense-row live-row ${liveType}`} type="button" onClick={() => onInspectLive(liveType, row)}>
      <div>
        <strong>{liveRowTitle(liveType, row)}</strong>
        <small>{liveRowDetail(liveType, row)}</small>
      </div>
      <span>{liveRowMetric(liveType, row)}</span>
      <span>{liveRowActor(row)}</span>
    </button>
  );
}

function liveRowID(row: Record<string, unknown>, index: number): string {
  return stringFromRecord(row, ["id", "session", "connection_id", "path", "last_path"]) || String(index);
}

function liveRowTitle(kind: LiveTargetKind, row: Record<string, unknown>): string {
  if (kind === "transfer") {
    const direction = stringFromRecord(row, ["direction"]) || "transfer";
    return `${titleCase(direction)} ${basename(livePath(row)) || shortValue(liveSessionID(row), 14) || "active"}`;
  }
  if (kind === "session") {
    return `Session ${shortValue(liveSessionID(row), 18) || "active"}`;
  }
  if (kind === "request") {
    return `${titleCase(stringFromRecord(row, ["operation"]) || "Request")} ${basename(livePath(row)) || ""}`.trim();
  }
  return `Connection ${shortValue(stringFromRecord(row, ["id", "connection_id"]), 18) || stringFromRecord(row, ["state"]) || "active"}`;
}

function liveRowDetail(kind: LiveTargetKind, row: Record<string, unknown>): string {
  if (kind === "transfer") {
    return livePath(row) || liveSessionID(row) || liveIP(row);
  }
  return stringFromRecord(row, ["last_path", "path"]) || stringFromRecord(row, ["last_operation", "operation"]) || liveSessionID(row) || stringFromRecord(row, ["remote_addr", "ip"]);
}

function liveRowMetric(kind: LiveTargetKind, row: Record<string, unknown>): string {
  if (kind === "transfer") {
    return liveRate(row) || liveBytes(row) || liveDuration(row, "age_sec");
  }
  return liveActiveLine(row) || liveRate(row) || liveDuration(row, "idle_sec");
}

function liveRowActor(row: Record<string, unknown>): string {
  return liveUser(row) || liveIP(row) || stringFromRecord(row, ["source", "protocol"]);
}

function RiskPanel(props: {
  insights?: InsightsPayload;
  bannedHashes: number;
  bannedIPs: number;
  maintenance?: Record<string, unknown>;
  maintenancePending: boolean;
  banIPPending: boolean;
  onRunMaintenance: () => void;
  onBanIP: (ip: string) => void;
  onInspectActor: (actorType: ActorType, value: string) => void;
}) {
  const suspicious = props.insights?.suspicious_ips ?? [];
  const running = Boolean(props.maintenance?.running);
  return (
    <DataPanel title="Risk & Maintenance" empty="No risk data available">
      <div class="risk-summary">
        <Metric label="Banned Users" value={formatNumber(props.bannedHashes)} compact />
        <Metric label="Banned IPs" value={formatNumber(props.bannedIPs)} compact />
        <Metric label="Panics" value={formatNumber(props.insights?.parsed_panics)} compact tone={Number(props.insights?.parsed_panics || 0) > 0 ? "warn" : "normal"} />
      </div>
      <div class="action-line">
        <span class={running ? "status-chip hot" : "status-chip"}>{running ? "Running" : "Idle"}</span>
        <button type="button" onClick={props.onRunMaintenance} disabled={running || props.maintenancePending}>
          Run Maintenance
        </button>
      </div>
      {suspicious.map((ip) => (
        <div class="dense-row risk-row" key={ip.name}>
          <button class="dense-row-main" type="button" onClick={() => props.onInspectActor("ip", ip.name)}>
            <strong>{ip.name}</strong>
            <small>{ip.count} events, {ip.denied ?? 0} denied</small>
          </button>
          <button type="button" onClick={() => props.onBanIP(ip.name)} disabled={props.banIPPending}>
            Ban IP
          </button>
        </div>
      ))}
    </DataPanel>
  );
}

function CountPanel({ title, rows, denied, onSelect }: { title: string; rows: NamedPair[]; denied?: boolean; onSelect?: (name: string) => void }) {
  const max = Math.max(...rows.slice(0, 10).map((row) => row.count), 1);
  return (
    <DataPanel title={title} empty="No rows">
      {rows.slice(0, 10).map((row) => {
        const content = (
          <>
            <strong>{shortValue(row.name, 28)}</strong>
            {denied ? <small>{row.denied ?? 0} denied</small> : null}
            <div class="mini-track">
              <i style={{ width: `${Math.max(3, Math.round((row.count / max) * 100))}%` }} />
            </div>
          </>
        );
        return (
          <div class="dense-row" key={row.name}>
            {onSelect ? (
              <button class="dense-row-main" type="button" onClick={() => onSelect(row.name)}>
                {content}
              </button>
            ) : (
              <div>{content}</div>
            )}
            <span>{formatNumber(row.count)}</span>
          </div>
        );
      })}
    </DataPanel>
  );
}

function Inspector(props: {
  target: InspectorTarget;
  range: string;
  banIPPending: boolean;
  onBanIP: (ip: string) => void;
  onInspectEvent: (event: EventRow) => void;
  onInspectUser: (user: UserRow) => void;
  onInspectActor: (actorType: ActorType, value: string) => void;
  onOpenPath: (path?: string) => void;
  onClose: () => void;
}) {
  const queryClient = useQueryClient();
  const [notice, setNotice] = useState("");
  const event = props.target.type === "event" ? props.target.event : undefined;
  const user = props.target.type === "user" ? props.target.user : undefined;
  const actor = props.target.type === "actor" ? props.target : undefined;
  const live = props.target.type === "live" ? props.target : undefined;
  const metric = props.target.type === "metric" ? props.target.metric : undefined;
  const selectedPath = targetPath(props.target);
  const sessionID = eventSession(event) || liveSessionID(live?.row);
  const selectedUser = user?.hash || "";

  useEffect(() => {
    setNotice("");
  }, [props.target]);

  const preview = useQuery({
    queryKey: ["preview", selectedPath],
    queryFn: () => api<PreviewPayload>(previewURL(selectedPath)),
    enabled: selectedPath !== ""
  });

  const ownerDetails = useQuery({
    queryKey: ["owner-details", preview.data?.owner_details_url],
    queryFn: () => api<Record<string, unknown>>(preview.data?.owner_details_url || ""),
    enabled: Boolean(preview.data?.owner_details_url)
  });

  const sessionTimeline = useQuery({
    queryKey: ["session-timeline", sessionID],
    queryFn: () => api<SessionTimelinePayload>(adminPath(`/admin/api/sessions/${encodeURIComponent(sessionID)}`, { limit: 120 })),
    enabled: sessionID !== ""
  });

  const userDetails = useQuery({
    queryKey: ["user-detail", selectedUser],
    queryFn: () => api<UserDetailPayload>(`/admin/api/users/${encodeURIComponent(selectedUser)}`),
    enabled: selectedUser !== ""
  });

  const actorDetails = useQuery({
    queryKey: ["actor-detail", actor?.actorType, actor?.value, props.range],
    queryFn: () =>
      api<ActorDetailPayload>(
        adminPath("/admin/api/actor", {
          type: actor?.actorType || "ip",
          value: actor?.value || "",
          range: props.range
        })
      ),
    enabled: Boolean(actor?.value)
  });

  const action = useMutation({
    mutationFn: (next: InspectorAction) => runInspectorAction(next),
    onSuccess: async (_data, variables) => {
      setNotice(`${actionLabel(variables.type)} complete`);
      await queryClient.invalidateQueries({ queryKey: ["preview"] });
      await queryClient.invalidateQueries({ queryKey: ["events"] });
      await queryClient.invalidateQueries({ queryKey: ["uploads"] });
      await queryClient.invalidateQueries({ queryKey: ["downloads"] });
      if (variables.type === "delete") {
        props.onClose();
      }
    },
    onError: (error) => {
      setNotice(error instanceof Error ? error.message : "Action failed");
    }
  });

  const userAction = useMutation({
    mutationFn: (next: UserInspectorAction) => postJSON(`/admin/api/users/${encodeURIComponent(next.hash)}/${next.type}`, {}),
    onSuccess: async (_data, variables) => {
      setNotice(`${variables.type === "ban" ? "Ban" : "Unban"} user complete`);
      await queryClient.invalidateQueries({ queryKey: ["user-detail", variables.hash] });
      await queryClient.invalidateQueries({ queryKey: ["users"] });
      await queryClient.invalidateQueries({ queryKey: ["banned"] });
      await queryClient.invalidateQueries({ queryKey: ["events"] });
    },
    onError: (error) => {
      setNotice(error instanceof Error ? error.message : "Action failed");
    }
  });

  const data = preview.data;
  const ownerStats = ownerDetails.data?.stats as Record<string, unknown> | undefined;
  const hasSelection = props.target.type !== "none";
  const previewError = preview.isError ? preview.error : null;
  const missingPath = Boolean(event && previewError && selectedPath);

  async function rename() {
    if (!data?.rel_path) {
      return;
    }
    const next = window.prompt("New file or directory name", data.name);
    if (!next || next.trim() === data.name) {
      return;
    }
    await action.mutateAsync({ type: "rename", path: data.rel_path, newName: next.trim() });
  }

  async function deletePath() {
    if (!data?.rel_path || !window.confirm(`Delete ${data.rel_path}?`)) {
      return;
    }
    await action.mutateAsync({ type: "delete", path: data.rel_path });
  }

  async function markBad() {
    if (!data?.rel_path || !window.confirm(`Mark ${data.rel_path} as a bad file?`)) {
      return;
    }
    await action.mutateAsync({ type: "mark-bad", path: data.rel_path });
  }

  async function banOwner() {
    if (!data?.rel_path || !data.owner || !window.confirm(`Ban owner ${data.owner}?`)) {
      return;
    }
    await action.mutateAsync({ type: "ban-owner", path: data.rel_path });
  }

  return (
    <aside class={`inspector ${hasSelection ? "open" : ""}`} aria-live="polite">
      {!hasSelection ? (
        <div class="inspector-empty">
          <h2>Inspector</h2>
          <p>Select a file, session, or event.</p>
        </div>
      ) : (
        <>
          <div class="inspector-head">
            <div>
              <span class="eyebrow">Inspector</span>
              <h2>
                {live
                  ? liveInspectorTitle(live.liveType, live.row)
                  : metric
                    ? metric.title
                    : actor
                      ? `${actor.actorType.toUpperCase()} ${shortValue(actor.value, 22)}`
                      : user
                        ? shortValue(user.hash, 22)
                        : event
                          ? event.event || "Event"
                          : data?.name || selectedPath}
              </h2>
            </div>
            <button type="button" onClick={props.onClose} aria-label="Close inspector">
              Close
            </button>
          </div>

          {event ? <EventSummary event={event} /> : null}
          {event ? (
            <EventActions
              event={event}
              path={selectedPath}
              banIPPending={props.banIPPending}
              onBanIP={props.onBanIP}
              onInspectUser={props.onInspectUser}
              onInspectActor={props.onInspectActor}
              onNotice={setNotice}
            />
          ) : null}
          {live ? (
            <LiveDetailBox
              target={live}
              banIPPending={props.banIPPending}
              onBanIP={props.onBanIP}
              onInspectUser={props.onInspectUser}
              onInspectActor={props.onInspectActor}
              onOpenPath={props.onOpenPath}
              onNotice={setNotice}
            />
          ) : null}
          {metric ? <MetricDetailBox metric={metric} /> : null}
          {actor ? (
            <ActorDetailBox
              actor={actor}
              details={actorDetails.data}
              loading={actorDetails.isLoading}
              onInspectEvent={props.onInspectEvent}
              onInspectSession={(session) => props.onInspectEvent(eventFromSession(session))}
              onInspectUser={props.onInspectUser}
              onOpenPath={props.onOpenPath}
            />
          ) : null}
          {user ? (
            <UserDetailBox
              user={user}
              details={userDetails.data}
              loading={userDetails.isLoading}
              actionPending={userAction.isPending}
              onToggleBan={(hash, banned) => {
                if (window.confirm(`${banned ? "Unban" : "Ban"} ${hash}?`)) {
                  userAction.mutate({ type: banned ? "unban" : "ban", hash });
                }
              }}
              onInspectEvent={props.onInspectEvent}
              onOpenPath={props.onOpenPath}
            />
          ) : null}

          {sessionID ? <SessionTimelineBox session={sessionTimeline.data} loading={sessionTimeline.isLoading} onInspectEvent={props.onInspectEvent} /> : null}

          {selectedPath ? (
            <>
              {preview.isLoading ? <div class="empty">Loading preview...</div> : null}
              {preview.isError ? (
                <div class={missingPath ? "detail-box subtle" : "error"}>
                  {missingPath ? "Path preview is unavailable; the event metadata is still shown above." : "Preview unavailable."}
                </div>
              ) : null}
            </>
          ) : event ? (
            <div class="detail-box subtle">This event has no file path, so the inspector is showing event and session context.</div>
          ) : null}

          {data ? (
            <>
              <PreviewHero preview={data} />
              <dl class="metadata">
                <Meta label="Path" value={data.rel_path} />
                <Meta label="Size" value={data.is_dir ? data.total_size || data.size : data.size} />
                <Meta label="Modified" value={data.mod_time} />
                <Meta label="Owner" value={data.owner} />
                <Meta label="Downloads" value={String(data.downloads ?? 0)} />
                <Meta label="MIME" value={data.mime_type} />
              </dl>

              {ownerStats ? (
                <div class="owner-box">
                  <strong>Owner details</strong>
                  <span>{String(ownerStats.upload_count ?? 0)} uploads</span>
                  <span>{String(ownerStats.download_count ?? 0)} downloads</span>
                  <span>{String(ownerStats.seen ?? 0)} sessions</span>
                </div>
              ) : null}

              <PreviewDetails preview={data} />

              <div class="inspector-actions">
                {data.download_url ? (
                  <a class="button-link" href={data.download_url}>
                    Download
                  </a>
                ) : null}
                {data.owner ? (
                  <button type="button" onClick={() => props.onInspectUser({ hash: data.owner || "" })}>
                    Inspect Owner
                  </button>
                ) : null}
                <button type="button" onClick={rename} disabled={action.isPending}>
                  Rename
                </button>
                <button type="button" onClick={deletePath} disabled={action.isPending}>
                  Delete
                </button>
                {!data.is_dir ? (
                  <button type="button" onClick={markBad} disabled={action.isPending}>
                    Mark Bad
                  </button>
                ) : null}
                {data.owner ? (
                  <button type="button" onClick={banOwner} disabled={action.isPending}>
                    Ban Owner
                  </button>
                ) : null}
              </div>
            </>
          ) : null}
          {notice ? <p class="notice">{notice}</p> : null}
        </>
      )}
    </aside>
  );
}

function LiveDetailBox(props: {
  target: { liveType: LiveTargetKind; row: Record<string, unknown> };
  banIPPending: boolean;
  onBanIP: (ip: string) => void;
  onInspectUser: (user: UserRow) => void;
  onInspectActor: (actorType: ActorType, value: string) => void;
  onOpenPath: (path?: string) => void;
  onNotice: (notice: string) => void;
}) {
  const row = props.target.row;
  const kind = props.target.liveType;
  const path = livePath(row);
  const user = liveUser(row);
  const ip = liveIP(row);
  const session = liveSessionID(row);
  const connectionID = stringFromRecord(row, ["connection_id", "id"]);
  const rate = liveRate(row);
  const bytes = liveBytes(row);

  async function copyLiveDetails() {
    try {
      await navigator.clipboard.writeText(JSON.stringify({ type: kind, ...row }, null, 2));
      props.onNotice("Live details copied");
    } catch {
      props.onNotice("Unable to copy live details");
    }
  }

  return (
    <>
      <div class="event-card live-card">
        <div class="event-card-head">
          <SourcePill source={stringFromRecord(row, ["source"]) || "live"} />
          <span class={liveStatusClass(row)}>{liveStatusLabel(kind, row)}</span>
        </div>
        <dl class="metadata">
          <Meta label="Type" value={titleCase(kind)} />
          <Meta label="Direction" value={stringFromRecord(row, ["direction"])} />
          <Meta label="State" value={stringFromRecord(row, ["state"])} />
          <Meta label="Protocol" value={stringFromRecord(row, ["protocol"])} />
          <Meta label="User" value={user} />
          <Meta label="Auth User" value={stringFromRecord(row, ["auth_user"])} />
          <Meta label="IP" value={ip} />
          <Meta label="Remote" value={stringFromRecord(row, ["remote_addr"])} />
          <Meta label="Local" value={stringFromRecord(row, ["local_addr"])} />
          <Meta label="Session" value={session} />
          <Meta label="Connection" value={connectionID} />
          <Meta label="Started" value={stringFromRecord(row, ["start_time", "started_time"])} />
          <Meta label="Age" value={liveDuration(row, "age_sec")} />
          <Meta label="Idle" value={liveDuration(row, "idle_sec")} />
          <Meta label="Last Activity" value={stringFromRecord(row, ["last_activity"])} />
          <Meta label="Last Operation" value={stringFromRecord(row, ["last_operation", "operation"])} />
          <Meta label="Path" value={path} />
          <Meta label="Last Error" value={stringFromRecord(row, ["last_error", "error"])} />
          <Meta label="Active" value={liveActiveLine(row)} />
          <Meta label="Transferred" value={bytes} />
          <Meta label="Rate" value={rate} />
          <Meta label="Client" value={liveClientLine(row)} />
          <Meta label="Flags" value={liveFlagLine(row)} />
        </dl>
      </div>

      <div class="inspector-actions event-actions">
        {path ? (
          <button type="button" onClick={() => props.onOpenPath(path)}>
            Inspect File
          </button>
        ) : null}
        {path ? (
          <a class="button-link" href={explorerURL(path)}>
            Open Explorer
          </a>
        ) : null}
        {user ? (
          <button type="button" onClick={() => props.onInspectUser({ hash: user })}>
            Inspect User
          </button>
        ) : null}
        {user ? (
          <a class="button-link" href={adminPath("/admin/v2/", { view: "users", q: user })}>
            Filter User
          </a>
        ) : null}
        {ip ? (
          <button type="button" onClick={() => props.onInspectActor("ip", ip)}>
            Inspect IP
          </button>
        ) : null}
        {ip ? (
          <a class="button-link" href={adminPath("/admin/v2/", { view: "security", q: ip })}>
            Filter IP
          </a>
        ) : null}
        {session ? (
          <a class="button-link" href={adminPath("/admin/v2/", { view: "activity", q: session })}>
            Filter Session
          </a>
        ) : null}
        {ip ? (
          <button type="button" onClick={() => props.onBanIP(ip)} disabled={props.banIPPending}>
            Ban IP
          </button>
        ) : null}
        <button type="button" onClick={copyLiveDetails}>
          Copy Details
        </button>
      </div>
    </>
  );
}

function MetricDetailBox({ metric }: { metric: MetricTarget }) {
  return (
    <div class="event-card metric-card">
      <div class="event-card-head">
        <SourcePill source="metric" />
        <span class="status-chip">{metric.value}</span>
      </div>
      {metric.summary ? <p class="metric-detail-copy">{metric.summary}</p> : null}
      <dl class="metadata">
        {metric.rows.map((row) => (
          <Meta label={row.label} value={row.value} key={row.label} />
        ))}
      </dl>
    </div>
  );
}

function EventSummary({ event }: { event: EventRow }) {
  const path = targetPath({ type: "event", event });
  const session = eventSession(event);
  const user = eventUser(event);
  const command = eventCommand(event);
  const target = metaString(event, ["target", "new_path", "old_path", "name", "file"]);
  const error = metaString(event, ["error", "err", "message"]);
  return (
    <div class="event-card">
      <div class="event-card-head">
        <SourcePill source={sourceFor(event)} />
        <span class={statusClass(event)}>{statusFor(event)}</span>
      </div>
      <dl class="metadata">
        <Meta label="Time" value={event.time || String(event.timestamp || "")} />
        <Meta label="Event" value={event.event} />
        <Meta label="Path" value={path} />
        <Meta label="Target" value={target} />
        <Meta label="Command" value={command} />
        <Meta label="User" value={user} />
        <Meta label="IP" value={event.ip} />
        <Meta label="Session" value={session} />
        <Meta label="Error" value={error} />
      </dl>
      <EventInsightBox event={event} />
      {eventIsDelete(event) ? <div class="detail-box subtle">Delete events often point at a path that no longer exists; keep the metadata as the record of what happened.</div> : null}
      <EventMetaBlock event={event} />
    </div>
  );
}

function EventInsightBox({ event }: { event: EventRow }) {
  const insight = eventInsight(event);
  if (!insight) {
    return null;
  }
  return (
    <div class={`event-insight ${insight.tone === "warn" ? "warn" : ""}`}>
      <div class="panel-heading">
        <h3>{insight.title}</h3>
        <span>{insight.label}</span>
      </div>
      <dl class="metadata compact-meta">
        {insight.rows.map((row) => (
          <Meta label={row.label} value={row.value} key={row.label} />
        ))}
      </dl>
    </div>
  );
}

function EventActions(props: {
  event: EventRow;
  path: string;
  banIPPending: boolean;
  onBanIP: (ip: string) => void;
  onInspectUser: (user: UserRow) => void;
  onInspectActor: (actorType: ActorType, value: string) => void;
  onNotice: (notice: string) => void;
}) {
  const session = eventSession(props.event);
  const user = eventUser(props.event);
  const ip = props.event.ip || metaString(props.event, ["ip", "ip_address", "remote_addr"]);
  if (!props.path && !ip && !session && !user) {
    return null;
  }
  async function copyEvent() {
    try {
      await navigator.clipboard.writeText(JSON.stringify(eventCopyPayload(props.event), null, 2));
      props.onNotice("Event JSON copied");
    } catch {
      props.onNotice("Unable to copy event JSON");
    }
  }
  return (
    <div class="inspector-actions event-actions">
      {props.path ? (
        <a class="button-link" href={explorerURL(props.path)}>
          Open Explorer
        </a>
      ) : null}
      {user ? (
        <button type="button" onClick={() => props.onInspectUser({ hash: user })}>
          Inspect User
        </button>
      ) : null}
      {user ? (
        <a class="button-link" href={adminPath("/admin/v2/", { view: "users", q: user })}>
          Filter User
        </a>
      ) : null}
      {session ? (
        <a class="button-link" href={adminPath("/admin/v2/", { view: "activity", q: session })}>
          Filter Session
        </a>
      ) : null}
      {ip ? (
        <button type="button" onClick={() => props.onInspectActor("ip", ip)}>
          Inspect IP
        </button>
      ) : null}
      {ip ? (
        <a class="button-link" href={adminPath("/admin/v2/", { view: "security", q: ip })}>
          Filter IP
        </a>
      ) : null}
      {ip ? (
        <button type="button" onClick={() => props.onBanIP(ip)} disabled={props.banIPPending}>
          Ban IP
        </button>
      ) : null}
      <button type="button" onClick={copyEvent}>
        Copy JSON
      </button>
    </div>
  );
}

function UserDetailBox(props: {
  user: UserRow;
  details?: UserDetailPayload;
  loading: boolean;
  actionPending: boolean;
  onToggleBan: (hash: string, banned: boolean) => void;
  onInspectEvent: (event: EventRow) => void;
  onOpenPath: (path?: string) => void;
}) {
  const hash = props.details?.hash || props.user.hash;
  const stats = props.details?.stats;
  const banned = Boolean(props.details?.is_banned ?? props.user.is_banned);
  const files = props.details?.files ?? [];
  const events = props.details?.events ?? [];
  const [showFileThumbs, setShowFileThumbs] = useState(false);
  if (props.loading) {
    return <div class="detail-box subtle">Loading user details...</div>;
  }
  return (
    <>
      <div class="event-card">
        <div class="event-card-head">
          <SourcePill source="sftp" />
          <span class={banned ? "status-chip hot" : "status-chip"}>{banned ? "banned" : "active"}</span>
        </div>
        <dl class="metadata">
          <Meta label="User" value={hash} />
          <Meta label="Last Login" value={stats?.last_login || props.user.last_login} />
          <Meta label="Last IP" value={stats?.last_address} />
          <Meta label="Sessions" value={formatNumber(stats?.seen ?? props.user.seen)} />
          <Meta label="Uploads" value={`${formatNumber(stats?.upload_count ?? props.user.upload_count)} / ${formatBytes(stats?.upload_bytes ?? props.user.upload_bytes)}`} />
          <Meta
            label="Downloads"
            value={`${formatNumber(stats?.download_count ?? props.user.download_count)} / ${formatBytes(stats?.download_bytes ?? props.user.download_bytes)}`}
          />
        </dl>
        <div class="inspector-actions event-actions">
          <button type="button" onClick={() => props.onToggleBan(hash, banned)} disabled={props.actionPending}>
            {banned ? "Unban User" : "Ban User"}
          </button>
          <a class="button-link" href={adminPath("/admin/v2/", { q: hash })}>
            Filter User
          </a>
        </div>
      </div>

      <div class="session-box">
        <div class="panel-heading">
          <h3>User Files</h3>
          <div class="heading-actions">
            <span>{files.length} files</span>
            <ToggleButton active={showFileThumbs} label="Thumbnails" onClick={() => setShowFileThumbs((value) => !value)} />
          </div>
        </div>
        <div class="timeline-list">
          {files.slice(0, 12).map((file) => (
            <button
              class={`timeline-row user-file-row ${showFileThumbs ? "with-file-preview" : ""}`}
              type="button"
              key={file.path || file.name}
              onClick={() => props.onOpenPath(file.path)}
            >
              {showFileThumbs && file.path ? <FilePreviewBadge path={file.path} /> : null}
              <span>{file.is_dir ? "dir" : file.size_human || formatBytes(file.size)}</span>
              <strong>{file.name || file.path || "file"}</strong>
              <em>{file.path || ""}</em>
            </button>
          ))}
          {files.length === 0 ? <div class="empty">No files for this user.</div> : null}
        </div>
      </div>

      <div class="session-box">
        <div class="panel-heading">
          <h3>User Events</h3>
          <span>{events.length} events</span>
        </div>
        <div class="timeline-list">
          {events.slice(0, 16).map((event, index) => (
            <button class="timeline-row" type="button" key={`${event.timestamp || 0}-${index}`} onClick={() => props.onInspectEvent(eventFromUserEvent(event, hash, index))}>
              <span>{event.time || ""}</span>
              <strong>{event.event || "event"}</strong>
              <em>{event.path || event.ip || ""}</em>
            </button>
          ))}
          {events.length === 0 ? <div class="empty">No recent events for this user.</div> : null}
        </div>
      </div>
    </>
  );
}

function ActorDetailBox(props: {
  actor: { actorType: ActorType; value: string };
  details?: ActorDetailPayload;
  loading: boolean;
  onInspectEvent: (event: EventRow) => void;
  onInspectSession: (session: SessionRow) => void;
  onInspectUser: (user: UserRow) => void;
  onOpenPath: (path?: string) => void;
}) {
  const files = props.details?.files ?? [];
  const sessions = props.details?.sessions ?? [];
  const events = props.details?.events ?? [];
  const summary = props.details?.summary ?? {};
  const isBanned = Boolean(summary.is_banned);
  const [showThumbs, setShowThumbs] = useState(true);
  if (props.loading) {
    return <div class="detail-box subtle">Loading actor drilldown...</div>;
  }
  return (
    <>
      <div class="event-card actor-card">
        <div class="event-card-head">
          <SourcePill source={props.actor.actorType === "ip" ? "explorer" : "sftp"} />
          <span class={isBanned ? "status-chip hot" : "status-chip"}>{isBanned ? "banned" : "observed"}</span>
        </div>
        <dl class="metadata">
          <Meta label={props.actor.actorType === "ip" ? "IP" : "User"} value={props.details?.actor || props.actor.value} />
          <Meta label="Window" value={props.details?.window?.label} />
          <Meta label="Events" value={formatNumber(numberFromUnknown(summary.events))} />
          <Meta label="Files" value={formatNumber(numberFromUnknown(summary.files))} />
          <Meta label="Sessions" value={formatNumber(numberFromUnknown(summary.sessions))} />
          <Meta label="Uploads" value={formatNumber(numberFromUnknown(summary.recent_uploads))} />
        </dl>
        <div class="inspector-actions event-actions">
          {props.actor.actorType === "user" ? (
            <button type="button" onClick={() => props.onInspectUser({ hash: props.details?.actor || props.actor.value })}>
              Inspect User
            </button>
          ) : null}
          <a class="button-link" href={adminPath("/admin/v2/", { view: "activity", q: props.details?.actor || props.actor.value })}>
            Filter Activity
          </a>
        </div>
      </div>

      <div class="session-box">
        <div class="panel-heading">
          <h3>Files</h3>
          <div class="heading-actions">
            <span>{files.length} touched</span>
            <ToggleButton active={showThumbs} label="Thumbnails" onClick={() => setShowThumbs((value) => !value)} />
          </div>
        </div>
        <div class="timeline-list">
          {files.slice(0, 18).map((file) => (
            <button class={`timeline-row actor-file-row ${showThumbs ? "with-file-preview" : ""}`} type="button" key={file.path || file.name} onClick={() => props.onOpenPath(file.path)}>
              {showThumbs && file.path ? <FilePreviewBadge path={file.path} /> : null}
              <span>{file.is_dir ? "dir" : file.size_human || formatBytes(file.size)}</span>
              <strong>{file.path || file.name || "file"}</strong>
              <em>{actorFileDetail(file)}</em>
            </button>
          ))}
          {files.length === 0 ? <div class="empty">No file paths for this actor in the current window.</div> : null}
        </div>
      </div>

      <div class="session-box">
        <div class="panel-heading">
          <h3>Sessions</h3>
          <span>{sessions.length} sessions</span>
        </div>
        <div class="timeline-list">
          {sessions.slice(0, 10).map((session) => (
            <button class="timeline-row" type="button" key={session.session} onClick={() => props.onInspectSession(session)}>
              <span>{formatDuration(session.duration_sec)}</span>
              <strong>{shortValue(session.session, 18)}</strong>
              <em>{`${formatNumber(session.event_count)} events ${session.ip || ""}`}</em>
            </button>
          ))}
          {sessions.length === 0 ? <div class="empty">No sessions for this actor.</div> : null}
        </div>
      </div>

      <div class="session-box">
        <div class="panel-heading">
          <h3>Recent Events</h3>
          <span>{events.length} events</span>
        </div>
        <div class="timeline-list">
          {events.slice(0, 14).map((event) => (
            <button class="timeline-row" type="button" key={event.id} onClick={() => props.onInspectEvent(event)}>
              <span>{event.time || ""}</span>
              <strong>{event.event || "event"}</strong>
              <em>{targetPath({ type: "event", event }) || event.session || event.ip || ""}</em>
            </button>
          ))}
          {events.length === 0 ? <div class="empty">No recent events for this actor.</div> : null}
        </div>
      </div>
    </>
  );
}

function EventMetaBlock({ event }: { event: EventRow }) {
  const metaObject = event.meta_obj && Object.keys(event.meta_obj).length > 0 ? event.meta_obj : null;
  const text = metaObject ? JSON.stringify(metaObject, null, 2) : event.meta || "";
  if (!text) {
    return null;
  }
  return (
    <div class="json-block">
      <div class="panel-heading">
        <h3>Event Metadata</h3>
      </div>
      <pre>{text}</pre>
    </div>
  );
}

function SessionTimelineBox({ session, loading, onInspectEvent }: { session?: SessionTimelinePayload; loading: boolean; onInspectEvent: (event: EventRow) => void }) {
  const rows = useMemo(
    () => [...(session?.events ?? [])].sort((a, b) => (a.timestamp ?? 0) - (b.timestamp ?? 0) || a.id - b.id),
    [session?.events]
  );
  const profile = useMemo(() => activityProfile(rows), [rows]);
  const started = session?.started_at ?? rows[0]?.timestamp ?? 0;
  const ended = session?.ended_at ?? rows[rows.length - 1]?.timestamp ?? started;
  const duration = Math.max(0, ended - started);
  const hasEndEvent = rows.some((row) => (row.event || "").toLowerCase() === "session/end");
  if (loading) {
    return <div class="detail-box subtle">Loading session timeline...</div>;
  }
  if (!session?.session) {
    return null;
  }
  return (
    <div class="session-box session-viewer">
      <div class="panel-heading">
        <h3>Session Timeline</h3>
        <span class={hasEndEvent ? "status-chip" : "status-chip hot"}>{hasEndEvent ? "complete" : "active"}</span>
      </div>
      <dl class="metadata compact-meta">
        <Meta label="Session" value={session.session} />
        <Meta label="User" value={session.user_id} />
        <Meta label="IP" value={session.ip} />
        <Meta label="Started" value={session.start_time} />
        <Meta label="Ended" value={session.end_time} />
      </dl>
      <div class="session-stat-strip">
        <Metric label="Events" value={formatNumber(rows.length)} compact />
        <Metric label="Duration" value={formatDuration(duration)} compact />
        <Metric label="Transfers" value={formatNumber(profile.transfer)} compact />
        <Metric label="Denied" value={formatNumber(profile.denied)} compact tone={profile.denied > 0 ? "warn" : "normal"} />
      </div>
      <div class="session-rail" aria-label="Session event timeline">
        <div class="session-rail-line" />
        {rows.map((row, index) => (
          <button
            class={`session-node ${sessionNodeClass(row)}`}
            type="button"
            key={row.id}
            style={{ left: `${sessionNodeLeft(row, started, ended, index, rows.length)}%` }}
            title={`${row.time || ""} ${row.event || "event"}`}
            onClick={() => onInspectEvent({ ...row, session: session.session })}
          >
            <span>{shortEventName(row.event)}</span>
          </button>
        ))}
      </div>
      <div class="session-axis">
        <span>{session.start_time || "start"}</span>
        <strong>{formatDuration(duration)}</strong>
        <span>{hasEndEvent ? session.end_time || "end" : "now"}</span>
      </div>
      <div class="timeline-list session-event-list">
        {rows.map((row) => (
          <button class={`timeline-row session-event-row ${sessionNodeClass(row)}`} type="button" key={row.id} onClick={() => onInspectEvent({ ...row, session: session.session })}>
            <span>{sessionOffset(row, started)}</span>
            <strong>{row.event || "event"}</strong>
            <em>{targetPath({ type: "event", event: row }) || statusFor(row)}</em>
          </button>
        ))}
      </div>
    </div>
  );
}

function PreviewHero({ preview }: { preview: PreviewPayload }) {
  const thumb = useQuery({
    queryKey: ["thumbnail", preview.thumb_url],
    queryFn: () => fetchBlobURL(preview.thumb_url || ""),
    enabled: Boolean(preview.thumb_url)
  });

  if (preview.is_image && preview.thumb_url) {
    return (
      <div class="preview-hero">
        {thumb.data ? <img src={thumb.data} alt={preview.name} /> : <span>Thumbnail loading</span>}
      </div>
    );
  }
  if (preview.is_video && preview.video_url) {
    return (
      <div class="preview-hero">
        <video src={preview.video_url} controls />
      </div>
    );
  }
  return (
    <div class="preview-hero placeholder">
      <span>{preview.is_dir ? "Directory" : preview.ext || "File"}</span>
    </div>
  );
}

function PreviewDetails({ preview }: { preview: PreviewPayload }) {
  if (preview.is_dir) {
    return (
      <div class="detail-box">
        <strong>Contents</strong>
        <span>{preview.child_dirs ?? 0} directories</span>
        <span>{preview.child_files ?? 0} files</span>
      </div>
    );
  }
  if (preview.is_text) {
    return (
      <div class="text-preview">
        <div class="panel-heading">
          <h3>Text Preview</h3>
          <span>{preview.text_line_count ?? 0} lines</span>
        </div>
        <pre>{(preview.text_lines ?? []).join("\n")}</pre>
      </div>
    );
  }
  if (preview.is_archive) {
    return (
      <div class="archive-list">
        <div class="panel-heading">
          <h3>Archive</h3>
          <span>{preview.archive_entries?.length ?? 0} entries</span>
        </div>
        {(preview.archive_entries ?? []).slice(0, 12).map((entry) => (
          <div class="archive-row" key={entry.name}>
            <span>{entry.name}</span>
            <span>{entry.size || ""}</span>
          </div>
        ))}
      </div>
    );
  }
  if (preview.is_pdf) {
    return <div class="detail-box">PDF pages: {preview.pdf_page_count ?? "unknown"}</div>;
  }
  if (preview.is_stl) {
    return (
      <div class="detail-box">
        <strong>{preview.stl_title || "STL model"}</strong>
        <span>{preview.stl_triangles ?? 0} triangles</span>
      </div>
    );
  }
  return null;
}

function Metric({
  label,
  value,
  tone = "normal",
  compact = false,
  active = false,
  onClick
}: {
  label: string;
  value: string;
  tone?: "normal" | "warn";
  compact?: boolean;
  active?: boolean;
  onClick?: () => void;
}) {
  const className = `metric ${tone === "warn" ? "warn" : ""} ${compact ? "compact" : ""} ${active ? "active" : ""} ${onClick ? "clickable" : ""}`;
  const content = (
    <>
      <span>{label}</span>
      <strong>{value}</strong>
    </>
  );
  if (onClick) {
    return (
      <button class={className} type="button" data-metric={metricKey(label)} onClick={onClick}>
        {content}
      </button>
    );
  }
  return (
    <div class={className} data-metric={metricKey(label)}>
      {content}
    </div>
  );
}

function SourcePill({ source }: { source: string }) {
  return <span class={`source-pill ${source}`}>{source}</span>;
}

function DataPanel(props: { title: string; empty: string; children: ComponentChildren; action?: ComponentChildren }) {
  const hasChildren = hasRenderableChildren(props.children);
  return (
    <section class="data-panel">
      <div class="panel-heading">
        <h2>{props.title}</h2>
        {props.action ? <div class="heading-actions">{props.action}</div> : null}
      </div>
      {hasChildren ? props.children : <div class="empty">{props.empty}</div>}
    </section>
  );
}

function hasRenderableChildren(children: ComponentChildren): boolean {
  if (Array.isArray(children)) {
    return children.some(hasRenderableChildren);
  }
  return children !== null && children !== undefined && children !== false;
}

function ToggleButton(props: { active: boolean; label: string; onClick: () => void }) {
  return (
    <button class={`toggle-button ${props.active ? "active" : ""}`} type="button" onClick={props.onClick}>
      {props.label}
    </button>
  );
}

function FilePreviewBadge({ path, size = "small" }: { path: string; size?: "small" | "large" }) {
  const preview = useQuery({
    queryKey: ["file-preview-badge", path],
    queryFn: () => api<PreviewPayload>(previewURL(path)),
    staleTime: 60_000
  });
  const thumb = useQuery({
    queryKey: ["file-preview-badge-thumb", preview.data?.thumb_url],
    queryFn: () => fetchBlobURL(preview.data?.thumb_url || ""),
    enabled: Boolean(preview.data?.thumb_url),
    staleTime: 60_000
  });
  const kind = preview.data ? kindForPreview(preview.data) : thumbnailKindForPath(path);
  const label = preview.data?.name || basename(path);
  return (
    <span class={`file-preview-badge ${size} ${kind}`} aria-hidden="true">
      {thumb.data && !thumb.isError ? <img src={thumb.data} alt="" /> : <FileIcon kind={kind} label={label} />}
    </span>
  );
}

function FileIcon({ kind, label }: { kind: ThumbnailKind | "danger"; label?: string }) {
  const title = label || kind;
  switch (kind) {
    case "image":
      return (
        <svg viewBox="0 0 24 24" role="img" aria-label={title}>
          <rect x="3" y="3" width="18" height="18" rx="2" />
          <circle cx="8.5" cy="8.5" r="1.5" />
          <polyline points="21 15 16 10 5 21" />
        </svg>
      );
    case "video":
      return (
        <svg viewBox="0 0 24 24" role="img" aria-label={title}>
          <rect x="2" y="3" width="20" height="18" rx="2" />
          <path d="m10 8 5 4-5 4V8z" />
        </svg>
      );
    case "text":
      return (
        <svg viewBox="0 0 24 24" role="img" aria-label={title}>
          <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
          <polyline points="14 2 14 8 20 8" />
          <line x1="8" y1="13" x2="16" y2="13" />
          <line x1="8" y1="17" x2="16" y2="17" />
        </svg>
      );
    case "archive":
      return (
        <svg viewBox="0 0 24 24" role="img" aria-label={title}>
          <polyline points="21 8 21 21 3 21 3 8" />
          <rect x="1" y="3" width="22" height="5" />
          <line x1="10" y1="12" x2="14" y2="12" />
        </svg>
      );
    case "pdf":
      return (
        <svg viewBox="0 0 24 24" role="img" aria-label={title}>
          <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
          <polyline points="14 2 14 8 20 8" />
          <line x1="8" y1="13" x2="12" y2="13" />
          <line x1="8" y1="17" x2="16" y2="17" />
        </svg>
      );
    case "model":
      return (
        <svg viewBox="0 0 24 24" role="img" aria-label={title}>
          <path d="M12 2 2 7l10 5 10-5-10-5z" />
          <path d="m2 17 10 5 10-5" />
          <path d="m2 12 10 5 10-5" />
        </svg>
      );
    case "directory":
      return (
        <svg viewBox="0 0 24 24" role="img" aria-label={title}>
          <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" />
        </svg>
      );
    case "danger":
      return (
        <svg viewBox="0 0 24 24" role="img" aria-label={title}>
          <path d="M10.29 3.86 1.82 18A2 2 0 0 0 3.53 21h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
          <line x1="12" y1="9" x2="12" y2="13" />
          <line x1="12" y1="17" x2="12.01" y2="17" />
        </svg>
      );
    default:
      return (
        <svg viewBox="0 0 24 24" role="img" aria-label={title}>
          <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
          <polyline points="14 2 14 8 20 8" />
        </svg>
      );
  }
}

function PathRow(props: { title: string; detail: string; meta: string; path?: string; thumbnail?: boolean; onClick: () => void }) {
  return (
    <button class={`path-row ${props.thumbnail ? "with-thumbnail" : ""}`} type="button" onClick={props.onClick}>
      {props.thumbnail && props.path ? <FilePreviewBadge path={props.path} /> : null}
      <span>
        <strong>{props.title}</strong>
        <small>{props.detail}</small>
      </span>
      <em>{props.meta}</em>
    </button>
  );
}

function Meta({ label, value }: { label: string; value?: string }) {
  if (!value) {
    return null;
  }
  return (
    <>
      <dt>{label}</dt>
      <dd>{value}</dd>
    </>
  );
}

async function runInspectorAction(action: InspectorAction): Promise<unknown> {
  switch (action.type) {
    case "delete":
      return postJSON("/admin/api/explorer/delete", { path: action.path });
    case "rename":
      return postJSON("/admin/api/explorer/rename", {
        path: action.path,
        new_name: action.newName
      });
    case "mark-bad":
      return postJSON("/admin/api/maintenance/mark-bad", { path: action.path });
    case "ban-owner":
      return postJSON("/admin/api/explorer/ban-owner", { path: action.path });
  }
}

function actionLabel(action: InspectorAction["type"]): string {
  switch (action) {
    case "mark-bad":
      return "Mark bad";
    case "ban-owner":
      return "Ban owner";
    default:
      return action;
  }
}

function eventFromSession(session: SessionRow): EventRow {
  return {
    id: Number(session.started_at || 0),
    timestamp: session.started_at,
    time: session.start_time,
    event: session.has_end ? "session" : "session/active",
    user_id: session.user_id,
    ip: session.ip,
    session: session.session,
    meta_obj: {
      end_time: session.end_time,
      duration: formatDuration(session.duration_sec),
      event_count: session.event_count ?? 0,
      uploads: session.upload_count ?? 0,
      downloads: session.download_count ?? 0,
      denied: session.denied_count ?? 0
    }
  };
}

function eventFromAuthAttempt(attempt: AuthAttemptRow): EventRow {
  return {
    id: attempt.id,
    timestamp: attempt.timestamp,
    time: attempt.time,
    event: "auth/attempt",
    user_id: attempt.user_id || attempt.generated_hash,
    ip: attempt.ip,
    session: attempt.session,
    meta_obj: {
      username: attempt.username || "",
      password: attempt.password || "",
      generated_hash: attempt.generated_hash || "",
      source: "sftp",
      status: "attempt"
    }
  };
}

function eventFromUserEvent(event: UserEventRow, hash: string, index: number): EventRow {
  return {
    id: Number(event.timestamp || index),
    timestamp: event.timestamp,
    time: event.time,
    event: event.event,
    user_id: hash,
    ip: event.ip,
    path: event.path,
    meta: event.meta,
    meta_obj: metaRecord({ id: 0, meta: event.meta })
  };
}

function eventCopyPayload(event: EventRow): Record<string, unknown> {
  return {
    ...event,
    source: sourceFor(event),
    status: statusFor(event),
    path: targetPath({ type: "event", event }),
    user_id: eventUser(event),
    session: eventSession(event),
    meta_obj: metaRecord(event)
  };
}

function credentialLabel(username?: string, password?: string): string {
  const user = username || "(empty)";
  const pass = password || "(empty)";
  return `${user} / ${pass}`;
}

function targetPath(target: InspectorTarget): string {
  if (target.type === "path") {
    return cleanPath(target.path);
  }
  if (target.type === "event") {
    return cleanPath(target.event.path || metaString(target.event, ["path", "target_path", "old_path", "new_path", "file"]));
  }
  if (target.type === "live") {
    return livePath(target.row);
  }
  return "";
}

function eventSession(event?: EventRow): string {
  if (!event) {
    return "";
  }
  return event.session || metaString(event, ["session", "session_id", "user_session"]);
}

function eventUser(event?: EventRow): string {
  if (!event) {
    return "";
  }
  return event.user_id || metaString(event, ["user", "user_id", "owner", "owner_hash", "generated_hash"]);
}

function eventCommand(event: EventRow): string {
  return metaString(event, ["command", "cmd", "exec", "argv", "args"]);
}

function eventInsight(event: EventRow): { title: string; label: string; tone?: "warn"; rows: InsightRow[] } | null {
  const path = targetPath({ type: "event", event });
  const user = eventUser(event);
  const session = eventSession(event);
  const status = statusFor(event);
  const error = metaString(event, ["error", "err", "message"]);
  if (eventIsDelete(event)) {
    return {
      title: "Delete Context",
      label: "mutation",
      tone: "warn",
      rows: [
        { label: "Deleted Path", value: path },
        { label: "Target", value: metaString(event, ["target", "old_path", "new_path", "file"]) },
        { label: "Actor", value: user },
        { label: "Session", value: session },
        { label: "Status", value: status },
        { label: "Error", value: error }
      ]
    };
  }
  if (isExecEvent(event)) {
    return {
      title: "Exec Context",
      label: "command",
      tone: "warn",
      rows: [
        { label: "Command", value: eventCommand(event) },
        { label: "Actor", value: user },
        { label: "IP", value: event.ip || metaString(event, ["ip", "remote_addr"]) },
        { label: "Session", value: session },
        { label: "Status", value: status },
        { label: "Error", value: error }
      ]
    };
  }
  if (isSessionEvent(event)) {
    return {
      title: "Session Context",
      label: "timeline",
      rows: [
        { label: "Session", value: session },
        { label: "Actor", value: user },
        { label: "IP", value: event.ip || metaString(event, ["ip", "remote_addr"]) },
        { label: "Started", value: metaString(event, ["start_time", "started_at"]) || event.time },
        { label: "Ended", value: metaString(event, ["end_time", "ended_at"]) },
        { label: "Duration", value: metaString(event, ["duration", "duration_sec"]) },
        { label: "Events", value: metaString(event, ["event_count", "events"]) }
      ]
    };
  }
  if ((event.event || "").toLowerCase().includes("auth")) {
    return {
      title: "Auth Context",
      label: "identity",
      tone: "warn",
      rows: [
        { label: "Username", value: metaString(event, ["username", "login"]) },
        { label: "Password", value: metaString(event, ["password"]) },
        { label: "Generated Hash", value: metaString(event, ["generated_hash"]) || user },
        { label: "IP", value: event.ip || metaString(event, ["ip", "remote_addr"]) },
        { label: "Session", value: session },
        { label: "Status", value: status }
      ]
    };
  }
  if (isTransferEvent(event)) {
    return {
      title: "Transfer Context",
      label: "file",
      rows: [
        { label: "Path", value: path },
        { label: "Actor", value: user },
        { label: "IP", value: event.ip || metaString(event, ["ip", "remote_addr"]) },
        { label: "Session", value: session },
        { label: "Bytes", value: metaString(event, ["size", "bytes", "delta", "upload_bytes", "download_bytes"]) },
        { label: "Status", value: status }
      ]
    };
  }
  return null;
}

function eventIsDelete(event: EventRow): boolean {
  const name = (event.event || "").toLowerCase();
  const action = metaString(event, ["action", "operation"]).toLowerCase();
  return name.includes("delete") || action.includes("delete") || action.includes("unlink");
}

function statusClass(event: EventRow): string {
  const status = statusFor(event).toLowerCase();
  if (status.includes("fail") || status.includes("error") || status.includes("denied") || status.includes("bad")) {
    return "status-chip hot";
  }
  return "status-chip";
}

function metaString(row: EventRow, keys: string[]): string {
  const meta = metaRecord(row);
  for (const key of keys) {
    const value = meta[key];
    if (typeof value === "string" && value.trim() !== "") {
      return value;
    }
    if (typeof value === "number" || typeof value === "boolean") {
      return String(value);
    }
    if (Array.isArray(value) && value.length > 0) {
      return value.map((item) => String(item)).join(" ");
    }
    if (value && typeof value === "object") {
      return JSON.stringify(value);
    }
  }
  return "";
}

function metaRecord(row: EventRow): Record<string, unknown> {
  if (row.meta_obj && typeof row.meta_obj === "object" && !Array.isArray(row.meta_obj)) {
    return row.meta_obj;
  }
  if (!row.meta) {
    return {};
  }
  try {
    const parsed = JSON.parse(row.meta);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
  } catch {
    return {};
  }
  return {};
}

function countBySource(rows: EventRow[]): Record<SourceFilter, number> {
  const counts: Record<SourceFilter, number> = { all: rows.length, sftp: 0, admin: 0, explorer: 0 };
  for (const row of rows) {
    counts[sourceFor(row)]++;
  }
  return counts;
}

function percentOf(value: number, total: number): number {
  if (total <= 0) {
    return 0;
  }
  return (value / total) * 100;
}

function eventBuckets(rows: EventRow[], size: number): number[] {
  const buckets = Array.from({ length: size }, () => 0);
  if (rows.length === 0) {
    return buckets;
  }
  const times = rows.map((row) => Number(row.timestamp || 0)).filter((value) => value > 0);
  if (times.length === 0) {
    rows.forEach((_row, index) => {
      buckets[Math.min(size - 1, Math.floor((index / Math.max(rows.length, 1)) * size))]++;
    });
    return buckets;
  }
  const min = Math.min(...times);
  const max = Math.max(...times);
  const span = Math.max(1, max - min + 1);
  for (const timestamp of times) {
    const bucket = Math.min(size - 1, Math.floor(((timestamp - min) / span) * size));
    buckets[bucket]++;
  }
  return buckets;
}

function activityProfile(rows: EventRow[]) {
  return {
    total: rows.length,
    attention: rows.filter(isAttentionEvent).length,
    denied: rows.filter(isDeniedEvent).length,
    transfer: rows.filter(isTransferEvent).length,
    mutating: rows.filter(isMutatingEvent).length,
    session: rows.filter(isSessionEvent).length,
    exec: rows.filter(isExecEvent).length
  };
}

function matchesActivityKind(row: EventRow, kind: ActivityKind): boolean {
  switch (kind) {
    case "attention":
      return isAttentionEvent(row);
    case "denied":
      return isDeniedEvent(row);
    case "transfer":
      return isTransferEvent(row);
    case "mutating":
      return isMutatingEvent(row);
    case "session":
      return isSessionEvent(row);
    case "exec":
      return isExecEvent(row);
    case "all":
    default:
      return true;
  }
}

function rawStatus(row: EventRow): string {
  return valueFromMeta(row, "status") || valueFromMeta(row, "result");
}

function eventText(row: EventRow): string {
  return `${row.event || ""} ${rawStatus(row)} ${metaString(row, ["action", "operation", "error", "err", "message", "command", "cmd", "exec"])}`.toLowerCase();
}

function isAttentionEvent(row: EventRow): boolean {
  const text = eventText(row);
  return text.includes("fail") || text.includes("error") || text.includes("denied") || text.includes("panic") || text.includes("bad");
}

function isDeniedEvent(row: EventRow): boolean {
  return eventText(row).includes("denied");
}

function isTransferEvent(row: EventRow): boolean {
  const name = (row.event || "").toLowerCase();
  return name === "upload" || name === "download" || name.includes("upload") || name.includes("download");
}

function isMutatingEvent(row: EventRow): boolean {
  const text = eventText(row);
  return eventIsDelete(row) || text.includes("rename") || text.includes("ban") || text.includes("mark-bad") || text.includes("move") || text.includes("write");
}

function isSessionEvent(row: EventRow): boolean {
  const name = (row.event || "").toLowerCase();
  return name.startsWith("session") || name.includes("session/");
}

function isExecEvent(row: EventRow): boolean {
  const text = eventText(row);
  return text.includes("exec") || text.includes("command") || eventCommand(row) !== "";
}

function sessionNodeClass(row: EventRow): string {
  if (isDeniedEvent(row) || isAttentionEvent(row)) {
    return "attention";
  }
  if (isTransferEvent(row)) {
    return "transfer";
  }
  if (isMutatingEvent(row)) {
    return "mutation";
  }
  if (isSessionEvent(row)) {
    return "session";
  }
  return "neutral";
}

function sessionNodeLeft(row: EventRow, started: number, ended: number, index: number, total: number): number {
  if (ended > started && row.timestamp) {
    return Math.max(1, Math.min(99, ((row.timestamp - started) / (ended - started)) * 100));
  }
  if (total <= 1) {
    return 50;
  }
  return Math.max(1, Math.min(99, (index / (total - 1)) * 100));
}

function shortEventName(event: string | undefined): string {
  const name = (event || "event").replace("session/", "sess/").replace("download", "down").replace("upload", "up");
  return name.length > 9 ? `${name.slice(0, 8)}.` : name;
}

function sessionOffset(row: EventRow, started: number): string {
  const offset = Math.max(0, (row.timestamp ?? started) - started);
  return `+${formatDuration(offset)}`;
}

function topCounts(rows: EventRow[], value: (row: EventRow) => string, limit: number): NamedCount[] {
  const counts = new Map<string, number>();
  for (const row of rows) {
    const key = value(row).trim();
    if (!key) {
      continue;
    }
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return Array.from(counts.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name))
    .slice(0, limit);
}

function topCountsFromStrings(values: string[], limit: number): NamedCount[] {
  const counts = new Map<string, number>();
  for (const value of values) {
    const key = value.trim();
    if (!key) {
      continue;
    }
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return Array.from(counts.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name))
    .slice(0, limit);
}

function userProfile(users: UserRow[]) {
  const uploadBytes = users.reduce((sum, user) => sum + (user.upload_bytes ?? 0), 0);
  const downloadBytes = users.reduce((sum, user) => sum + (user.download_bytes ?? 0), 0);
  const uploadCount = users.reduce((sum, user) => sum + (user.upload_count ?? 0), 0);
  const downloadCount = users.reduce((sum, user) => sum + (user.download_count ?? 0), 0);
  const sessions = users.reduce((sum, user) => sum + (user.seen ?? 0), 0);
  const active = users.filter(isActiveUser).length;
  return {
    total: users.length,
    active,
    quiet: Math.max(0, users.length - active),
    banned: users.filter((user) => user.is_banned).length,
    uploaders: users.filter((user) => (user.upload_count ?? 0) > 0 || (user.upload_bytes ?? 0) > 0).length,
    downloaders: users.filter((user) => (user.download_count ?? 0) > 0 || (user.download_bytes ?? 0) > 0).length,
    sessions,
    uploadCount,
    uploadBytes,
    downloadCount,
    downloadBytes
  };
}

function filterUsers(users: UserRow[], filter: UserFilter): UserRow[] {
  switch (filter) {
    case "active":
      return users.filter(isActiveUser);
    case "uploaders":
      return users.filter((user) => (user.upload_count ?? 0) > 0 || (user.upload_bytes ?? 0) > 0);
    case "downloaders":
      return users.filter((user) => (user.download_count ?? 0) > 0 || (user.download_bytes ?? 0) > 0);
    case "banned":
      return users.filter((user) => user.is_banned);
    case "quiet":
      return users.filter((user) => !isActiveUser(user));
    case "all":
    default:
      return users;
  }
}

function sortUsers(users: UserRow[], sort: UserSort): UserRow[] {
  const next = [...users];
  return next.sort((a, b) => {
    let delta = 0;
    if (sort === "uploads") {
      delta = (b.upload_bytes ?? 0) - (a.upload_bytes ?? 0) || (b.upload_count ?? 0) - (a.upload_count ?? 0);
    } else if (sort === "downloads") {
      delta = (b.download_bytes ?? 0) - (a.download_bytes ?? 0) || (b.download_count ?? 0) - (a.download_count ?? 0);
    } else if (sort === "sessions") {
      delta = (b.seen ?? 0) - (a.seen ?? 0);
    } else if (sort === "last_login") {
      delta = userLoginTime(b) - userLoginTime(a);
    } else {
      delta = userActivityScore(b) - userActivityScore(a);
    }
    return delta || a.hash.localeCompare(b.hash);
  });
}

function userActivityScore(user: UserRow): number {
  return (user.seen ?? 0) + (user.upload_count ?? 0) + (user.download_count ?? 0);
}

function userLoginTime(user: UserRow): number {
  const parsed = Date.parse(user.last_login || "");
  return Number.isFinite(parsed) ? parsed : 0;
}

function isActiveUser(user: UserRow): boolean {
  return userActivityScore(user) > 0 || userLoginTime(user) > 0;
}

function userWorkbenchCopy(profile: ReturnType<typeof userProfile>, visible: number, total: number): string {
  if (total === 0) {
    return "No users match the current search.";
  }
  if (profile.banned > 0) {
    return `${visible} visible users, ${profile.banned} banned, ${formatBytes(profile.uploadBytes)} uploaded, ${formatBytes(profile.downloadBytes)} downloaded.`;
  }
  return `${visible} visible users, ${profile.active} active, ${formatNumber(profile.sessions)} tracked sessions, ${formatBytes(profile.uploadBytes)} uploaded.`;
}

function sortLabel(sort: UserSort): string {
  switch (sort) {
    case "uploads":
      return "uploads";
    case "downloads":
      return "downloads";
    case "sessions":
      return "sessions";
    case "last_login":
      return "last login";
    case "activity":
    default:
      return "activity";
  }
}

function collectThumbnailCandidates(events: EventRow[], uploads: UploadRow[], downloads?: DownloadsPayload): ThumbnailCandidate[] {
  const byPath = new Map<string, ThumbnailCandidate>();
  const add = (candidate: ThumbnailCandidate) => {
    const path = cleanPath(candidate.path);
    if (!path || byPath.has(path)) {
      return;
    }
    byPath.set(path, { ...candidate, path });
  };

  for (const upload of uploads) {
    add({
      path: upload.path || "",
      source: "upload",
      detail: `${upload.time || "recent"} ${shortValue(upload.user_id, 10)}`,
      meta: formatBytes(upload.size),
      kind: thumbnailKindForPath(upload.path || "")
    });
  }
  for (const file of downloads?.files ?? []) {
    add({
      path: file.path,
      source: "download",
      detail: `${file.downloads_in_range ?? 0} in range, ${file.downloads_total ?? 0} total`,
      meta: file.size_human || "",
      kind: thumbnailKindForPath(file.path)
    });
  }
  for (const row of events) {
    const path = targetPath({ type: "event", event: row });
    if (!path) {
      continue;
    }
    add({
      path,
      source: sourceFor(row),
      detail: `${row.time || ""} ${row.event || ""}`.trim(),
      meta: shortValue(row.user_id || row.ip, 12),
      kind: thumbnailKindForPath(path)
    });
  }
  return Array.from(byPath.values());
}

function filterThumbnailCandidates(candidates: ThumbnailCandidate[], filter: ThumbnailFilter): ThumbnailCandidate[] {
  if (filter === "all") {
    return candidates;
  }
  if (filter === "visual") {
    return candidates.filter((candidate) => candidate.kind === "image" || candidate.kind === "video" || candidate.kind === "pdf" || candidate.kind === "model");
  }
  return candidates.filter((candidate) => candidate.kind === filter);
}

function sortThumbnailCandidates(candidates: ThumbnailCandidate[], sort: ThumbnailSort): ThumbnailCandidate[] {
  const next = [...candidates];
  if (sort === "recent") {
    return next;
  }
  return next.sort((a, b) => {
    if (sort === "kind") {
      return a.kind.localeCompare(b.kind) || basename(a.path).localeCompare(basename(b.path));
    }
    if (sort === "source") {
      return a.source.localeCompare(b.source) || basename(a.path).localeCompare(basename(b.path));
    }
    return basename(a.path).localeCompare(basename(b.path));
  });
}

function filterThumbnailFolder(candidates: ThumbnailCandidate[], folder: string): ThumbnailCandidate[] {
  if (folder === "all") {
    return candidates;
  }
  return candidates.filter((candidate) => folderForPath(candidate.path) === folder);
}

function filterThumbnailSearch(candidates: ThumbnailCandidate[], query: string): ThumbnailCandidate[] {
  const needle = query.trim().toLowerCase();
  if (!needle) {
    return candidates;
  }
  return candidates.filter((candidate) =>
    `${candidate.path} ${candidate.detail} ${candidate.meta || ""} ${candidate.source} ${candidate.kind}`.toLowerCase().includes(needle)
  );
}

function thumbnailFolders(candidates: ThumbnailCandidate[], limit: number): NamedCount[] {
  return topCountsFromStrings(candidates.map((candidate) => folderForPath(candidate.path)), limit);
}

function folderForPath(path: string): string {
  const clean = cleanPath(path);
  if (!clean || !clean.includes("/")) {
    return "/";
  }
  return clean.slice(0, clean.lastIndexOf("/")) || "/";
}

function thumbnailMetaLine(preview: PreviewPayload | undefined, fallback: string): string {
  if (!preview) {
    return fallback;
  }
  const parts = [preview.size || preview.total_size || "", preview.owner ? `owner ${shortValue(preview.owner, 12)}` : "", `${formatNumber(preview.downloads)} downloads`].filter(Boolean);
  return parts.join(" / ") || fallback;
}

function thumbnailDetailLine(preview: PreviewPayload | undefined): string {
  if (!preview) {
    return "";
  }
  if (preview.is_image && preview.image_width && preview.image_height) {
    return `${preview.image_width} x ${preview.image_height} ${preview.image_mode || ""}`.trim();
  }
  if (preview.is_video) {
    return preview.video_native ? "native video preview" : "video file";
  }
  if (preview.is_pdf) {
    return `${formatNumber(preview.pdf_page_count)} PDF pages`;
  }
  if (preview.is_archive) {
    return `${formatNumber(preview.archive_entries?.length)} archive entries`;
  }
  if (preview.is_text) {
    return `${formatNumber(preview.text_line_count)} lines / ${formatNumber(preview.text_word_count)} words`;
  }
  if (preview.is_stl) {
    return `${formatNumber(preview.stl_triangles)} STL triangles`;
  }
  if (preview.is_dir) {
    return `${formatNumber(preview.child_dirs)} dirs / ${formatNumber(preview.child_files)} files`;
  }
  return preview.mod_time || "";
}

function thumbnailKindForPath(path: string): ThumbnailKind {
  const clean = cleanPath(path).toLowerCase();
  if (!clean) {
    return "other";
  }
  if (clean.endsWith("/")) {
    return "directory";
  }
  const ext = clean.includes(".") ? clean.slice(clean.lastIndexOf(".") + 1) : "";
  if (["apng", "avif", "gif", "heic", "heif", "jpeg", "jpg", "png", "svg", "webp"].includes(ext)) {
    return "image";
  }
  if (["avi", "m4v", "mkv", "mov", "mp4", "mpeg", "mpg", "webm"].includes(ext)) {
    return "video";
  }
  if (ext === "pdf") {
    return "pdf";
  }
  if (["7z", "gz", "rar", "tar", "tgz", "zip"].includes(ext)) {
    return "archive";
  }
  if (["css", "csv", "go", "html", "js", "json", "log", "md", "py", "rs", "sh", "toml", "ts", "tsx", "txt", "xml", "yaml", "yml"].includes(ext)) {
    return "text";
  }
  if (["3mf", "obj", "stl"].includes(ext)) {
    return "model";
  }
  return "other";
}

function previewKind(preview?: PreviewPayload): string {
  if (!preview) {
    return "file";
  }
  if (preview.is_dir) {
    return "dir";
  }
  if (preview.is_image) {
    return "image";
  }
  if (preview.is_video) {
    return "video";
  }
  if (preview.is_pdf) {
    return "pdf";
  }
  if (preview.is_archive) {
    return "archive";
  }
  if (preview.is_text) {
    return "text";
  }
  if (preview.is_stl) {
    return "stl";
  }
  return preview.ext || "file";
}

function kindForPreview(preview: PreviewPayload): ThumbnailKind {
  if (preview.is_dir) {
    return "directory";
  }
  if (preview.is_image) {
    return "image";
  }
  if (preview.is_video) {
    return "video";
  }
  if (preview.is_pdf) {
    return "pdf";
  }
  if (preview.is_archive) {
    return "archive";
  }
  if (preview.is_text) {
    return "text";
  }
  if (preview.is_stl) {
    return "model";
  }
  return thumbnailKindForPath(preview.rel_path || preview.name);
}

function pulseCopy(events: EventRow[], explorerEvents: EventRow[], insights?: InsightsPayload): string {
  if (events.length === 0) {
    return "No events recorded in the current window.";
  }
  const denied = insights?.kpi?.denied ?? 0;
  if (denied > 0) {
    return `${events.length} events, ${denied} denied, ${explorerEvents.length} explorer-origin.`;
  }
  return `${events.length} events, ${explorerEvents.length} explorer-origin, no denied events in view.`;
}

function securityCopy(attempts: AuthAttemptRow[], suspicious: NamedPair[], denied: number, panics: number): string {
  if (panics > 0) {
    return `${panics} parsed panics, ${denied} denied events, ${attempts.length} auth attempts.`;
  }
  if (suspicious.length > 0) {
    return `${suspicious.length} suspicious IPs, ${denied} denied events, ${attempts.length} auth attempts.`;
  }
  if (attempts.length > 0) {
    return `${attempts.length} auth attempts in view, no suspicious IPs flagged.`;
  }
  return "No auth attempts or high-risk signals in this window.";
}

function shortUserAgent(ua: string): string {
  return ua
    .replace(/\s+/g, " ")
    .replace(/Mozilla\/5\.0\s*/i, "")
    .trim()
    .slice(0, 86);
}

function uaActivityLabel(row: UserAgentStat): string {
  const parts = [
    (row.uploads ?? 0) > 0 ? `${formatNumber(row.uploads)} up` : "",
    (row.downloads ?? 0) > 0 ? `${formatNumber(row.downloads)} down` : "",
    (row.denied ?? 0) > 0 ? `${formatNumber(row.denied)} denied` : "",
    (row.mutations ?? 0) > 0 ? `${formatNumber(row.mutations)} changes` : ""
  ].filter(Boolean);
  return parts.join(" / ") || row.top_event || "activity";
}

function actorFileDetail(file: ActorFileRow): string {
  const parts = [
    file.last_event || "",
    file.last_time || "",
    file.upload_count ? `${formatNumber(file.upload_count)} up` : "",
    file.download_count ? `${formatNumber(file.download_count)} down` : "",
    file.denied_count ? `${formatNumber(file.denied_count)} denied` : ""
  ].filter(Boolean);
  return parts.join(" / ");
}

function panicText(row: unknown): string {
  if (typeof row === "string") {
    return row;
  }
  if (row && typeof row === "object") {
    const record = row as Record<string, unknown>;
    return stringFromRecord(record, ["time", "timestamp", "message", "msg", "line"]) || JSON.stringify(row);
  }
  return String(row ?? "");
}

function sourceFor(row: EventRow): SourceFilter {
  const source = valueFromMeta(row, "source").toLowerCase();
  if (source === "explorer" || source === "admin" || source === "sftp") {
    return source;
  }
  if ((row.event || "").startsWith("explorer_")) {
    return "explorer";
  }
  if ((row.user_id || "") === "system" || (row.event || "").startsWith("admin/")) {
    return "admin";
  }
  return "sftp";
}

function statusFor(row: EventRow): string {
  return rawStatus(row) || (isAttentionEvent(row) ? "attention" : "ok");
}

function valueFromMeta(row: EventRow, key: string): string {
  const value = row.meta_obj?.[key];
  if (typeof value === "string") {
    return value;
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  return "";
}

function cleanPath(path: string | undefined): string {
  return (path || "").trim().replace(/^\/+/, "");
}

function basename(path: string): string {
  const clean = cleanPath(path);
  if (!clean) {
    return "";
  }
  const parts = clean.split("/");
  return parts[parts.length - 1] || clean;
}

function countLive(payload?: LivePayload): number {
  const connections = Array.isArray(payload?.connections) ? payload.connections.length : 0;
  const sessions = Array.isArray(payload?.sessions) ? payload.sessions.length : 0;
  const transfers = Array.isArray(payload?.transfers) ? payload.transfers.length : 0;
  const requests = Array.isArray(payload?.requests) ? payload.requests.length : 0;
  return connections + sessions + transfers + requests;
}

function formatNumber(value: number | undefined): string {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return "0";
  }
  return new Intl.NumberFormat().format(value);
}

function numberFromUnknown(value: unknown): number {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === "string") {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : 0;
  }
  return 0;
}

function formatBytes(value: number | undefined): string {
  if (!value) {
    return "0 B";
  }
  const units = ["B", "KB", "MB", "GB", "TB"];
  let next = value;
  let unit = 0;
  while (next >= 1024 && unit < units.length - 1) {
    next /= 1024;
    unit++;
  }
  return `${next.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}

function formatRate(value: number | undefined): string {
  return value && value > 0 ? `${formatBytes(value)}/s` : "0 B/s";
}

function formatPercent(value: number | undefined): string {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    return "0%";
  }
  return `${value.toFixed(1).replace(/\.0$/, "")}%`;
}

function clampPercent(value: number | undefined): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return 0;
  }
  return Math.max(0, Math.min(100, value));
}

function formatDuration(seconds: number | undefined): string {
  if (!seconds || seconds < 0) {
    return "0s";
  }
  if (seconds < 60) {
    return `${Math.round(seconds)}s`;
  }
  if (seconds < 3600) {
    return `${Math.round(seconds / 60)}m`;
  }
  return `${Math.round(seconds / 3600)}h`;
}

function shortValue(value: string | undefined, length = 12): string {
  if (!value) {
    return "";
  }
  if (value.length <= length) {
    return value;
  }
  return `${value.slice(0, length)}...`;
}

function recordArray(value: unknown): Array<Record<string, unknown>> {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.filter((item): item is Record<string, unknown> => Boolean(item) && typeof item === "object" && !Array.isArray(item));
}

function stringFromRecord(row: Record<string, unknown>, keys: string[]): string {
  for (const key of keys) {
    const value = row[key];
    if (typeof value === "string" && value.trim() !== "") {
      return value;
    }
    if (typeof value === "number" && Number.isFinite(value)) {
      return String(value);
    }
  }
  return "";
}

function boolFromRecord(row: Record<string, unknown>, key: string): boolean {
  return row[key] === true || row[key] === "true";
}

function livePath(row: Record<string, unknown>): string {
  return cleanPath(stringFromRecord(row, ["path", "last_path"]));
}

function liveUser(row: Record<string, unknown>): string {
  return stringFromRecord(row, ["user_id", "user", "owner", "owner_hash"]);
}

function liveIP(row: Record<string, unknown>): string {
  return stringFromRecord(row, ["ip", "remote_ip"]) || hostFromAddress(stringFromRecord(row, ["remote_addr"]));
}

function liveSessionID(row: Record<string, unknown> | undefined): string {
  if (!row) {
    return "";
  }
  return stringFromRecord(row, ["session", "session_id"]);
}

function liveRate(row: Record<string, unknown>): string {
  const direct = numberFromUnknown(row.rate_bps);
  const total = numberFromUnknown(row.total_rate_bps);
  const upload = numberFromUnknown(row.upload_rate_bps);
  const download = numberFromUnknown(row.download_rate_bps);
  const value = direct || total || upload + download;
  return value > 0 ? `${formatBytes(value)}/s` : "";
}

function liveBytes(row: Record<string, unknown>): string {
  const direct = numberFromUnknown(row.bytes);
  const upload = numberFromUnknown(row.upload_bytes);
  const download = numberFromUnknown(row.download_bytes);
  if (direct > 0) {
    return formatBytes(direct);
  }
  const parts = [];
  if (upload > 0) {
    parts.push(`${formatBytes(upload)} up`);
  }
  if (download > 0) {
    parts.push(`${formatBytes(download)} down`);
  }
  return parts.join(" / ");
}

function liveDuration(row: Record<string, unknown>, key: string): string {
  const seconds = numberFromUnknown(row[key]);
  return seconds > 0 ? formatDuration(seconds) : "";
}

function liveActiveLine(row: Record<string, unknown>): string {
  const requests = numberFromUnknown(row.requests_active);
  const transfers = numberFromUnknown(row.active_transfers);
  const parts = [];
  if (requests > 0) {
    parts.push(`${formatNumber(requests)} requests`);
  }
  if (transfers > 0) {
    parts.push(`${formatNumber(transfers)} transfers`);
  }
  return parts.join(" / ");
}

function liveClientLine(row: Record<string, unknown>): string {
  return [stringFromRecord(row, ["client_version"]), stringFromRecord(row, ["user_agent"])].filter(Boolean).join(" / ");
}

function liveFlagLine(row: Record<string, unknown>): string {
  const flags = [];
  if (boolFromRecord(row, "admin")) {
    flags.push("admin");
  }
  if (boolFromRecord(row, "banned")) {
    flags.push("banned");
  }
  if (boolFromRecord(row, "throttled")) {
    flags.push("throttled");
  }
  const loginType = stringFromRecord(row, ["login_type"]);
  if (loginType) {
    flags.push(loginType);
  }
  return flags.join(" / ");
}

function liveStatusLabel(kind: LiveTargetKind, row: Record<string, unknown>): string {
  if (boolFromRecord(row, "banned")) {
    return "banned";
  }
  if (kind === "transfer") {
    return stringFromRecord(row, ["direction"]) || "transfer";
  }
  return stringFromRecord(row, ["state", "direction"]) || kind;
}

function liveStatusClass(row: Record<string, unknown>): string {
  if (boolFromRecord(row, "banned") || stringFromRecord(row, ["last_error", "error"])) {
    return "status-chip hot";
  }
  return "status-chip";
}

function liveInspectorTitle(kind: LiveTargetKind, row: Record<string, unknown>): string {
  return liveRowTitle(kind, row);
}

function filesMetric(summary?: SummaryPayload): MetricTarget {
  return {
    title: "File Inventory",
    value: formatNumber(summary?.files),
    summary: "Archive file and directory totals from the current summary snapshot.",
    rows: [
      { label: "Files", value: formatNumber(summary?.files) },
      { label: "Directories", value: formatNumber(summary?.directories) },
      { label: "Stored", value: summary?.formatted_bytes || formatBytes(summary?.bytes) },
      { label: "Contributor Min", value: formatBytes(summary?.contributor_threshold) }
    ]
  };
}

function directoriesMetric(summary?: SummaryPayload): MetricTarget {
  return {
    title: "Directory Inventory",
    value: formatNumber(summary?.directories),
    summary: "Directory count and storage context for the archive.",
    rows: [
      { label: "Directories", value: formatNumber(summary?.directories) },
      { label: "Files", value: formatNumber(summary?.files) },
      { label: "Stored", value: summary?.formatted_bytes || formatBytes(summary?.bytes) },
      { label: "Archive", value: summary?.archive }
    ]
  };
}

function storageMetric(summary?: SummaryPayload): MetricTarget {
  const storage = summary?.storage ?? [];
  const rows: InsightRow[] = [
    { label: "Stored", value: summary?.formatted_bytes || formatBytes(summary?.bytes) },
    { label: "Volumes", value: formatNumber(storage.length) }
  ];
  for (const volume of storage.slice(0, 5)) {
    rows.push({
      label: volume.label || volume.id || volume.kind || "Storage",
      value: volume.error || `${volume.used || formatBytes(volume.used_bytes)} used / ${volume.free || formatBytes(volume.free_bytes)} free`
    });
  }
  return {
    title: "Storage",
    value: summary?.formatted_bytes || formatBytes(summary?.bytes),
    summary: "Storage health for uploads, logs, and database files.",
    rows
  };
}

function uptimeMetric(summary?: SummaryPayload): MetricTarget {
  return {
    title: "Runtime",
    value: summary?.uptime || formatDuration(summary?.uptime_seconds),
    summary: "Process and listener details from the admin summary.",
    rows: [
      { label: "Uptime", value: summary?.uptime || formatDuration(summary?.uptime_seconds) },
      { label: "Version", value: summary?.version },
      { label: "Admin HTTP", value: summary?.admin_http },
      { label: "SSH", value: summary?.ssh_port ? `:${summary.ssh_port}` : "" },
      { label: "Archive", value: summary?.archive }
    ]
  };
}

function liveMetric(live: LivePayload | undefined, liveCount: number): MetricTarget {
  const payload = (live ?? {}) as Record<string, unknown>;
  const connections = numberFromUnknown(payload.connection_count) || recordArray(live?.connections).length;
  const sessions = numberFromUnknown(payload.session_count) || recordArray(live?.sessions).length;
  const transfers = numberFromUnknown(payload.transfer_count) || recordArray(live?.transfers).length;
  return {
    title: "Live Activity",
    value: formatNumber(liveCount),
    summary: "Current in-flight connections, sessions, and transfers.",
    rows: [
      { label: "Connections", value: formatNumber(connections) },
      { label: "Sessions", value: formatNumber(sessions) },
      { label: "Transfers", value: formatNumber(transfers) },
      { label: "Upload Rate", value: formatRate(numberFromUnknown(payload.upload_rate_bps)) },
      { label: "Download Rate", value: formatRate(numberFromUnknown(payload.download_rate_bps)) },
      { label: "Total Rate", value: formatRate(numberFromUnknown(payload.total_rate_bps)) },
      { label: "Uploaded", value: formatBytes(numberFromUnknown(payload.upload_bytes)) },
      { label: "Downloaded", value: formatBytes(numberFromUnknown(payload.download_bytes)) },
      { label: "Window", value: `${formatNumber(numberFromUnknown(payload.rate_window_sec))}s` }
    ]
  };
}

function authMetric(auth?: AuthAttemptsPayload): MetricTarget {
  const attempts = auth?.attempts ?? [];
  const latest = attempts[0];
  return {
    title: "Auth Attempts",
    value: formatNumber(attempts.length),
    summary: "Recent login attempts in the current security window.",
    rows: [
      { label: "Attempts", value: formatNumber(attempts.length) },
      { label: "Window", value: auth?.window?.label },
      { label: "Latest", value: latest ? `${latest.time || ""} ${latest.ip || ""}`.trim() : "" },
      { label: "Latest Username", value: latest?.username },
      { label: "Generated Hash", value: shortValue(latest?.generated_hash, 22) }
    ]
  };
}

function authCombosMetric(auth?: AuthAttemptsPayload): MetricTarget {
  const combos = auth?.combos ?? [];
  return {
    title: "Credential Combos",
    value: formatNumber(combos.length),
    summary: "Credential pairs seen in recent auth attempts.",
    rows: [
      { label: "Combos", value: formatNumber(combos.length) },
      { label: "Window", value: auth?.window?.label },
      ...combos.slice(0, 6).map((combo, index) => ({
        label: `#${index + 1}`,
        value: `${credentialLabel(combo.username, combo.password)} / ${formatNumber(combo.count)} tries`
      }))
    ]
  };
}

function suspiciousMetric(rows: NamedPair[]): MetricTarget {
  return {
    title: "Suspicious IPs",
    value: formatNumber(rows.length),
    summary: "IPs with suspicious or denied activity in the current window.",
    rows: [
      { label: "IPs", value: formatNumber(rows.length) },
      ...rows.slice(0, 7).map((row) => ({ label: row.name, value: `${formatNumber(row.count)} events / ${formatNumber(row.denied ?? 0)} denied` }))
    ]
  };
}

function panicMetric(insights?: InsightsPayload): MetricTarget {
  const rows = insights?.recent_panics ?? [];
  return {
    title: "Panics",
    value: formatNumber(insights?.parsed_panics),
    summary: "Parsed panic signals from recent logs.",
    rows: [
      { label: "Panics", value: formatNumber(insights?.parsed_panics) },
      ...rows.slice(0, 6).map((row, index) => ({ label: `Recent ${index + 1}`, value: shortValue(panicText(row), 72) }))
    ]
  };
}

function bannedIPMetric(banned?: BannedPayload): MetricTarget {
  const rows = banned?.ips ?? [];
  return {
    title: "Banned IPs",
    value: formatNumber(rows.length),
    summary: "IP addresses currently blocked by admin policy.",
    rows: [
      { label: "Banned IPs", value: formatNumber(rows.length) },
      ...rows.slice(0, 8).map((row) => ({ label: row.ip || "ip", value: [row.comment, row.banned_at].filter(Boolean).join(" / ") }))
    ]
  };
}

function bannedUserMetric(banned?: BannedPayload): MetricTarget {
  const rows = banned?.hashes ?? [];
  return {
    title: "Banned Users",
    value: formatNumber(rows.length),
    summary: "User hashes currently shadow-banned.",
    rows: [
      { label: "Banned Users", value: formatNumber(rows.length) },
      ...rows.slice(0, 8).map((row) => ({ label: shortValue(row.hash, 18), value: row.banned_at }))
    ]
  };
}

function hostFromAddress(value: string): string {
  if (!value) {
    return "";
  }
  const bracketed = value.match(/^\[([^\]]+)\]:\d+$/);
  if (bracketed) {
    return bracketed[1];
  }
  const parts = value.split(":");
  if (parts.length === 2 && /^\d+$/.test(parts[1])) {
    return parts[0];
  }
  return value;
}

function titleCase(value: string): string {
  if (!value) {
    return "";
  }
  return value.slice(0, 1).toUpperCase() + value.slice(1).replace(/[_-]+/g, " ");
}

function rangeLabel(range: string): string {
  switch (range) {
    case "15m":
      return "15m";
    case "1h":
      return "1h";
    case "6h":
      return "6h";
    case "24h":
      return "24h";
    case "48h":
      return "48h";
    case "7d":
      return "7d";
    case "30d":
      return "30d";
    case "all":
      return "All";
    default:
      return range;
  }
}

function sourceFilterLabel(source: SourceFilter): string {
  switch (source) {
    case "sftp":
      return "SFTP";
    case "admin":
      return "Admin";
    case "explorer":
      return "Explorer";
    case "all":
    default:
      return "All sources";
  }
}

function metricKey(label: string): string {
  return label.toLowerCase().replace(/[^a-z0-9]+/g, "-");
}

function isSmallViewport(): boolean {
  return typeof window !== "undefined" && window.matchMedia("(max-width: 820px)").matches;
}

function adminPath(path: string, params: Record<string, string | number | undefined>): string {
  const q = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === "") {
      continue;
    }
    q.set(key, String(value));
  }
  const query = q.toString();
  return query ? `${path}?${query}` : path;
}

function explorerURL(path: string): string {
  const clean = cleanPath(path);
  if (!clean) {
    return "/admin/explorer/";
  }
  return `/admin/explorer/${clean.split("/").map(encodeURIComponent).join("/")}`;
}

function readURLParam(key: string): string {
  return new URLSearchParams(window.location.search).get(key)?.trim() || "";
}

function parseViewParam(): View {
  const value = readURLParam("view");
  if (value === "activity" || value === "thumbnails" || value === "users" || value === "security") {
    return value;
  }
  return "overview";
}

function parseSourceParam(): SourceFilter {
  const value = readURLParam("source");
  if (value === "sftp" || value === "admin" || value === "explorer") {
    return value;
  }
  return "all";
}

function hasHueParam(): boolean {
  return new URLSearchParams(window.location.search).has("hue");
}

function parseHueParam(): number {
  const raw = Number(readURLParam("hue"));
  if (!Number.isFinite(raw)) {
    return defaultHue;
  }
  return clampHue(raw);
}

function replaceURLParams(params: Record<string, string>) {
  const url = new URL(window.location.href);
  for (const [key, value] of Object.entries(params)) {
    if (value === "") {
      url.searchParams.delete(key);
    } else {
      url.searchParams.set(key, value);
    }
  }
  window.history.replaceState(null, "", `${url.pathname}${url.search}${url.hash}`);
}

function clampHue(value: number): number {
  const next = Math.round(value) % 360;
  return next < 0 ? next + 360 : next;
}

function hexToHue(hex: string): number {
  const clean = hex.replace("#", "");
  const value = Number.parseInt(clean.length === 3 ? clean.split("").map((ch) => ch + ch).join("") : clean, 16);
  const r = ((value >> 16) & 255) / 255;
  const g = ((value >> 8) & 255) / 255;
  const b = (value & 255) / 255;
  const max = Math.max(r, g, b);
  const min = Math.min(r, g, b);
  const delta = max - min;
  if (delta === 0) {
    return defaultHue;
  }
  let hue = 0;
  if (max === r) {
    hue = 60 * (((g - b) / delta) % 6);
  } else if (max === g) {
    hue = 60 * ((b - r) / delta + 2);
  } else {
    hue = 60 * ((r - g) / delta + 4);
  }
  return clampHue(hue);
}

function hslToHex(hue: number, saturation: number, lightness: number): string {
  const s = saturation / 100;
  const l = lightness / 100;
  const c = (1 - Math.abs(2 * l - 1)) * s;
  const x = c * (1 - Math.abs(((hue / 60) % 2) - 1));
  const m = l - c / 2;
  let r = 0;
  let g = 0;
  let b = 0;
  if (hue < 60) {
    r = c;
    g = x;
  } else if (hue < 120) {
    r = x;
    g = c;
  } else if (hue < 180) {
    g = c;
    b = x;
  } else if (hue < 240) {
    g = x;
    b = c;
  } else if (hue < 300) {
    r = x;
    b = c;
  } else {
    r = c;
    b = x;
  }
  return `#${toHex(r + m)}${toHex(g + m)}${toHex(b + m)}`;
}

function toHex(value: number): string {
  return Math.round(value * 255).toString(16).padStart(2, "0");
}
