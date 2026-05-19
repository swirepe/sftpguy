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

type View = "overview" | "activity";
type SourceFilter = "all" | "sftp" | "admin" | "explorer";
type ActivityKind = "all" | "attention" | "denied" | "transfer" | "mutating" | "session" | "exec";
type InspectorTarget = { type: "none" } | { type: "path"; path: string } | { type: "event"; event: EventRow };

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

type InsightsPayload = {
  kpi?: Record<string, number>;
  top_events?: NamedCount[];
  top_users?: NamedPair[];
  top_ips?: NamedPair[];
  suspicious_ips?: NamedPair[];
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

type BannedPayload = {
  hashes?: Array<{ hash: string; banned_at?: string }>;
  ips?: Array<{ ip: string; banned_at?: string; comment?: string }>;
};

type InspectorAction =
  | { type: "delete"; path: string }
  | { type: "rename"; path: string; newName: string }
  | { type: "mark-bad"; path: string }
  | { type: "ban-owner"; path: string };

const defaultHue = 174;
const rangeOptions = ["15m", "1h", "6h", "24h", "48h", "7d", "30d", "all"];

export function App() {
  const queryClient = useQueryClient();
  const initialHueParam = hasHueParam();
  const [view, setView] = useState<View>("overview");
  const [inspectorTarget, setInspectorTarget] = useState<InspectorTarget>({ type: "none" });
  const [range, setRange] = useState(readURLParam("range") || "24h");
  const [query, setQuery] = useState(readURLParam("q"));
  const [sourceFilter, setSourceFilter] = useState<SourceFilter>("all");
  const [hue, setHue] = useState(parseHueParam());
  const [hueInURL, setHueInURL] = useState(initialHueParam);

  useEffect(() => {
    document.documentElement.style.setProperty("--hue", String(hue));
    if (hueInURL) {
      replaceURLParams({ hue: String(hue), range: range === "24h" ? "" : range, q: query });
    } else {
      replaceURLParams({ range: range === "24h" ? "" : range, q: query });
    }
  }, [hue, hueInURL, query, range]);

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
    queryFn: () => api<UsersPayload>(adminPath("/admin/api/users", { limit: 10, q: query })),
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

  function updateHueFromColor(hex: string) {
    setHue(hexToHue(hex));
    setHueInURL(true);
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
              onRunMaintenance={() => runMaintenance.mutate()}
              onBanIP={(ip) => banIP.mutate(ip)}
            />
          ) : (
            <Activity
              rows={filteredEventRows}
              loading={events.isLoading}
              sourceFilter={sourceFilter}
              onInspectEvent={inspectEvent}
            />
          )}
        </section>

        <Inspector
          target={inspectorTarget}
          banIPPending={banIP.isPending}
          onBanIP={(ip) => banIP.mutate(ip)}
          onInspectEvent={inspectEvent}
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
  return (
    <div class="toolbar">
      <div class="segmented" role="tablist" aria-label="Admin v2 views">
        <button class={props.view === "overview" ? "active" : ""} type="button" onClick={() => props.onView("overview")}>
          Overview
        </button>
        <button class={props.view === "activity" ? "active" : ""} type="button" onClick={() => props.onView("activity")}>
          Activity
        </button>
      </div>

      <div class="control-cluster">
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
        <button type="button" class="refresh-button" onClick={props.onRefresh}>
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

  return (
    <div class="overview-grid">
      <section class="metric-strip" aria-label="Summary">
        <Metric label="Files" value={formatNumber(summary?.files)} />
        <Metric label="Stored" value={summary?.formatted_bytes || formatBytes(summary?.bytes)} />
        <Metric label="Uptime" value={summary?.uptime || formatDuration(summary?.uptime_seconds)} />
        <Metric label="Dirs" value={formatNumber(summary?.directories)} />
        <Metric label="Users" value={formatNumber(summary?.users)} />
        <Metric label="Contrib" value={formatNumber(summary?.contributors)} />
        <Metric label="Events" value={formatNumber(kpi.events)} />
        <Metric label="Uploads" value={formatNumber(kpi.uploads)} />
        <Metric label="Downloads" value={formatNumber(kpi.downloads)} />
        <Metric label="Denied" value={formatNumber(kpi.denied)} tone={Number(kpi.denied || 0) > 0 ? "warn" : "normal"} />
        <Metric label="Live" value={formatNumber(props.liveCount)} />
        <Metric label="Explorer" value={`${explorerShare}%`} />
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
        <DataPanel title="Recent Uploads" empty="No uploads in this window">
          {props.uploads.map((row) => (
            <PathRow
              key={row.id}
              title={row.path || "(no path)"}
              detail={`${row.time || ""} ${row.user_id || ""}`}
              meta={formatBytes(row.size)}
              onClick={() => props.onOpenPath(row.path)}
            />
          ))}
        </DataPanel>

        <DataPanel title="Downloaded Files" empty="No download activity yet">
          {downloads.map((row) => (
            <PathRow
              key={row.path}
              title={row.path}
              detail={`${row.downloads_total ?? 0} total, ${row.downloads_in_range ?? 0} in range`}
              meta={row.size_human || ""}
              onClick={() => props.onOpenPath(row.path)}
            />
          ))}
        </DataPanel>
      </section>

      <section class="triple">
        <CountPanel title="Top Events" rows={props.insights?.top_events ?? []} />
        <CountPanel title="Top Users" rows={props.insights?.top_users ?? []} denied />
        <CountPanel title="Top IPs" rows={props.insights?.top_ips ?? []} denied />
      </section>

      <section class="split">
        <UsersPanel users={props.users} />
        <SessionsPanel sessions={props.sessions} onInspectSession={props.onInspectSession} />
      </section>

      <section class="split">
        <LivePanel live={props.live} />
        <RiskPanel
          insights={props.insights}
          bannedHashes={bannedHashes}
          bannedIPs={bannedIPs}
          maintenance={props.maintenance}
          maintenancePending={props.maintenancePending}
          banIPPending={props.banIPPending}
          onRunMaintenance={props.onRunMaintenance}
          onBanIP={props.onBanIP}
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
  onInspectEvent: (event: EventRow) => void;
}) {
  const [kind, setKind] = useState<ActivityKind>("all");
  const rows = useMemo(() => props.rows.filter((row) => matchesActivityKind(row, kind)), [props.rows, kind]);
  const profile = useMemo(() => activityProfile(props.rows), [props.rows]);

  return (
    <div class="activity-grid">
      <section class="metric-strip activity-metrics" aria-label="Activity summary">
        <Metric label="Rows" value={formatNumber(props.rows.length)} />
        <Metric label="Attention" value={formatNumber(profile.attention)} tone={profile.attention > 0 ? "warn" : "normal"} />
        <Metric label="Denied" value={formatNumber(profile.denied)} tone={profile.denied > 0 ? "warn" : "normal"} />
        <Metric label="Transfers" value={formatNumber(profile.transfer)} />
        <Metric label="Mutations" value={formatNumber(profile.mutating)} />
        <Metric label="Sessions" value={formatNumber(profile.session)} />
        <Metric label="Exec" value={formatNumber(profile.exec)} tone={profile.exec > 0 ? "warn" : "normal"} />
      </section>

      <section class="split">
        <ActivityBreakdownPanel profile={profile} />
        <ActorBreakdownPanel rows={props.rows} />
      </section>

      <section class="wide-panel">
        <div class="panel-heading">
          <h2>Event Stream</h2>
          <span>{props.loading ? "Refreshing" : `${rows.length} of ${props.rows.length} ${props.sourceFilter} rows`}</span>
        </div>
        <ActivityKindTabs value={kind} onChange={setKind} />
        <EventTable rows={rows} onInspectEvent={props.onInspectEvent} />
      </section>
    </div>
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

function ActorBreakdownPanel({ rows }: { rows: EventRow[] }) {
  const users = topCounts(rows, (row) => row.user_id || "anonymous", 5);
  const ips = topCounts(rows, (row) => row.ip || "unknown", 5);
  return (
    <DataPanel title="Actors" empty="No actor data">
      <div class="actor-columns">
        <div>
          <h3>Users</h3>
          <BarList rows={users} />
        </div>
        <div>
          <h3>IPs</h3>
          <BarList rows={ips} />
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
            class="event-row"
            type="button"
            role="row"
            key={row.id}
            onClick={() => props.onInspectEvent(row)}
          >
            <span>{row.time || row.timestamp || ""}</span>
            <span>
              <SourcePill source={sourceFor(row)} />
            </span>
            <span class="event-name">{row.event || ""}</span>
            <span>
              <span class={statusClass(row)}>{statusFor(row)}</span>
            </span>
            <span class="path-cell">{rowPath}</span>
            <span>{shortValue(row.user_id)}</span>
            <span>{row.ip || ""}</span>
            <span class="truncate">{row.session || ""}</span>
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

function BarList({ rows }: { rows: NamedCount[] }) {
  const max = Math.max(...rows.map((row) => row.count), 1);
  return (
    <div class="bar-list">
      {rows.map((row) => {
        const width = Math.max(2, Math.round((row.count / max) * 100));
        return (
          <div class="bar-row" key={row.name}>
            <span>{row.name}</span>
            <div class="bar-track">
              <i style={{ width: `${width}%` }} />
            </div>
            <strong>{formatNumber(row.count)}</strong>
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

function UsersPanel({ users }: { users: UserRow[] }) {
  return (
    <DataPanel title="Users" empty="No users match the current filter">
      {users.map((user) => (
        <div class="dense-row" key={user.hash}>
          <div>
            <strong>{shortValue(user.hash)}</strong>
            <small>{user.last_login || "no login time"}</small>
          </div>
          <span>{formatBytes(user.upload_bytes)} up</span>
          <span>{formatBytes(user.download_bytes)} down</span>
        </div>
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

function LivePanel({ live }: { live?: LivePayload }) {
  const connections = recordArray(live?.connections).slice(0, 6);
  const sessions = recordArray(live?.sessions).slice(0, 6);
  const requests = recordArray(live?.requests).slice(0, 6);
  return (
    <DataPanel title="Live" empty="No live activity">
      {connections.map((row, index) => (
        <LiveRow key={`conn-${index}`} label="Connection" row={row} />
      ))}
      {sessions.map((row, index) => (
        <LiveRow key={`session-${index}`} label="Session" row={row} />
      ))}
      {requests.map((row, index) => (
        <LiveRow key={`request-${index}`} label="Request" row={row} />
      ))}
    </DataPanel>
  );
}

function LiveRow({ label, row }: { label: string; row: Record<string, unknown> }) {
  return (
    <div class="dense-row">
      <div>
        <strong>{label}</strong>
        <small>{stringFromRecord(row, ["path", "operation", "session_id", "id"])}</small>
      </div>
      <span>{stringFromRecord(row, ["source", "protocol", "user_id"])}</span>
      <span>{stringFromRecord(row, ["remote_addr", "ip"])}</span>
    </div>
  );
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
          <div>
            <strong>{ip.name}</strong>
            <small>{ip.count} events, {ip.denied ?? 0} denied</small>
          </div>
          <button type="button" onClick={() => props.onBanIP(ip.name)} disabled={props.banIPPending}>
            Ban IP
          </button>
        </div>
      ))}
    </DataPanel>
  );
}

function CountPanel({ title, rows, denied }: { title: string; rows: NamedPair[]; denied?: boolean }) {
  const max = Math.max(...rows.slice(0, 10).map((row) => row.count), 1);
  return (
    <DataPanel title={title} empty="No rows">
      {rows.slice(0, 10).map((row) => (
        <div class="dense-row" key={row.name}>
          <div>
            <strong>{shortValue(row.name, 28)}</strong>
            {denied ? <small>{row.denied ?? 0} denied</small> : null}
            <div class="mini-track">
              <i style={{ width: `${Math.max(3, Math.round((row.count / max) * 100))}%` }} />
            </div>
          </div>
          <span>{formatNumber(row.count)}</span>
        </div>
      ))}
    </DataPanel>
  );
}

function Inspector(props: {
  target: InspectorTarget;
  banIPPending: boolean;
  onBanIP: (ip: string) => void;
  onInspectEvent: (event: EventRow) => void;
  onClose: () => void;
}) {
  const queryClient = useQueryClient();
  const [notice, setNotice] = useState("");
  const event = props.target.type === "event" ? props.target.event : undefined;
  const selectedPath = targetPath(props.target);
  const sessionID = eventSession(event);

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
    queryFn: () => api<SessionTimelinePayload>(adminPath(`/admin/api/sessions/${encodeURIComponent(sessionID)}`, { limit: 36 })),
    enabled: sessionID !== ""
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
              <h2>{event ? event.event || "Event" : data?.name || selectedPath}</h2>
            </div>
            <button type="button" onClick={props.onClose} aria-label="Close inspector">
              Close
            </button>
          </div>

          {event ? <EventSummary event={event} /> : null}
          {event ? <EventActions event={event} path={selectedPath} banIPPending={props.banIPPending} onBanIP={props.onBanIP} /> : null}

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
              {notice ? <p class="notice">{notice}</p> : null}
            </>
          ) : null}
        </>
      )}
    </aside>
  );
}

function EventSummary({ event }: { event: EventRow }) {
  const path = targetPath({ type: "event", event });
  const session = eventSession(event);
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
        <Meta label="User" value={event.user_id} />
        <Meta label="IP" value={event.ip} />
        <Meta label="Session" value={session} />
        <Meta label="Error" value={error} />
      </dl>
      {eventIsDelete(event) ? <div class="detail-box subtle">Delete events often point at a path that no longer exists; keep the metadata as the record of what happened.</div> : null}
      <EventMetaBlock event={event} />
    </div>
  );
}

function EventActions(props: { event: EventRow; path: string; banIPPending: boolean; onBanIP: (ip: string) => void }) {
  const session = eventSession(props.event);
  const ip = props.event.ip || metaString(props.event, ["ip", "ip_address", "remote_addr"]);
  if (!props.path && !ip && !session) {
    return null;
  }
  return (
    <div class="inspector-actions event-actions">
      {props.path ? (
        <a class="button-link" href={explorerURL(props.path)}>
          Open Explorer
        </a>
      ) : null}
      {session ? (
        <a class="button-link" href={adminPath("/admin/v2/", { q: session })}>
          Filter Session
        </a>
      ) : null}
      {ip ? (
        <button type="button" onClick={() => props.onBanIP(ip)} disabled={props.banIPPending}>
          Ban IP
        </button>
      ) : null}
    </div>
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
  const rows = session?.events ?? [];
  if (loading) {
    return <div class="detail-box subtle">Loading session timeline...</div>;
  }
  if (!session?.session) {
    return null;
  }
  return (
    <div class="session-box">
      <div class="panel-heading">
        <h3>Session Timeline</h3>
        <span>{rows.length} events</span>
      </div>
      <dl class="metadata compact-meta">
        <Meta label="Session" value={session.session} />
        <Meta label="User" value={session.user_id} />
        <Meta label="IP" value={session.ip} />
        <Meta label="Started" value={session.start_time} />
        <Meta label="Ended" value={session.end_time} />
      </dl>
      <div class="timeline-list">
        {rows.slice(0, 16).map((row) => (
          <button class="timeline-row" type="button" key={row.id} onClick={() => onInspectEvent({ ...row, session: session.session })}>
            <span>{row.time || ""}</span>
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

function Metric({ label, value, tone = "normal", compact = false }: { label: string; value: string; tone?: "normal" | "warn"; compact?: boolean }) {
  return (
    <div class={`metric ${tone === "warn" ? "warn" : ""} ${compact ? "compact" : ""}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function SourcePill({ source }: { source: string }) {
  return <span class={`source-pill ${source}`}>{source}</span>;
}

function DataPanel(props: { title: string; empty: string; children: ComponentChildren }) {
  const hasChildren = Array.isArray(props.children) ? props.children.length > 0 : Boolean(props.children);
  return (
    <section class="data-panel">
      <div class="panel-heading">
        <h2>{props.title}</h2>
      </div>
      {hasChildren ? props.children : <div class="empty">{props.empty}</div>}
    </section>
  );
}

function PathRow(props: { title: string; detail: string; meta: string; onClick: () => void }) {
  return (
    <button class="path-row" type="button" onClick={props.onClick}>
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

function targetPath(target: InspectorTarget): string {
  if (target.type === "path") {
    return cleanPath(target.path);
  }
  if (target.type === "event") {
    return cleanPath(target.event.path || metaString(target.event, ["path", "target_path", "old_path", "new_path", "file"]));
  }
  return "";
}

function eventSession(event?: EventRow): string {
  if (!event) {
    return "";
  }
  return event.session || metaString(event, ["session", "session_id", "user_session"]);
}

function eventCommand(event: EventRow): string {
  return metaString(event, ["command", "cmd", "exec", "argv", "args"]);
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

function countLive(payload?: LivePayload): number {
  const connections = Array.isArray(payload?.connections) ? payload.connections.length : 0;
  const sessions = Array.isArray(payload?.sessions) ? payload.sessions.length : 0;
  const requests = Array.isArray(payload?.requests) ? payload.requests.length : 0;
  return connections + sessions + requests;
}

function formatNumber(value: number | undefined): string {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return "0";
  }
  return new Intl.NumberFormat().format(value);
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
