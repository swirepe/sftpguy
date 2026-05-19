import type { ComponentChildren } from "preact";
import { useState } from "preact/hooks";
import { useMutation, useQuery, useQueryClient } from "@tanstack/preact-query";
import {
  api,
  fetchBlobURL,
  postJSON,
  previewURL,
  rangeURL,
  type DownloadFileRow,
  type EventRow,
  type LivePayload,
  type PreviewPayload,
  type SummaryPayload,
  type UploadRow
} from "./api";

type View = "overview" | "activity";

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

type InspectorAction =
  | { type: "delete"; path: string }
  | { type: "rename"; path: string; newName: string }
  | { type: "mark-bad"; path: string }
  | { type: "ban-owner"; path: string };

const range = "24h";

export function App() {
  const [view, setView] = useState<View>("overview");
  const [selectedPath, setSelectedPath] = useState<string>("");

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
  const events = useQuery({
    queryKey: ["events", range],
    queryFn: () => api<EventsPayload>(rangeURL("/admin/api/events?limit=90", range)),
    refetchInterval: 20_000
  });
  const uploads = useQuery({
    queryKey: ["uploads", range],
    queryFn: () => api<UploadsPayload>(rangeURL("/admin/api/uploads/recent?limit=8", range)),
    refetchInterval: 20_000
  });
  const downloads = useQuery({
    queryKey: ["downloads", range],
    queryFn: () =>
      api<DownloadsPayload>(
        rangeURL("/admin/api/downloads?file_limit=8&recent_limit=8&downloader_limit=10", range)
      ),
    refetchInterval: 30_000
  });

  const eventRows = events.data?.events ?? [];
  const explorerEvents = eventRows.filter((row) => sourceFor(row) === "explorer");
  const liveCount = countLive(live.data);

  function openInspector(path: string | undefined) {
    const clean = cleanPath(path);
    if (clean) {
      setSelectedPath(clean);
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
          <div class="modebar">
            <div class="segmented" role="tablist" aria-label="Admin v2 views">
              <button
                class={view === "overview" ? "active" : ""}
                type="button"
                onClick={() => setView("overview")}
              >
                Overview
              </button>
              <button
                class={view === "activity" ? "active" : ""}
                type="button"
                onClick={() => setView("activity")}
              >
                Activity
              </button>
            </div>
            <span class="range-pill">Last 24h</span>
          </div>

          {view === "overview" ? (
            <Overview
              summary={summary.data}
              liveCount={liveCount}
              eventRows={eventRows}
              explorerEvents={explorerEvents}
              uploads={uploads.data?.uploads ?? []}
              downloads={downloads.data}
              loading={summary.isLoading || events.isLoading}
              onOpenPath={openInspector}
            />
          ) : (
            <Activity rows={eventRows} loading={events.isLoading} onOpenPath={openInspector} />
          )}
        </section>

        <Inspector path={selectedPath} onClose={() => setSelectedPath("")} />
      </main>
    </div>
  );
}

function Overview(props: {
  summary?: SummaryPayload;
  liveCount: number;
  eventRows: EventRow[];
  explorerEvents: EventRow[];
  uploads: UploadRow[];
  downloads?: DownloadsPayload;
  loading: boolean;
  onOpenPath: (path?: string) => void;
}) {
  const downloads = props.downloads?.files ?? [];
  const summary = props.summary;
  const totalEvents = props.eventRows.length;
  const explorerShare = totalEvents > 0 ? Math.round((props.explorerEvents.length / totalEvents) * 100) : 0;

  return (
    <div class="overview-grid">
      <section class="metric-strip" aria-label="Summary">
        <Metric label="Files" value={formatNumber(summary?.files)} />
        <Metric label="Storage" value={summary?.formatted_bytes || formatBytes(summary?.bytes)} />
        <Metric label="Users" value={formatNumber(summary?.users)} />
        <Metric label="Live" value={formatNumber(props.liveCount)} />
        <Metric label="Explorer" value={`${explorerShare}%`} />
      </section>

      <section class="insights-band">
        <div>
          <h2>Operational Pulse</h2>
          <p>{props.loading ? "Loading current activity..." : pulseCopy(props.eventRows, props.explorerEvents)}</p>
        </div>
        <div class="release">
          <span>Version</span>
          <strong>{summary?.version || "unknown"}</strong>
        </div>
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

      <section class="wide-panel">
        <div class="panel-heading">
          <h2>Explorer-Origin Activity</h2>
          <span>{props.explorerEvents.length} events</span>
        </div>
        <EventTable rows={props.explorerEvents.slice(0, 10)} onOpenPath={props.onOpenPath} />
      </section>
    </div>
  );
}

function Activity(props: { rows: EventRow[]; loading: boolean; onOpenPath: (path?: string) => void }) {
  return (
    <section class="wide-panel">
      <div class="panel-heading">
        <h2>Event Stream</h2>
        <span>{props.loading ? "Refreshing" : `${props.rows.length} rows`}</span>
      </div>
      <EventTable rows={props.rows} onOpenPath={props.onOpenPath} />
    </section>
  );
}

function EventTable(props: { rows: EventRow[]; onOpenPath: (path?: string) => void }) {
  if (props.rows.length === 0) {
    return <div class="empty">No events to show.</div>;
  }

  return (
    <div class="event-table" role="table">
      <div class="event-head" role="row">
        <span>Time</span>
        <span>Source</span>
        <span>Status</span>
        <span>Path</span>
        <span>User</span>
        <span>IP</span>
        <span>Session</span>
      </div>
      {props.rows.map((row) => {
        const rowPath = row.path || valueFromMeta(row, "path");
        return (
          <button
            class="event-row"
            type="button"
            role="row"
            key={row.id}
            onClick={() => props.onOpenPath(rowPath)}
            disabled={!cleanPath(rowPath)}
          >
            <span>{row.time || row.timestamp || ""}</span>
            <span>{sourceFor(row)}</span>
            <span>{statusFor(row)}</span>
            <span class="path-cell">{rowPath}</span>
            <span>{row.user_id || ""}</span>
            <span>{row.ip || ""}</span>
            <span class="truncate">{row.session || ""}</span>
          </button>
        );
      })}
    </div>
  );
}

function Inspector(props: { path: string; onClose: () => void }) {
  const queryClient = useQueryClient();
  const [notice, setNotice] = useState("");

  const preview = useQuery({
    queryKey: ["preview", props.path],
    queryFn: () => api<PreviewPayload>(previewURL(props.path)),
    enabled: props.path !== ""
  });

  const ownerDetails = useQuery({
    queryKey: ["owner-details", preview.data?.owner_details_url],
    queryFn: () => api<Record<string, unknown>>(preview.data?.owner_details_url || ""),
    enabled: Boolean(preview.data?.owner_details_url)
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
    <aside class={`inspector ${props.path ? "open" : ""}`} aria-live="polite">
      {!props.path ? (
        <div class="inspector-empty">
          <h2>Inspector</h2>
          <p>Select a path from activity, uploads, or downloads.</p>
        </div>
      ) : (
        <>
          <div class="inspector-head">
            <div>
              <span class="eyebrow">Inspector</span>
              <h2>{data?.name || props.path}</h2>
            </div>
            <button type="button" onClick={props.onClose} aria-label="Close inspector">
              Close
            </button>
          </div>

          {preview.isLoading ? <div class="empty">Loading preview...</div> : null}
          {preview.isError ? <div class="error">Preview unavailable.</div> : null}

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

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div class="metric">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
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

function pulseCopy(events: EventRow[], explorerEvents: EventRow[]): string {
  if (events.length === 0) {
    return "No events recorded in the current window.";
  }
  if (explorerEvents.length > 0) {
    return `${events.length} events, including ${explorerEvents.length} from explorer-origin traffic.`;
  }
  return `${events.length} events across SFTP and admin traffic.`;
}

function sourceFor(row: EventRow): string {
  const source = valueFromMeta(row, "source");
  if (source) {
    return source;
  }
  if ((row.event || "").startsWith("explorer_")) {
    return "explorer";
  }
  if ((row.user_id || "") === "system") {
    return "admin";
  }
  return "sftp";
}

function statusFor(row: EventRow): string {
  return valueFromMeta(row, "status") || valueFromMeta(row, "result") || row.event || "";
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
  if (typeof value !== "number") {
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
