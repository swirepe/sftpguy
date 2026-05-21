export type SummaryPayload = {
  archive?: string;
  version?: string;
  ssh_port?: number;
  admin_http?: string;
  uptime?: string;
  uptime_seconds?: number;
  users?: number;
  contributors?: number;
  files?: number;
  directories?: number;
  bytes?: number;
  formatted_bytes?: string;
  contributor_threshold?: number;
  storage?: StorageVolume[];
};

export type StorageVolume = {
  id?: string;
  kind?: string;
  label?: string;
  path?: string;
  stat_path?: string;
  device_id?: string;
  file_bytes?: number;
  file_size?: string;
  file_exists?: boolean;
  sidecars?: StorageFile[];
  total_bytes?: number;
  free_bytes?: number;
  used_bytes?: number;
  total?: string;
  free?: string;
  used?: string;
  used_percent?: number;
  free_percent?: number;
  error?: string;
};

export type StorageFile = {
  label?: string;
  path?: string;
  size_bytes?: number;
  size?: string;
  exists?: boolean;
  error?: string;
};

export type EventRow = {
  id: number;
  timestamp?: number;
  time?: string;
  event?: string;
  user_id?: string;
  ip?: string;
  geo?: GeoLocation;
  path?: string;
  meta?: string;
  meta_obj?: Record<string, unknown>;
  session?: string;
};

export type UploadRow = {
  id: number;
  time?: string;
  user_id?: string;
  ip?: string;
  geo?: GeoLocation;
  path?: string;
  size?: number;
  delta?: number;
  session?: string;
  meta?: string;
};

export type DownloadFileRow = {
  path: string;
  name?: string;
  owner?: string;
  size?: number;
  size_human?: string;
  downloads_total?: number;
  downloads_in_range?: number;
  unique_users_in_range?: number;
  unique_ips_in_range?: number;
  last_download_time?: string;
  last_downloader?: string;
  last_ip?: string;
};

export type LivePayload = {
  connections?: unknown[];
  sessions?: unknown[];
  transfers?: unknown[];
  requests?: unknown[];
};

export type GeoLocation = {
  ip?: string;
  database?: string;
  database_id?: string;
  city?: string;
  region?: string;
  region_code?: string;
  country?: string;
  country_code?: string;
  continent?: string;
  continent_code?: string;
  latitude?: number;
  longitude?: number;
  timezone?: string;
  postal_code?: string;
  accuracy_radius?: number;
  attribution?: string;
};

export type ArchiveEntry = {
  name: string;
  size?: string;
  is_dir?: boolean;
  category?: string;
};

export type PreviewPayload = {
  name: string;
  is_dir: boolean;
  rel_path?: string;
  owner?: string;
  owner_files_url?: string;
  owner_details_url?: string;
  downloads?: number;
  size?: string;
  mod_time?: string;
  ext?: string;
  child_dirs?: number;
  child_files?: number;
  total_size?: string;
  mime_type?: string;
  download_url?: string;
  is_image?: boolean;
  thumb_url?: string;
  image_width?: number;
  image_height?: number;
  image_mode?: string;
  is_video?: boolean;
  video_url?: string;
  video_native?: boolean;
  is_text?: boolean;
  text_lines?: string[];
  text_line_count?: number;
  text_word_count?: number;
  text_char_count?: number;
  text_line_ending?: string;
  is_archive?: boolean;
  archive_entries?: ArchiveEntry[];
  is_pdf?: boolean;
  pdf_page_count?: number;
  is_stl?: boolean;
  stl_triangles?: number;
  stl_title?: string;
};

const tokenKey = "sftpguy_admin_token";

export class APIError extends Error {
  status: number;
  payload: unknown;

  constructor(message: string, status: number, payload: unknown) {
    super(message);
    this.status = status;
    this.payload = payload;
  }
}

function adminToken(): string {
  return window.localStorage.getItem(tokenKey) || "";
}

function storeAdminToken(token: string) {
  window.localStorage.setItem(tokenKey, token);
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  const token = adminToken();
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  if (init.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const response = await fetch(path, { ...init, headers });
  if (response.status === 401) {
    const token = window.prompt("Admin token required");
    if (token) {
      storeAdminToken(token.trim());
      return api<T>(path, init);
    }
  }

  const raw = await response.text();
  let payload: unknown = {};
  if (raw) {
    try {
      payload = JSON.parse(raw);
    } catch {
      payload = raw;
    }
  }
  if (!response.ok) {
    throw new APIError(raw || `HTTP ${response.status}`, response.status, payload);
  }
  return payload as T;
}

export function previewURL(path: string): string {
  const params = new URLSearchParams();
  params.set("path", path);
  return `/admin/api/preview?${params.toString()}`;
}

export function rangeURL(path: string, range = "24h"): string {
  const sep = path.includes("?") ? "&" : "?";
  return `${path}${sep}range=${encodeURIComponent(range)}`;
}

export function postJSON<T>(path: string, body: unknown): Promise<T> {
  return api<T>(path, {
    method: "POST",
    body: JSON.stringify(body)
  });
}

export async function fetchBlobURL(path: string): Promise<string> {
  const headers = new Headers();
  const token = adminToken();
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  const response = await fetch(path, { headers });
  if (response.status === 401) {
    const token = window.prompt("Admin token required");
    if (token) {
      storeAdminToken(token.trim());
      return fetchBlobURL(path);
    }
  }
  if (!response.ok) {
    throw new APIError(`HTTP ${response.status}`, response.status, null);
  }
  return URL.createObjectURL(await response.blob());
}
