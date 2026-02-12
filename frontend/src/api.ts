export type RequestStatus =
  | "pending"
  | "approved"
  | "provisioning"
  | "active"
  | "rejected"
  | "failed";

export interface UserSummary {
  id: string;
  peeringdb_user_id: number | null;
  username: string;
  full_name: string | null;
  email: string | null;
  is_admin: boolean;
  created_at: string;
  updated_at: string;
}

export interface UserAsn {
  id: string;
  asn: number;
  net_id: number | null;
  net_name: string | null;
  source: string;
  verified_at: string;
  created_at: string;
}

export interface ZtNetwork {
  id: string;
  name: string;
  description: string | null;
  is_active: boolean;
}

export interface Membership {
  id: string;
  join_request_id: string;
  zt_network_id: string;
  node_id: string;
  member_id: string;
  is_authorized: boolean;
  assigned_ips: string[];
  created_at: string;
  updated_at: string;
}

export interface Ipv6Assignment {
  id: string;
  join_request_id: string;
  zt_network_id: string;
  asn: number;
  sequence: number;
  assigned_ip: string;
  created_at: string;
  updated_at: string;
}

export interface JoinRequest {
  id: string;
  user_id: string;
  asn: number;
  zt_network_id: string;
  status: RequestStatus;
  node_id: string | null;
  notes: string | null;
  reject_reason: string | null;
  last_error: string | null;
  retry_count: number;
  requested_at: string;
  decided_at: string | null;
  provisioned_at: string | null;
  updated_at: string;
  assigned_ipv6: string | null;
  ipv6_assignment: Ipv6Assignment | null;
  membership: Membership | null;
}

export interface AuditEvent {
  id: string;
  actor_user_id: string | null;
  action: string;
  target_type: string;
  target_id: string;
  metadata: Record<string, unknown>;
  created_at: string;
}

export interface ApiErrorPayload {
  code: string;
  message: string;
  details: Record<string, unknown>;
}

export class ApiClientError extends Error {
  status: number;
  code: string;
  details: Record<string, unknown>;

  constructor(payload: ApiErrorPayload, status: number) {
    super(payload.message);
    this.name = "ApiClientError";
    this.status = status;
    this.code = payload.code;
    this.details = payload.details;
  }
}

interface SuccessEnvelope<T> {
  data: T;
}

interface ErrorEnvelope {
  error: {
    code?: string;
    message?: string;
    details?: Record<string, unknown>;
  };
}

interface ApiRequestOptions extends Omit<RequestInit, "body"> {
  jsonBody?: unknown;
}

const DEFAULT_ERROR_CODE = "request_failed";

async function apiRequest<T>(path: string, options: ApiRequestOptions = {}): Promise<T> {
  const headers = new Headers(options.headers);
  let requestBody: BodyInit | undefined;

  if (options.jsonBody !== undefined) {
    if (!headers.has("Content-Type")) {
      headers.set("Content-Type", "application/json");
    }
    requestBody = JSON.stringify(options.jsonBody);
  }

  let response: Response;
  try {
    response = await fetch(path, {
      ...options,
      headers,
      body: requestBody,
      credentials: "include",
    });
  } catch {
    throw new ApiClientError(
      {
        code: "network_error",
        message: "Unable to reach the API service.",
        details: {},
      },
      0,
    );
  }

  const rawText = await response.text();
  const parsed = rawText ? tryParseJson(rawText) : undefined;

  if (!response.ok) {
    const payload = toErrorPayload(parsed, response.status, response.statusText);
    throw new ApiClientError(payload, response.status);
  }

  const envelope = parsed as SuccessEnvelope<T> | undefined;
  if (!envelope || typeof envelope !== "object" || !("data" in envelope)) {
    throw new ApiClientError(
      {
        code: "invalid_response",
        message: "API response was missing a data envelope.",
        details: {},
      },
      response.status,
    );
  }

  return envelope.data;
}

function tryParseJson(raw: string): unknown {
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    return undefined;
  }
}

function toErrorPayload(parsed: unknown, status: number, statusText: string): ApiErrorPayload {
  if (parsed && typeof parsed === "object" && "error" in parsed) {
    const envelope = parsed as ErrorEnvelope;
    const code = envelope.error.code;
    const message = envelope.error.message;
    const details = envelope.error.details;

    return {
      code: typeof code === "string" && code ? code : DEFAULT_ERROR_CODE,
      message:
        typeof message === "string" && message
          ? message
          : statusText || "Request failed.",
      details: details && typeof details === "object" ? details : {},
    };
  }

  return {
    code: DEFAULT_ERROR_CODE,
    message: statusText || `Request failed with status ${status}`,
    details: {},
  };
}

export function isApiClientError(value: unknown): value is ApiClientError {
  return value instanceof ApiClientError;
}

export interface MeResponse {
  user: UserSummary;
  asns: UserAsn[];
}

export interface AuthStartResponse {
  authorization_url: string;
  state: string;
  expires_at: string;
  redirect_uri: string;
  scope: string;
}

export interface AuthResult {
  auth: {
    mode: "local" | "peeringdb";
    authorized_asn_count: number;
    has_eligible_asn: boolean;
  };
  user: {
    id: string;
    username: string;
    full_name: string | null;
    email: string | null;
    is_admin: boolean;
  };
}

export interface OnboardingContext {
  eligible_asns: UserAsn[];
  zt_networks: ZtNetwork[];
  constraints: {
    has_network_restrictions: boolean;
    restricted_network_ids: string[];
    submission_allowed: boolean;
    blocked_reason: string | null;
  };
}

export interface AdminRequestList {
  request_count: number;
  filters: {
    status: RequestStatus | null;
    asn: number | null;
    zt_network_id: string | null;
    min_age_minutes: number | null;
  };
  requests: JoinRequest[];
}

export interface AdminRequestDetail {
  request: JoinRequest;
  audit_events: AuditEvent[];
}

export interface CreateRequestPayload {
  asn: number;
  zt_network_id: string;
  node_id?: string;
  notes?: string;
}

export interface AdminRequestFilters {
  status?: RequestStatus;
  asn?: number;
  zt_network_id?: string;
  min_age_minutes?: number;
}

function adminRequestQuery(filters: AdminRequestFilters): string {
  const params = new URLSearchParams();
  if (filters.status) {
    params.set("status", filters.status);
  }
  if (typeof filters.asn === "number" && Number.isFinite(filters.asn)) {
    params.set("asn", String(filters.asn));
  }
  if (filters.zt_network_id) {
    params.set("zt_network_id", filters.zt_network_id);
  }
  if (
    typeof filters.min_age_minutes === "number" &&
    Number.isFinite(filters.min_age_minutes) &&
    filters.min_age_minutes >= 0
  ) {
    params.set("min_age_minutes", String(filters.min_age_minutes));
  }

  const query = params.toString();
  return query ? `?${query}` : "";
}

export const api = {
  startPeeringDbAuth(): Promise<AuthStartResponse> {
    return apiRequest<AuthStartResponse>("/api/v1/auth/peeringdb/start", { method: "POST" });
  },

  completePeeringDbAuth(payload: {
    code?: string;
    state?: string;
    error?: string;
  }): Promise<AuthResult> {
    return apiRequest<AuthResult>("/api/v1/auth/peeringdb/callback", {
      method: "POST",
      jsonBody: payload,
    });
  },

  loginLocal(payload: { username: string; password: string }): Promise<AuthResult> {
    return apiRequest<AuthResult>("/api/v1/auth/local/login", {
      method: "POST",
      jsonBody: payload,
    });
  },

  logout(): Promise<{ logged_out: boolean }> {
    return apiRequest<{ logged_out: boolean }>("/api/v1/auth/logout", { method: "POST" });
  },

  getMe(): Promise<MeResponse> {
    return apiRequest<MeResponse>("/api/v1/me", { method: "GET" });
  },

  getOnboardingContext(): Promise<OnboardingContext> {
    return apiRequest<OnboardingContext>("/api/v1/onboarding/context", { method: "GET" });
  },

  createRequest(payload: CreateRequestPayload): Promise<{ request: JoinRequest }> {
    return apiRequest<{ request: JoinRequest }>("/api/v1/requests", {
      method: "POST",
      jsonBody: payload,
    });
  },

  listRequests(): Promise<{ requests: JoinRequest[] }> {
    return apiRequest<{ requests: JoinRequest[] }>("/api/v1/requests", { method: "GET" });
  },

  getRequestDetail(requestId: string): Promise<{ request: JoinRequest }> {
    return apiRequest<{ request: JoinRequest }>(`/api/v1/requests/${requestId}`, {
      method: "GET",
    });
  },

  listAdminRequests(filters: AdminRequestFilters): Promise<AdminRequestList> {
    return apiRequest<AdminRequestList>(`/api/v1/admin/requests${adminRequestQuery(filters)}`, {
      method: "GET",
    });
  },

  getAdminRequestDetail(requestId: string): Promise<AdminRequestDetail> {
    return apiRequest<AdminRequestDetail>(`/api/v1/admin/requests/${requestId}`, { method: "GET" });
  },

  approveRequest(requestId: string): Promise<{ request: JoinRequest }> {
    return apiRequest<{ request: JoinRequest }>(`/api/v1/admin/requests/${requestId}/approve`, {
      method: "POST",
    });
  },

  rejectRequest(requestId: string, rejectReason: string): Promise<{ request: JoinRequest }> {
    return apiRequest<{ request: JoinRequest }>(`/api/v1/admin/requests/${requestId}/reject`, {
      method: "POST",
      jsonBody: { reject_reason: rejectReason },
    });
  },

  retryRequest(requestId: string): Promise<{ request: JoinRequest }> {
    return apiRequest<{ request: JoinRequest }>(`/api/v1/admin/requests/${requestId}/retry`, {
      method: "POST",
    });
  },
};
