import { type FormEvent, type ReactNode, useCallback, useEffect, useMemo, useRef, useState } from "react";

import {
  type AdminRequestDetail,
  type AdminRequestFilters,
  type JoinRequest,
  type OnboardingContext,
  type RequestStatus,
  type UserAsn,
  type UserSummary,
  ApiClientError,
  api,
  isApiClientError,
} from "./api";
import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "./components/ui/table";

const REQUEST_POLL_INTERVAL_MS = 10_000;
const ADMIN_POLL_INTERVAL_MS = 10_000;

type RouteKey =
  | "home"
  | "login"
  | "auth_callback"
  | "onboarding"
  | "dashboard"
  | "request_detail"
  | "admin_requests"
  | "admin_request_detail";

type SessionState =
  | { status: "loading" }
  | { status: "authenticated"; user: UserSummary; asns: UserAsn[] }
  | { status: "unauthenticated" }
  | { status: "error"; message: string };

interface RouteDefinition {
  key: RouteKey;
  template: string;
  pattern: RegExp;
  params?: string[];
  requiresAuth?: boolean;
  requiresAdmin?: boolean;
}

const ROUTE_DEFINITIONS: RouteDefinition[] = [
  { key: "home", template: "/", pattern: /^\/$/ },
  { key: "login", template: "/login", pattern: /^\/login\/?$/ },
  {
    key: "auth_callback",
    template: "/auth/callback",
    pattern: /^\/auth\/callback\/?$/,
  },
  {
    key: "onboarding",
    template: "/onboarding",
    pattern: /^\/onboarding\/?$/,
    requiresAuth: true,
  },
  {
    key: "dashboard",
    template: "/dashboard",
    pattern: /^\/dashboard\/?$/,
    requiresAuth: true,
  },
  {
    key: "request_detail",
    template: "/requests/:id",
    pattern: /^\/requests\/([^/]+)\/?$/,
    params: ["id"],
    requiresAuth: true,
  },
  {
    key: "admin_requests",
    template: "/admin/requests",
    pattern: /^\/admin\/requests\/?$/,
    requiresAuth: true,
    requiresAdmin: true,
  },
  {
    key: "admin_request_detail",
    template: "/admin/requests/:id",
    pattern: /^\/admin\/requests\/([^/]+)\/?$/,
    params: ["id"],
    requiresAuth: true,
    requiresAdmin: true,
  },
];

interface RouteMatch {
  route: RouteDefinition;
  params: Record<string, string>;
}

interface NavItem {
  label: string;
  path: string;
}

const STATUS_ORDER: RequestStatus[] = [
  "pending",
  "approved",
  "provisioning",
  "active",
  "rejected",
  "failed",
];

function normalizePath(pathname: string): string {
  if (!pathname) {
    return "/";
  }
  if (pathname.length > 1 && pathname.endsWith("/")) {
    return pathname.slice(0, -1);
  }
  return pathname;
}

function navigate(pathname: string): void {
  const nextPath = normalizePath(pathname);
  if (normalizePath(window.location.pathname) === nextPath) {
    return;
  }

  window.history.pushState(null, "", nextPath);
  window.dispatchEvent(new PopStateEvent("popstate"));
}

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function matchRoute(pathname: string): RouteMatch | undefined {
  const normalized = normalizePath(pathname);

  for (const route of ROUTE_DEFINITIONS) {
    const matched = normalized.match(route.pattern);
    if (!matched) {
      continue;
    }

    const params: Record<string, string> = {};
    if (route.params) {
      route.params.forEach((name, index) => {
        params[name] = safeDecode(matched[index + 1]);
      });
    }

    return { route, params };
  }

  return undefined;
}

function cx(...parts: Array<string | undefined | null | false>): string {
  return parts.filter(Boolean).join(" ");
}

function formatDateTime(value: string | null | undefined): string {
  if (!value) {
    return "Not available";
  }

  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }

  return parsed.toLocaleString();
}

function formatAssignedIpv6(value: string | null | undefined): string {
  return value ?? "unassigned";
}

function statusLabel(status: RequestStatus): string {
  return status.replace(/_/g, " ");
}

function statusClass(status: RequestStatus): string {
  switch (status) {
    case "active":
      return "status-badge status-active";
    case "approved":
      return "status-badge status-approved";
    case "provisioning":
      return "status-badge status-provisioning";
    case "rejected":
      return "status-badge status-rejected";
    case "failed":
      return "status-badge status-failed";
    case "pending":
    default:
      return "status-badge status-pending";
  }
}

function StatusBadge({ status }: { status: RequestStatus }) {
  return <span className={statusClass(status)}>{statusLabel(status)}</span>;
}

function asApiError(error: unknown): ApiClientError | undefined {
  return isApiClientError(error) ? error : undefined;
}

function errorMessage(error: unknown, fallback: string): string {
  const apiError = asApiError(error);
  if (apiError) {
    return `${apiError.message} (${apiError.code})`;
  }
  return fallback;
}

function readStringDetail(error: ApiClientError | undefined, key: string): string | undefined {
  if (!error) {
    return undefined;
  }
  const value = error.details[key];
  return typeof value === "string" ? value : undefined;
}

function AppLink({
  to,
  className,
  children,
  onNavigate,
}: {
  to: string;
  className?: string;
  children: ReactNode;
  onNavigate?: () => void;
}) {
  return (
    <a
      href={to}
      className={className}
      onClick={(event) => {
        if (
          event.defaultPrevented ||
          event.button !== 0 ||
          event.metaKey ||
          event.ctrlKey ||
          event.shiftKey ||
          event.altKey
        ) {
          return;
        }

        event.preventDefault();
        navigate(to);
        if (onNavigate) {
          onNavigate();
        }
      }}
    >
      {children}
    </a>
  );
}

function ScreenSection({
  caption,
  title,
  children,
  action,
}: {
  caption: string;
  title: string;
  children: ReactNode;
  action?: ReactNode;
}) {
  return (
    <section className="panel page-enter" aria-live="polite">
      <header className="section-header">
        <div>
          <p className="caption">{caption}</p>
          <h1>{title}</h1>
        </div>
        {action ? <div className="section-action">{action}</div> : null}
      </header>
      {children}
    </section>
  );
}

function InlineError({
  message,
  action,
}: {
  message: string;
  action?: ReactNode;
}) {
  return (
    <div className="inline-message inline-error" role="alert">
      <span>{message}</span>
      {action ? <div className="inline-action">{action}</div> : null}
    </div>
  );
}

function InlineInfo({
  message,
  action,
}: {
  message: string;
  action?: ReactNode;
}) {
  return (
    <div className="inline-message inline-info">
      <span>{message}</span>
      {action ? <div className="inline-action">{action}</div> : null}
    </div>
  );
}

function EmptyState({
  title,
  description,
  action,
}: {
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="state-box">
      <h2>{title}</h2>
      <p>{description}</p>
      {action ? <div className="state-box-action">{action}</div> : null}
    </div>
  );
}

function DefinitionGrid({ rows }: { rows: Array<{ label: string; value: ReactNode }> }) {
  return (
    <dl className="definition-grid">
      {rows.map((row) => (
        <div key={row.label}>
          <dt>{row.label}</dt>
          <dd>{row.value}</dd>
        </div>
      ))}
    </dl>
  );
}

function HomeScreen({
  session,
}: {
  session: SessionState;
}) {
  if (session.status === "loading") {
    return (
      <ScreenSection caption="Welcome" title="ZT-IX Console">
        <p>Loading session state.</p>
      </ScreenSection>
    );
  }

  if (session.status === "error") {
    return (
      <ScreenSection caption="Welcome" title="ZT-IX Console">
        <InlineError message={session.message} action={<button type="button" className="button secondary" onClick={() => window.location.reload()}>Retry</button>} />
      </ScreenSection>
    );
  }

  if (session.status === "unauthenticated") {
    return (
      <ScreenSection
        caption="Welcome"
        title="ZT-IX Console"
        action={<AppLink to="/login" className="button primary">Open Login</AppLink>}
      >
        <p>
          Use the login route to start PeeringDB OAuth or local credential authentication.
          This frontend keeps all auth failures inline and does not rely on backend error pages.
        </p>
      </ScreenSection>
    );
  }

  return (
    <ScreenSection caption="Welcome" title="Session Active">
      <p>
        Signed in as <strong>{session.user.username}</strong>. Continue onboarding or monitor request
        state from dashboard routes.
      </p>
      <DefinitionGrid
        rows={[
          { label: "User ID", value: <code className="mono">{session.user.id}</code> },
          { label: "Role", value: session.user.is_admin ? "Admin" : "Operator" },
          { label: "Linked ASNs", value: String(session.asns.length) },
        ]}
      />
      <div className="button-row">
        <AppLink to="/onboarding" className="button primary">
          Open Onboarding
        </AppLink>
        <AppLink to="/dashboard" className="button secondary">
          Open Dashboard
        </AppLink>
        {session.user.is_admin ? (
          <AppLink to="/admin/requests" className="button secondary">
            Open Admin Queue
          </AppLink>
        ) : null}
      </div>
    </ScreenSection>
  );
}

function LoginScreen({
  session,
  onSessionRefresh,
}: {
  session: SessionState;
  onSessionRefresh: () => Promise<void>;
}) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [localBusy, setLocalBusy] = useState(false);
  const [oauthBusy, setOauthBusy] = useState(false);
  const [errorText, setErrorText] = useState<string | null>(null);

  const handleLocalLogin = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setErrorText(null);
    setLocalBusy(true);

    try {
      await api.loginLocal({ username, password });
      await onSessionRefresh();
      navigate("/onboarding");
    } catch (error) {
      setErrorText(errorMessage(error, "Local login failed."));
    } finally {
      setLocalBusy(false);
    }
  };

  const handlePeeringDbStart = async () => {
    setErrorText(null);
    setOauthBusy(true);

    try {
      const response = await api.startPeeringDbAuth();
      window.location.assign(response.authorization_url);
    } catch (error) {
      setErrorText(errorMessage(error, "Unable to start PeeringDB OAuth."));
      setOauthBusy(false);
    }
  };

  if (session.status === "loading") {
    return (
      <ScreenSection caption="Auth" title="Login">
        <p>Checking existing session.</p>
      </ScreenSection>
    );
  }

  if (session.status === "authenticated") {
    return (
      <ScreenSection
        caption="Auth"
        title="Already Signed In"
        action={<AppLink to="/onboarding" className="button primary">Continue</AppLink>}
      >
        <InlineInfo
          message={`You are already logged in as ${session.user.username}.`}
          action={<AppLink to="/dashboard" className="button secondary">Go to dashboard</AppLink>}
        />
      </ScreenSection>
    );
  }

  return (
    <ScreenSection caption="Auth" title="Login">
      <p className="lead-text">
        Choose PeeringDB OAuth or local credentials. Authentication errors are shown inline on this
        route.
      </p>
      {errorText ? <InlineError message={errorText} /> : null}
      <div className="auth-grid">
        <div className="sub-panel">
          <h2>PeeringDB OAuth</h2>
          <p>Start browser redirect flow and return to <code className="mono">/auth/callback</code>.</p>
          <button
            type="button"
            className="button primary"
            onClick={handlePeeringDbStart}
            disabled={oauthBusy || localBusy}
          >
            {oauthBusy ? "Redirecting..." : "Continue with PeeringDB"}
          </button>
        </div>
        <div className="sub-panel">
          <h2>Local Credentials</h2>
          <form className="form-grid" onSubmit={handleLocalLogin}>
            <label>
              Username
              <input
                value={username}
                onChange={(event) => setUsername(event.currentTarget.value)}
                autoComplete="username"
                required
              />
            </label>
            <label>
              Password
              <input
                type="password"
                value={password}
                onChange={(event) => setPassword(event.currentTarget.value)}
                autoComplete="current-password"
                required
              />
            </label>
            <button type="submit" className="button secondary" disabled={localBusy || oauthBusy}>
              {localBusy ? "Signing in..." : "Sign in"}
            </button>
          </form>
        </div>
      </div>
    </ScreenSection>
  );
}

function AuthCallbackScreen({
  onSessionRefresh,
}: {
  onSessionRefresh: () => Promise<void>;
}) {
  const [phase, setPhase] = useState<"processing" | "success" | "error">("processing");
  const [message, setMessage] = useState("Processing PeeringDB callback.");
  const [detailCode, setDetailCode] = useState<string | null>(null);
  const startedRef = useRef(false);

  useEffect(() => {
    if (startedRef.current) {
      return;
    }
    startedRef.current = true;

    const run = async () => {
      const query = new URLSearchParams(window.location.search);
      const code = query.get("code") ?? undefined;
      const state = query.get("state") ?? undefined;
      const oauthError = query.get("error") ?? undefined;

      if (!code && !state && !oauthError) {
        setPhase("error");
        setMessage("Callback parameters are missing. Restart login from /login.");
        return;
      }

      try {
        await api.completePeeringDbAuth({
          code,
          state,
          error: oauthError,
        });
        await onSessionRefresh();
        setPhase("success");
        setMessage("Login successful. Redirecting to onboarding.");
        window.setTimeout(() => {
          navigate("/onboarding");
        }, 500);
      } catch (error) {
        const apiError = asApiError(error);
        setPhase("error");
        setMessage(errorMessage(error, "OAuth callback failed."));
        setDetailCode(readStringDetail(apiError, "detail_code") ?? null);
      }
    };

    void run();
  }, [onSessionRefresh]);

  return (
    <ScreenSection caption="Auth" title="OAuth Callback">
      {phase === "processing" ? <InlineInfo message={message} /> : null}
      {phase === "success" ? <InlineInfo message={message} /> : null}
      {phase === "error" ? (
        <InlineError
          message={message}
          action={
            <div className="button-row">
              <AppLink to="/login" className="button secondary">
                Back to Login
              </AppLink>
            </div>
          }
        />
      ) : null}
      {detailCode ? <p className="caption minor">Detail code: {detailCode}</p> : null}
    </ScreenSection>
  );
}

function OnboardingScreen({
  onUnauthorized,
}: {
  onUnauthorized: () => void;
}) {
  const [context, setContext] = useState<OnboardingContext | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [duplicateLink, setDuplicateLink] = useState<string | null>(null);
  const [submitBusy, setSubmitBusy] = useState(false);

  const [asnValue, setAsnValue] = useState("");
  const [networkValue, setNetworkValue] = useState("");
  const [nodeIdValue, setNodeIdValue] = useState("");
  const [notesValue, setNotesValue] = useState("");

  const loadContext = useCallback(async () => {
    setLoading(true);
    setLoadError(null);

    try {
      const response = await api.getOnboardingContext();
      setContext(response);
    } catch (error) {
      const apiError = asApiError(error);
      if (apiError && apiError.status === 401) {
        onUnauthorized();
        return;
      }
      setLoadError(errorMessage(error, "Unable to load onboarding context."));
    } finally {
      setLoading(false);
    }
  }, [onUnauthorized]);

  useEffect(() => {
    void loadContext();
  }, [loadContext]);

  useEffect(() => {
    if (!context) {
      return;
    }

    if (!asnValue && context.eligible_asns.length > 0) {
      setAsnValue(String(context.eligible_asns[0].asn));
    }

    if (!networkValue && context.zt_networks.length > 0) {
      setNetworkValue(context.zt_networks[0].id);
    }
  }, [context, asnValue, networkValue]);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setSubmitError(null);
    setDuplicateLink(null);
    setSubmitBusy(true);

    const asn = Number(asnValue);
    if (!Number.isFinite(asn) || asn <= 0) {
      setSubmitError("Enter a valid ASN.");
      setSubmitBusy(false);
      return;
    }

    try {
      const response = await api.createRequest({
        asn,
        zt_network_id: networkValue,
        node_id: nodeIdValue.trim() || undefined,
        notes: notesValue.trim() || undefined,
      });
      navigate(`/requests/${response.request.id}`);
    } catch (error) {
      const apiError = asApiError(error);
      if (apiError && apiError.status === 401) {
        onUnauthorized();
        return;
      }

      if (apiError && apiError.code === "duplicate_active_request") {
        setDuplicateLink(readStringDetail(apiError, "existing_request_url") ?? null);
      }
      setSubmitError(errorMessage(error, "Unable to create onboarding request."));
    } finally {
      setSubmitBusy(false);
    }
  };

  if (loading) {
    return (
      <ScreenSection caption="Onboarding" title="Create Join Request">
        <p>Loading eligible ASN and network data.</p>
      </ScreenSection>
    );
  }

  if (loadError) {
    return (
      <ScreenSection caption="Onboarding" title="Create Join Request">
        <InlineError
          message={loadError}
          action={<button type="button" className="button secondary" onClick={() => void loadContext()}>Retry</button>}
        />
      </ScreenSection>
    );
  }

  if (!context) {
    return (
      <ScreenSection caption="Onboarding" title="Create Join Request">
        <EmptyState
          title="No context loaded"
          description="Onboarding context is unavailable. Retry loading this route."
          action={<button type="button" className="button secondary" onClick={() => void loadContext()}>Reload</button>}
        />
      </ScreenSection>
    );
  }

  if (!context.constraints.submission_allowed || context.eligible_asns.length === 0) {
    return (
      <ScreenSection caption="Onboarding" title="Create Join Request">
        <EmptyState
          title="No eligible ASN available"
          description="Your account does not currently have an eligible ASN assignment. Contact support to update account mappings."
          action={<AppLink to="/dashboard" className="button secondary">Open Dashboard</AppLink>}
        />
      </ScreenSection>
    );
  }

  return (
    <ScreenSection caption="Onboarding" title="Create Join Request">
      <p className="lead-text">
        Submit ASN and target network details. Duplicate active requests return inline conflict details.
      </p>
      {submitError ? (
        <InlineError
          message={submitError}
          action={
            duplicateLink ? (
              <AppLink to={duplicateLink} className="button secondary">
                Open existing request
              </AppLink>
            ) : undefined
          }
        />
      ) : null}
      <form className="form-grid onboarding-form" onSubmit={handleSubmit}>
        <label>
          ASN
          <select value={asnValue} onChange={(event) => setAsnValue(event.currentTarget.value)}>
            {context.eligible_asns.map((item) => (
              <option key={item.id} value={item.asn}>
                AS{item.asn}
                {item.net_name ? ` - ${item.net_name}` : ""}
              </option>
            ))}
          </select>
        </label>
        <label>
          Target ZeroTier network
          <select
            value={networkValue}
            onChange={(event) => setNetworkValue(event.currentTarget.value)}
          >
            {context.zt_networks.map((network) => (
              <option key={network.id} value={network.id}>
                {network.name} ({network.id})
              </option>
            ))}
          </select>
        </label>
        <label>
          Node ID (optional)
          <input
            value={nodeIdValue}
            onChange={(event) => setNodeIdValue(event.currentTarget.value)}
            maxLength={10}
            placeholder="abcde12345"
          />
        </label>
        <label>
          Notes (optional)
          <textarea
            value={notesValue}
            onChange={(event) => setNotesValue(event.currentTarget.value)}
            rows={4}
            placeholder="Operational notes for reviewers"
          />
        </label>
        <div className="button-row">
          <button type="submit" className="button primary" disabled={submitBusy}>
            {submitBusy ? "Submitting..." : "Submit Request"}
          </button>
          <AppLink to="/dashboard" className="button secondary">
            Go to Dashboard
          </AppLink>
        </div>
      </form>
      {context.constraints.has_network_restrictions ? (
        <p className="caption minor">
          Network restrictions enabled: {context.constraints.restricted_network_ids.join(", ")}
        </p>
      ) : null}
    </ScreenSection>
  );
}

function DashboardScreen({
  onUnauthorized,
}: {
  onUnauthorized: () => void;
}) {
  const [requests, setRequests] = useState<JoinRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);

  const loadRequests = useCallback(
    async (silent: boolean) => {
      if (!silent) {
        setLoading(true);
        setLoadError(null);
      }

      try {
        const response = await api.listRequests();
        setRequests(response.requests);
        setLastUpdated(new Date().toISOString());
      } catch (error) {
        const apiError = asApiError(error);
        if (apiError && apiError.status === 401) {
          onUnauthorized();
          return;
        }
        if (!silent) {
          setLoadError(errorMessage(error, "Unable to load request list."));
        }
      } finally {
        if (!silent) {
          setLoading(false);
        }
      }
    },
    [onUnauthorized],
  );

  useEffect(() => {
    void loadRequests(false);
    const timerId = window.setInterval(() => {
      void loadRequests(true);
    }, REQUEST_POLL_INTERVAL_MS);

    return () => {
      window.clearInterval(timerId);
    };
  }, [loadRequests]);

  const counts = useMemo(() => {
    const next: Record<RequestStatus, number> = {
      pending: 0,
      approved: 0,
      provisioning: 0,
      active: 0,
      rejected: 0,
      failed: 0,
    };

    requests.forEach((request) => {
      next[request.status] += 1;
    });

    return next;
  }, [requests]);

  const sortedRequests = useMemo(
    () => [...requests].sort((a, b) => b.requested_at.localeCompare(a.requested_at)),
    [requests],
  );

  if (loading) {
    return (
      <ScreenSection caption="Operator" title="Dashboard">
        <p>Loading operator requests.</p>
      </ScreenSection>
    );
  }

  if (loadError) {
    return (
      <ScreenSection caption="Operator" title="Dashboard">
        <InlineError
          message={loadError}
          action={<button type="button" className="button secondary" onClick={() => void loadRequests(false)}>Retry</button>}
        />
      </ScreenSection>
    );
  }

  return (
    <ScreenSection
      caption="Operator"
      title="Dashboard"
      action={
        <button type="button" className="button secondary" onClick={() => void loadRequests(false)}>
          Refresh
        </button>
      }
    >
      <p className="caption minor">
        Polling every {REQUEST_POLL_INTERVAL_MS / 1000}s. Last refresh: {formatDateTime(lastUpdated)}
      </p>

      <div className="stat-grid">
        {STATUS_ORDER.map((status) => (
          <div key={status} className="stat-card">
            <span className="caption minor">{statusLabel(status)}</span>
            <strong>{counts[status]}</strong>
          </div>
        ))}
      </div>

      {sortedRequests.length === 0 ? (
        <EmptyState
          title="No requests yet"
          description="Create your first onboarding request to begin provisioning."
          action={<AppLink to="/onboarding" className="button primary">Start onboarding</AppLink>}
        />
      ) : (
        <Table>
          <TableCaption>Operator request list</TableCaption>
          <TableHeader>
            <TableRow>
              <TableHead>Request</TableHead>
              <TableHead>ASN</TableHead>
              <TableHead>Network</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Assigned IPv6</TableHead>
              <TableHead>Updated</TableHead>
              <TableHead>Action</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {sortedRequests.map((request, index) => (
              <TableRow key={request.id} className={`stagger-row-${Math.min(index + 1, 8)}`}>
                <TableCell>
                  <code className="mono">{request.id}</code>
                </TableCell>
                <TableCell>
                  <code className="mono">AS{request.asn}</code>
                </TableCell>
                <TableCell>
                  <code className="mono">{request.zt_network_id}</code>
                </TableCell>
                <TableCell>
                  <StatusBadge status={request.status} />
                </TableCell>
                <TableCell>
                  <code className="mono">{formatAssignedIpv6(request.assigned_ipv6)}</code>
                </TableCell>
                <TableCell>{formatDateTime(request.updated_at)}</TableCell>
                <TableCell>
                  <AppLink to={`/requests/${request.id}`} className="text-link">
                    View details
                  </AppLink>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </ScreenSection>
  );
}

function RequestDetailScreen({
  requestId,
  onUnauthorized,
}: {
  requestId: string;
  onUnauthorized: () => void;
}) {
  const [request, setRequest] = useState<JoinRequest | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);

  const loadRequest = useCallback(
    async (silent: boolean) => {
      if (!silent) {
        setLoading(true);
        setLoadError(null);
      }

      try {
        const response = await api.getRequestDetail(requestId);
        setRequest(response.request);
        setLastUpdated(new Date().toISOString());
      } catch (error) {
        const apiError = asApiError(error);
        if (apiError && apiError.status === 401) {
          onUnauthorized();
          return;
        }
        if (!silent) {
          setLoadError(errorMessage(error, "Unable to load request detail."));
        }
      } finally {
        if (!silent) {
          setLoading(false);
        }
      }
    },
    [onUnauthorized, requestId],
  );

  useEffect(() => {
    void loadRequest(false);
    const timerId = window.setInterval(() => {
      void loadRequest(true);
    }, REQUEST_POLL_INTERVAL_MS);

    return () => {
      window.clearInterval(timerId);
    };
  }, [loadRequest]);

  if (loading) {
    return (
      <ScreenSection caption="Operator" title="Request Detail">
        <p>Loading request data.</p>
      </ScreenSection>
    );
  }

  if (loadError) {
    return (
      <ScreenSection caption="Operator" title="Request Detail">
        <InlineError
          message={loadError}
          action={<button type="button" className="button secondary" onClick={() => void loadRequest(false)}>Retry</button>}
        />
      </ScreenSection>
    );
  }

  if (!request) {
    return (
      <ScreenSection caption="Operator" title="Request Detail">
        <EmptyState
          title="Request not found"
          description="This request is unavailable or not visible to your account."
          action={<AppLink to="/dashboard" className="button secondary">Back to dashboard</AppLink>}
        />
      </ScreenSection>
    );
  }

  return (
    <ScreenSection
      caption="Operator"
      title="Request Detail"
      action={<StatusBadge status={request.status} />}
    >
      <p className="caption minor">
        Request ID <code className="mono">{request.id}</code> | Last refresh {formatDateTime(lastUpdated)}
      </p>
      {request.status === "failed" && request.last_error ? (
        <InlineError message={`Provisioning failed: ${request.last_error}`} />
      ) : null}
      {request.status === "rejected" && request.reject_reason ? (
        <InlineError message={`Rejected: ${request.reject_reason}`} />
      ) : null}

      <DefinitionGrid
        rows={[
          { label: "ASN", value: <code className="mono">AS{request.asn}</code> },
          { label: "ZeroTier Network", value: <code className="mono">{request.zt_network_id}</code> },
          { label: "Node ID", value: request.node_id ? <code className="mono">{request.node_id}</code> : "Not set" },
          { label: "Requested", value: formatDateTime(request.requested_at) },
          { label: "Updated", value: formatDateTime(request.updated_at) },
          { label: "Retries", value: String(request.retry_count) },
        ]}
      />

      <h2>Membership</h2>
      {request.membership ? (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Member ID</TableHead>
              <TableHead>Node</TableHead>
              <TableHead>Authorized</TableHead>
              <TableHead>Assigned IPs</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            <TableRow>
              <TableCell>
                <code className="mono">{request.membership.member_id}</code>
              </TableCell>
              <TableCell>
                <code className="mono">{request.membership.node_id}</code>
              </TableCell>
              <TableCell>{request.membership.is_authorized ? "Yes" : "No"}</TableCell>
              <TableCell>
                {request.membership.assigned_ips.length > 0
                  ? request.membership.assigned_ips.join(", ")
                  : "Not assigned"}
              </TableCell>
            </TableRow>
          </TableBody>
        </Table>
      ) : (
        <EmptyState
          title="No membership record yet"
          description="Membership details appear after provisioning succeeds."
        />
      )}

      <div className="button-row">
        <AppLink to="/dashboard" className="button secondary">
          Back to dashboard
        </AppLink>
      </div>
    </ScreenSection>
  );
}

function AdminRequestsScreen({
  onUnauthorized,
}: {
  onUnauthorized: () => void;
}) {
  const [statusFilter, setStatusFilter] = useState<RequestStatus | "">("");
  const [asnFilter, setAsnFilter] = useState("");
  const [networkFilter, setNetworkFilter] = useState("");
  const [minAgeFilter, setMinAgeFilter] = useState("");

  const [appliedFilters, setAppliedFilters] = useState<AdminRequestFilters>({});
  const [requests, setRequests] = useState<JoinRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);

  const loadRequests = useCallback(
    async (silent: boolean, filters: AdminRequestFilters) => {
      if (!silent) {
        setLoading(true);
        setLoadError(null);
      }

      try {
        const response = await api.listAdminRequests(filters);
        setRequests(response.requests);
        setLastUpdated(new Date().toISOString());
      } catch (error) {
        const apiError = asApiError(error);
        if (apiError && (apiError.status === 401 || apiError.status === 403)) {
          onUnauthorized();
          return;
        }
        if (!silent) {
          setLoadError(errorMessage(error, "Unable to load admin queue."));
        }
      } finally {
        if (!silent) {
          setLoading(false);
        }
      }
    },
    [onUnauthorized],
  );

  useEffect(() => {
    void loadRequests(false, appliedFilters);
    const timerId = window.setInterval(() => {
      void loadRequests(true, appliedFilters);
    }, ADMIN_POLL_INTERVAL_MS);

    return () => {
      window.clearInterval(timerId);
    };
  }, [appliedFilters, loadRequests]);

  const applyFilters = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const nextFilters: AdminRequestFilters = {};
    if (statusFilter) {
      nextFilters.status = statusFilter;
    }

    const asn = Number(asnFilter);
    if (asnFilter.trim() && Number.isFinite(asn) && asn > 0) {
      nextFilters.asn = asn;
    }

    if (networkFilter.trim()) {
      nextFilters.zt_network_id = networkFilter.trim();
    }

    const minAge = Number(minAgeFilter);
    if (minAgeFilter.trim() && Number.isFinite(minAge) && minAge >= 0) {
      nextFilters.min_age_minutes = minAge;
    }

    setAppliedFilters(nextFilters);
  };

  const clearFilters = () => {
    setStatusFilter("");
    setAsnFilter("");
    setNetworkFilter("");
    setMinAgeFilter("");
    setAppliedFilters({});
  };

  if (loading) {
    return (
      <ScreenSection caption="Admin" title="Request Queue">
        <p>Loading admin queue.</p>
      </ScreenSection>
    );
  }

  if (loadError) {
    return (
      <ScreenSection caption="Admin" title="Request Queue">
        <InlineError
          message={loadError}
          action={<button type="button" className="button secondary" onClick={() => void loadRequests(false, appliedFilters)}>Retry</button>}
        />
      </ScreenSection>
    );
  }

  return (
    <ScreenSection
      caption="Admin"
      title="Request Queue"
      action={
        <button
          type="button"
          className="button secondary"
          onClick={() => void loadRequests(false, appliedFilters)}
        >
          Refresh
        </button>
      }
    >
      <form className="filter-grid" onSubmit={applyFilters}>
        <label>
          Status
          <select
            value={statusFilter}
            onChange={(event) => setStatusFilter(event.currentTarget.value as RequestStatus | "")}
          >
            <option value="">All</option>
            {STATUS_ORDER.map((status) => (
              <option key={status} value={status}>
                {statusLabel(status)}
              </option>
            ))}
          </select>
        </label>
        <label>
          ASN
          <input
            value={asnFilter}
            onChange={(event) => setAsnFilter(event.currentTarget.value)}
            placeholder="64512"
          />
        </label>
        <label>
          ZeroTier Network
          <input
            value={networkFilter}
            onChange={(event) => setNetworkFilter(event.currentTarget.value)}
            placeholder="abcdef0123456789"
          />
        </label>
        <label>
          Minimum age (minutes)
          <input
            value={minAgeFilter}
            onChange={(event) => setMinAgeFilter(event.currentTarget.value)}
            placeholder="30"
          />
        </label>
        <div className="button-row">
          <button type="submit" className="button primary">
            Apply filters
          </button>
          <button type="button" className="button secondary" onClick={clearFilters}>
            Clear
          </button>
        </div>
      </form>

      <p className="caption minor">
        Polling every {ADMIN_POLL_INTERVAL_MS / 1000}s. Last refresh: {formatDateTime(lastUpdated)}
      </p>

      {requests.length === 0 ? (
        <EmptyState
          title="No requests found"
          description="No requests match the current filter criteria."
          action={<button type="button" className="button secondary" onClick={clearFilters}>Reset filters</button>}
        />
      ) : (
        <Table>
          <TableCaption>Admin request queue</TableCaption>
          <TableHeader>
            <TableRow>
              <TableHead>Request</TableHead>
              <TableHead>ASN</TableHead>
              <TableHead>Network</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>User</TableHead>
              <TableHead>Assigned IPv6</TableHead>
              <TableHead>Updated</TableHead>
              <TableHead>Action</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {requests.map((request, index) => (
              <TableRow key={request.id} className={`stagger-row-${Math.min(index + 1, 8)}`}>
                <TableCell>
                  <code className="mono">{request.id}</code>
                </TableCell>
                <TableCell>
                  <code className="mono">AS{request.asn}</code>
                </TableCell>
                <TableCell>
                  <code className="mono">{request.zt_network_id}</code>
                </TableCell>
                <TableCell>
                  <StatusBadge status={request.status} />
                </TableCell>
                <TableCell>
                  <code className="mono">{request.user_id}</code>
                </TableCell>
                <TableCell>
                  <code className="mono">{formatAssignedIpv6(request.assigned_ipv6)}</code>
                </TableCell>
                <TableCell>{formatDateTime(request.updated_at)}</TableCell>
                <TableCell>
                  <AppLink to={`/admin/requests/${request.id}`} className="text-link">
                    Review
                  </AppLink>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </ScreenSection>
  );
}

function AdminRequestDetailScreen({
  requestId,
  onUnauthorized,
}: {
  requestId: string;
  onUnauthorized: () => void;
}) {
  const [detail, setDetail] = useState<AdminRequestDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionInfo, setActionInfo] = useState<string | null>(null);
  const [actionBusy, setActionBusy] = useState(false);
  const [rejectReason, setRejectReason] = useState("");

  const loadDetail = useCallback(
    async (silent: boolean) => {
      if (!silent) {
        setLoading(true);
        setLoadError(null);
      }

      try {
        const response = await api.getAdminRequestDetail(requestId);
        setDetail(response);
      } catch (error) {
        const apiError = asApiError(error);
        if (apiError && (apiError.status === 401 || apiError.status === 403)) {
          onUnauthorized();
          return;
        }
        if (!silent) {
          setLoadError(errorMessage(error, "Unable to load admin request detail."));
        }
      } finally {
        if (!silent) {
          setLoading(false);
        }
      }
    },
    [onUnauthorized, requestId],
  );

  useEffect(() => {
    void loadDetail(false);
    const timerId = window.setInterval(() => {
      void loadDetail(true);
    }, ADMIN_POLL_INTERVAL_MS);

    return () => {
      window.clearInterval(timerId);
    };
  }, [loadDetail]);

  const performAction = useCallback(
    async (action: "approve" | "reject" | "retry") => {
      if (!detail) {
        return;
      }

      if (action === "reject" && !rejectReason.trim()) {
        setActionError("Reject reason is required.");
        return;
      }

      setActionBusy(true);
      setActionError(null);
      setActionInfo(null);

      try {
        if (action === "approve") {
          await api.approveRequest(detail.request.id);
          setActionInfo("Request approved and queued for provisioning.");
        } else if (action === "retry") {
          await api.retryRequest(detail.request.id);
          setActionInfo("Retry queued from failed state.");
        } else {
          await api.rejectRequest(detail.request.id, rejectReason.trim());
          setActionInfo("Request rejected.");
          setRejectReason("");
        }

        await loadDetail(true);
      } catch (error) {
        setActionError(errorMessage(error, "Admin action failed."));
      } finally {
        setActionBusy(false);
      }
    },
    [detail, loadDetail, rejectReason],
  );

  if (loading) {
    return (
      <ScreenSection caption="Admin" title="Request Review">
        <p>Loading request detail.</p>
      </ScreenSection>
    );
  }

  if (loadError) {
    return (
      <ScreenSection caption="Admin" title="Request Review">
        <InlineError
          message={loadError}
          action={<button type="button" className="button secondary" onClick={() => void loadDetail(false)}>Retry</button>}
        />
      </ScreenSection>
    );
  }

  if (!detail) {
    return (
      <ScreenSection caption="Admin" title="Request Review">
        <EmptyState
          title="Request unavailable"
          description="This request was not found."
          action={<AppLink to="/admin/requests" className="button secondary">Back to admin queue</AppLink>}
        />
      </ScreenSection>
    );
  }

  const request = detail.request;
  const canApprove = request.status === "pending";
  const canReject = request.status === "pending";
  const canRetry = request.status === "failed";

  return (
    <ScreenSection
      caption="Admin"
      title="Request Review"
      action={<StatusBadge status={request.status} />}
    >
      <p className="caption minor">
        Reviewing <code className="mono">{request.id}</code>
      </p>
      {actionError ? <InlineError message={actionError} /> : null}
      {actionInfo ? <InlineInfo message={actionInfo} /> : null}

      <DefinitionGrid
        rows={[
          { label: "ASN", value: <code className="mono">AS{request.asn}</code> },
          { label: "ZeroTier Network", value: <code className="mono">{request.zt_network_id}</code> },
          { label: "Submitted", value: formatDateTime(request.requested_at) },
          { label: "Last Updated", value: formatDateTime(request.updated_at) },
          { label: "Retry Count", value: String(request.retry_count) },
          {
            label: "Last Error",
            value: request.last_error ? request.last_error : "No error recorded",
          },
        ]}
      />

      <div className="action-panel">
        <h2>Actions</h2>
        <div className="button-row">
          <button
            type="button"
            className="button primary"
            disabled={actionBusy || !canApprove}
            onClick={() => void performAction("approve")}
          >
            Approve
          </button>
          <button
            type="button"
            className="button secondary"
            disabled={actionBusy || !canRetry}
            onClick={() => void performAction("retry")}
          >
            Retry
          </button>
        </div>
        <label>
          Reject reason
          <textarea
            value={rejectReason}
            onChange={(event) => setRejectReason(event.currentTarget.value)}
            rows={3}
            placeholder="Policy mismatch, incomplete data, etc."
            disabled={actionBusy || !canReject}
          />
        </label>
        <button
          type="button"
          className="button secondary"
          disabled={actionBusy || !canReject}
          onClick={() => void performAction("reject")}
        >
          Reject
        </button>
      </div>

      <h2>Audit Events</h2>
      {detail.audit_events.length === 0 ? (
        <EmptyState
          title="No audit events"
          description="Audit timeline is currently empty for this request."
        />
      ) : (
        <Table>
          <TableCaption>Request audit events</TableCaption>
          <TableHeader>
            <TableRow>
              <TableHead>Time</TableHead>
              <TableHead>Action</TableHead>
              <TableHead>Actor</TableHead>
              <TableHead>Metadata</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {detail.audit_events.map((event, index) => (
              <TableRow key={event.id} className={`stagger-row-${Math.min(index + 1, 8)}`}>
                <TableCell>{formatDateTime(event.created_at)}</TableCell>
                <TableCell>{event.action}</TableCell>
                <TableCell>
                  {event.actor_user_id ? <code className="mono">{event.actor_user_id}</code> : "system"}
                </TableCell>
                <TableCell>
                  <code className="mono metadata">{JSON.stringify(event.metadata)}</code>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}

      <div className="button-row">
        <AppLink to="/admin/requests" className="button secondary">
          Back to admin queue
        </AppLink>
      </div>
    </ScreenSection>
  );
}

function NotFoundScreen() {
  return (
    <ScreenSection caption="Routing" title="Path Not Found">
      <EmptyState
        title="Unknown route"
        description="This path is outside the current SPA route set."
        action={<AppLink to="/" className="button secondary">Back home</AppLink>}
      />
    </ScreenSection>
  );
}

function ForbiddenScreen() {
  return (
    <ScreenSection caption="Access" title="Admin Access Required">
      <InlineError
        message="Your current session does not have admin privileges for /admin routes."
        action={<AppLink to="/dashboard" className="button secondary">Open dashboard</AppLink>}
      />
    </ScreenSection>
  );
}

function SessionErrorScreen({
  message,
  onRetry,
}: {
  message: string;
  onRetry: () => Promise<void>;
}) {
  return (
    <ScreenSection caption="Session" title="Unable to Validate Session">
      <InlineError
        message={message}
        action={
          <button type="button" className="button secondary" onClick={() => void onRetry()}>
            Retry session check
          </button>
        }
      />
    </ScreenSection>
  );
}

export function App() {
  const [pathname, setPathname] = useState(() => normalizePath(window.location.pathname));
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [session, setSession] = useState<SessionState>({ status: "loading" });
  const [logoutBusy, setLogoutBusy] = useState(false);

  const matchedRoute = useMemo(() => matchRoute(pathname), [pathname]);

  useEffect(() => {
    const onLocationChange = () => {
      setPathname(normalizePath(window.location.pathname));
      setMobileNavOpen(false);
    };

    window.addEventListener("popstate", onLocationChange);
    return () => {
      window.removeEventListener("popstate", onLocationChange);
    };
  }, []);

  const refreshSession = useCallback(async () => {
    try {
      const response = await api.getMe();
      setSession({
        status: "authenticated",
        user: response.user,
        asns: response.asns,
      });
    } catch (error) {
      const apiError = asApiError(error);
      if (apiError && apiError.status === 401) {
        setSession({ status: "unauthenticated" });
        return;
      }
      setSession({ status: "error", message: errorMessage(error, "Session check failed.") });
    }
  }, []);

  useEffect(() => {
    void refreshSession();
  }, [refreshSession]);

  useEffect(() => {
    if (!matchedRoute?.route.requiresAuth) {
      return;
    }

    if (session.status === "unauthenticated") {
      navigate("/login");
    }
  }, [matchedRoute, session.status]);

  const handleUnauthorized = useCallback(() => {
    setSession({ status: "unauthenticated" });
    if (normalizePath(window.location.pathname) !== "/login") {
      navigate("/login");
    }
  }, []);

  const handleLogout = async () => {
    setLogoutBusy(true);
    try {
      await api.logout();
    } catch {
      // Ignore and refresh session state from API.
    } finally {
      setLogoutBusy(false);
      await refreshSession();
      navigate("/login");
    }
  };

  const isAuthenticated = session.status === "authenticated";
  const isAdmin = isAuthenticated && session.user.is_admin;

  const navItems = useMemo(() => {
    const items: NavItem[] = [{ label: "Home", path: "/" }];

    if (!isAuthenticated) {
      items.push({ label: "Login", path: "/login" });
      return items;
    }

    items.push({ label: "Onboarding", path: "/onboarding" });
    items.push({ label: "Dashboard", path: "/dashboard" });
    if (isAdmin) {
      items.push({ label: "Admin Queue", path: "/admin/requests" });
    }

    return items;
  }, [isAdmin, isAuthenticated]);

  let content: ReactNode = <NotFoundScreen />;

  if (!matchedRoute) {
    content = <NotFoundScreen />;
  } else if (matchedRoute.route.requiresAuth && session.status === "loading") {
    content = (
      <ScreenSection caption="Session" title="Loading">
        <p>Validating session before opening this route.</p>
      </ScreenSection>
    );
  } else if (matchedRoute.route.requiresAuth && session.status === "error") {
    content = <SessionErrorScreen message={session.message} onRetry={refreshSession} />;
  } else if (matchedRoute.route.requiresAdmin && !isAdmin) {
    content = <ForbiddenScreen />;
  } else {
    switch (matchedRoute.route.key) {
      case "home":
        content = <HomeScreen session={session} />;
        break;
      case "login":
        content = <LoginScreen session={session} onSessionRefresh={refreshSession} />;
        break;
      case "auth_callback":
        content = <AuthCallbackScreen onSessionRefresh={refreshSession} />;
        break;
      case "onboarding":
        content = <OnboardingScreen onUnauthorized={handleUnauthorized} />;
        break;
      case "dashboard":
        content = <DashboardScreen onUnauthorized={handleUnauthorized} />;
        break;
      case "request_detail":
        content = (
          <RequestDetailScreen
            requestId={matchedRoute.params.id}
            onUnauthorized={handleUnauthorized}
          />
        );
        break;
      case "admin_requests":
        content = <AdminRequestsScreen onUnauthorized={handleUnauthorized} />;
        break;
      case "admin_request_detail":
        content = (
          <AdminRequestDetailScreen
            requestId={matchedRoute.params.id}
            onUnauthorized={handleUnauthorized}
          />
        );
        break;
      default:
        content = <NotFoundScreen />;
    }
  }

  return (
    <div className="app-canvas">
      <div className="shell-grid">
        <aside className={cx("sidebar", mobileNavOpen && "open")}>
          <div className="brand-block">
            <p className="caption">ZT-IX</p>
            <h2>Operational Console</h2>
            <p className="muted">Phase 11 workflow routes</p>
          </div>
          <nav id="primary-navigation" aria-label="Primary" className="nav-list">
            {navItems.map((item, index) => {
              const active =
                item.path === "/"
                  ? pathname === "/"
                  : pathname === item.path || pathname.startsWith(`${item.path}/`);
              return (
                <AppLink
                  key={item.path}
                  to={item.path}
                  className={cx("nav-item", active && "active")}
                  onNavigate={() => setMobileNavOpen(false)}
                >
                  <span className="nav-index">{String(index + 1).padStart(2, "0")}</span>
                  <span>{item.label}</span>
                </AppLink>
              );
            })}
          </nav>
        </aside>

        <main className="workspace">
          <header className="topbar">
            <button
              type="button"
              className="button secondary menu-button"
              onClick={() => setMobileNavOpen((current) => !current)}
              aria-expanded={mobileNavOpen}
              aria-controls="primary-navigation"
            >
              Menu
            </button>
            <div className="topbar-meta">
              <span className="topbar-chip">
                {session.status === "authenticated" ? `@${session.user.username}` : session.status}
              </span>
              <code className="mono">{pathname}</code>
              {isAuthenticated ? (
                <button
                  type="button"
                  className="button secondary"
                  onClick={() => void handleLogout()}
                  disabled={logoutBusy}
                >
                  {logoutBusy ? "Signing out..." : "Logout"}
                </button>
              ) : null}
            </div>
          </header>

          {content}
        </main>
      </div>
    </div>
  );
}
