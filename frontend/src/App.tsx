import { type TFunction } from "i18next";
import { useTranslation } from "react-i18next";
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
import { branding } from "./branding";
import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "./components/ui/table";
import { DEFAULT_LOCALE, LOCALE_OPTIONS, type SupportedLocale, resolveSupportedLocale } from "./i18n";

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
  labelKey: string;
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

function formatDateTime(value: string | null | undefined, locale: string, t: TFunction): string {
  if (!value) {
    return t("common.notAvailable");
  }

  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }

  return parsed.toLocaleString(locale);
}

function formatAssignedIpv6(value: string | null | undefined, t: TFunction): string {
  return value ?? t("common.unassigned");
}

function statusLabel(status: RequestStatus, t: TFunction): string {
  return t(`status.${status}`);
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
  const { t } = useTranslation();
  return <span className={statusClass(status)}>{statusLabel(status, t)}</span>;
}

function asApiError(error: unknown): ApiClientError | undefined {
  return isApiClientError(error) ? error : undefined;
}

function apiErrorMessage(error: unknown, t: TFunction, fallbackKey: string): string {
  const apiError = asApiError(error);
  if (!apiError) {
    return t(fallbackKey);
  }

  const translationKey = `errors.api.${apiError.code}`;
  const localized = t(translationKey);
  if (localized !== translationKey) {
    return localized;
  }

  return t(fallbackKey);
}

function readStringDetail(error: ApiClientError | undefined, key: string): string | undefined {
  if (!error) {
    return undefined;
  }
  const value = error.details[key];
  return typeof value === "string" ? value : undefined;
}

function isHttpUrl(value: string): boolean {
  return /^https?:\/\//i.test(value);
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
      {rows.map((row, index) => (
        <div key={`${index}-${row.label}`}>
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
  const { t } = useTranslation();

  if (session.status === "loading") {
    return (
      <ScreenSection caption={t("home.caption")} title={branding.appName}>
        <p>{t("home.loading")}</p>
      </ScreenSection>
    );
  }

  if (session.status === "error") {
    return (
      <ScreenSection caption={t("home.caption")} title={branding.appName}>
        <InlineError
          message={session.message}
          action={
            <button type="button" className="button secondary" onClick={() => window.location.reload()}>
              {t("common.retry")}
            </button>
          }
        />
      </ScreenSection>
    );
  }

  if (session.status === "unauthenticated") {
    return (
      <ScreenSection
        caption={t("home.caption")}
        title={branding.appName}
        action={
          <AppLink to="/login" className="button primary">
            {t("home.openLogin")}
          </AppLink>
        }
      >
        <p>{t("home.unauthenticatedMessage")}</p>
      </ScreenSection>
    );
  }

  return (
    <ScreenSection caption={t("home.caption")} title={t("home.signedInTitle")}>
      <p>
        {t("home.signedInMessage", {
          username: session.user.username,
        })}
      </p>
      <DefinitionGrid
        rows={[
          { label: t("labels.userId"), value: <code className="mono">{session.user.id}</code> },
          {
            label: t("labels.role"),
            value: session.user.is_admin ? t("roles.admin") : t("roles.operator"),
          },
          { label: t("labels.linkedAsns"), value: String(session.asns.length) },
        ]}
      />
      <div className="button-row">
        <AppLink to="/onboarding" className="button primary">
          {t("home.goToOnboarding")}
        </AppLink>
        <AppLink to="/dashboard" className="button secondary">
          {t("home.goToDashboard")}
        </AppLink>
        {session.user.is_admin ? (
          <AppLink to="/admin/requests" className="button secondary">
            {t("home.goToAdminQueue")}
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
  const { t } = useTranslation();
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
      setErrorText(apiErrorMessage(error, t, "errors.fallback.localLogin"));
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
      setErrorText(apiErrorMessage(error, t, "errors.fallback.oauthStart"));
      setOauthBusy(false);
    }
  };

  if (session.status === "loading") {
    return (
      <ScreenSection caption={t("login.caption")} title={t("login.title")}>
        <p>{t("login.checkingSession")}</p>
      </ScreenSection>
    );
  }

  if (session.status === "authenticated") {
    return (
      <ScreenSection
        caption={t("login.caption")}
        title={t("login.alreadySignedInTitle")}
        action={
          <AppLink to="/onboarding" className="button primary">
            {t("common.continue")}
          </AppLink>
        }
      >
        <InlineInfo
          message={t("login.alreadySignedInMessage", { username: session.user.username })}
          action={
            <AppLink to="/dashboard" className="button secondary">
              {t("login.goToDashboard")}
            </AppLink>
          }
        />
      </ScreenSection>
    );
  }

  return (
    <ScreenSection caption={t("login.caption")} title={t("login.title")}>
      <p className="lead-text">{t("login.lead")}</p>
      {errorText ? <InlineError message={errorText} /> : null}
      <div className="auth-grid">
        <div className="sub-panel">
          <h2>{t("login.oauth.title")}</h2>
          <p>{t("login.oauth.description")}</p>
          <button
            type="button"
            className="button primary"
            onClick={handlePeeringDbStart}
            disabled={oauthBusy || localBusy}
          >
            {oauthBusy ? t("login.oauth.busy") : t("login.oauth.cta")}
          </button>
        </div>
        <div className="sub-panel">
          <h2>{t("login.local.title")}</h2>
          <form className="form-grid" onSubmit={handleLocalLogin}>
            <label>
              {t("login.local.username")}
              <input
                value={username}
                onChange={(event) => setUsername(event.currentTarget.value)}
                autoComplete="username"
                required
              />
            </label>
            <label>
              {t("login.local.password")}
              <input
                type="password"
                value={password}
                onChange={(event) => setPassword(event.currentTarget.value)}
                autoComplete="current-password"
                required
              />
            </label>
            <button type="submit" className="button secondary" disabled={localBusy || oauthBusy}>
              {localBusy ? t("login.local.busy") : t("login.local.cta")}
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
  const { t } = useTranslation();
  const [phase, setPhase] = useState<"processing" | "success" | "error">("processing");
  const [message, setMessage] = useState(t("authCallback.messages.processing"));
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
        setMessage(t("authCallback.messages.missingParameters"));
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
        setMessage(t("authCallback.messages.success"));
        window.setTimeout(() => {
          navigate("/onboarding");
        }, 500);
      } catch (error) {
        const apiError = asApiError(error);
        setPhase("error");
        setMessage(apiErrorMessage(error, t, "errors.fallback.oauthCallback"));
        setDetailCode(readStringDetail(apiError, "detail_code") ?? null);
      }
    };

    void run();
  }, [onSessionRefresh, t]);

  return (
    <ScreenSection caption={t("authCallback.caption")} title={t("authCallback.title")}>
      {phase === "processing" ? <InlineInfo message={message} /> : null}
      {phase === "success" ? <InlineInfo message={message} /> : null}
      {phase === "error" ? (
        <InlineError
          message={message}
          action={
            <div className="button-row">
              <AppLink to="/login" className="button secondary">
                {t("authCallback.backToLogin")}
              </AppLink>
            </div>
          }
        />
      ) : null}
      {detailCode ? <p className="caption minor">{t("authCallback.detailCode", { code: detailCode })}</p> : null}
    </ScreenSection>
  );
}

function OnboardingScreen({
  onUnauthorized,
}: {
  onUnauthorized: () => void;
}) {
  const { t } = useTranslation();
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
      setLoadError(apiErrorMessage(error, t, "errors.fallback.onboardingContext"));
    } finally {
      setLoading(false);
    }
  }, [onUnauthorized, t]);

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
      setSubmitError(t("onboarding.validation.invalidAsn"));
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
      setSubmitError(apiErrorMessage(error, t, "errors.fallback.onboardingCreate"));
    } finally {
      setSubmitBusy(false);
    }
  };

  if (loading) {
    return (
      <ScreenSection caption={t("onboarding.caption")} title={t("onboarding.title")}>
        <p>{t("onboarding.loading")}</p>
      </ScreenSection>
    );
  }

  if (loadError) {
    return (
      <ScreenSection caption={t("onboarding.caption")} title={t("onboarding.title")}>
        <InlineError
          message={loadError}
          action={
            <button type="button" className="button secondary" onClick={() => void loadContext()}>
              {t("common.retry")}
            </button>
          }
        />
      </ScreenSection>
    );
  }

  if (!context) {
    return (
      <ScreenSection caption={t("onboarding.caption")} title={t("onboarding.title")}>
        <EmptyState
          title={t("onboarding.emptyContext.title")}
          description={t("onboarding.emptyContext.description")}
          action={
            <button type="button" className="button secondary" onClick={() => void loadContext()}>
              {t("common.reload")}
            </button>
          }
        />
      </ScreenSection>
    );
  }

  if (!context.constraints.submission_allowed || context.eligible_asns.length === 0) {
    return (
      <ScreenSection caption={t("onboarding.caption")} title={t("onboarding.title")}>
        <EmptyState
          title={t("onboarding.noEligibleAsn.title")}
          description={t("onboarding.noEligibleAsn.description")}
          action={
            <AppLink to="/dashboard" className="button secondary">
              {t("onboarding.noEligibleAsn.openDashboard")}
            </AppLink>
          }
        />
      </ScreenSection>
    );
  }

  return (
    <ScreenSection caption={t("onboarding.caption")} title={t("onboarding.title")}>
      <p className="lead-text">{t("onboarding.lead")}</p>
      {submitError ? (
        <InlineError
          message={submitError}
          action={
            duplicateLink ? (
              <AppLink to={duplicateLink} className="button secondary">
                {t("onboarding.openExistingRequest")}
              </AppLink>
            ) : undefined
          }
        />
      ) : null}
      <form className="form-grid onboarding-form" onSubmit={handleSubmit}>
        <label>
          {t("onboarding.form.asn")}
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
          {t("onboarding.form.network")}
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
          {t("onboarding.form.nodeId")}
          <input
            value={nodeIdValue}
            onChange={(event) => setNodeIdValue(event.currentTarget.value)}
            maxLength={10}
            placeholder={t("onboarding.form.nodeIdPlaceholder")}
          />
        </label>
        <label>
          {t("onboarding.form.notes")}
          <textarea
            value={notesValue}
            onChange={(event) => setNotesValue(event.currentTarget.value)}
            rows={4}
            placeholder={t("onboarding.form.notesPlaceholder")}
          />
        </label>
        <div className="button-row">
          <button type="submit" className="button primary" disabled={submitBusy}>
            {submitBusy ? t("onboarding.form.submitting") : t("onboarding.form.submit")}
          </button>
          <AppLink to="/dashboard" className="button secondary">
            {t("onboarding.form.goToDashboard")}
          </AppLink>
        </div>
      </form>
      {context.constraints.has_network_restrictions ? (
        <p className="caption minor">
          {t("onboarding.restrictions", {
            networks: context.constraints.restricted_network_ids.join(", "),
          })}
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
  const { t, i18n } = useTranslation();
  const [requests, setRequests] = useState<JoinRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);

  const locale = i18n.resolvedLanguage ?? DEFAULT_LOCALE;

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
          setLoadError(apiErrorMessage(error, t, "errors.fallback.requestsList"));
        }
      } finally {
        if (!silent) {
          setLoading(false);
        }
      }
    },
    [onUnauthorized, t],
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
      <ScreenSection caption={t("dashboard.caption")} title={t("dashboard.title")}>
        <p>{t("dashboard.loading")}</p>
      </ScreenSection>
    );
  }

  if (loadError) {
    return (
      <ScreenSection caption={t("dashboard.caption")} title={t("dashboard.title")}>
        <InlineError
          message={loadError}
          action={
            <button type="button" className="button secondary" onClick={() => void loadRequests(false)}>
              {t("common.retry")}
            </button>
          }
        />
      </ScreenSection>
    );
  }

  return (
    <ScreenSection
      caption={t("dashboard.caption")}
      title={t("dashboard.title")}
      action={
        <button type="button" className="button secondary" onClick={() => void loadRequests(false)}>
          {t("common.refresh")}
        </button>
      }
    >
      <p className="caption minor">
        {t("dashboard.polling", {
          seconds: REQUEST_POLL_INTERVAL_MS / 1000,
          refreshedAt: formatDateTime(lastUpdated, locale, t),
        })}
      </p>

      <div className="stat-grid">
        {STATUS_ORDER.map((status) => (
          <div key={status} className="stat-card">
            <span className="caption minor">{statusLabel(status, t)}</span>
            <strong>{counts[status]}</strong>
          </div>
        ))}
      </div>

      {sortedRequests.length === 0 ? (
        <EmptyState
          title={t("dashboard.empty.title")}
          description={t("dashboard.empty.description")}
          action={
            <AppLink to="/onboarding" className="button primary">
              {t("dashboard.empty.start")}
            </AppLink>
          }
        />
      ) : (
        <Table>
          <TableCaption>{t("dashboard.table.caption")}</TableCaption>
          <TableHeader>
            <TableRow>
              <TableHead>{t("dashboard.table.request")}</TableHead>
              <TableHead>{t("dashboard.table.asn")}</TableHead>
              <TableHead>{t("dashboard.table.network")}</TableHead>
              <TableHead>{t("dashboard.table.status")}</TableHead>
              <TableHead>{t("dashboard.table.assignedIpv6")}</TableHead>
              <TableHead>{t("dashboard.table.updated")}</TableHead>
              <TableHead>{t("dashboard.table.action")}</TableHead>
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
                  <code className="mono">{formatAssignedIpv6(request.assigned_ipv6, t)}</code>
                </TableCell>
                <TableCell>{formatDateTime(request.updated_at, locale, t)}</TableCell>
                <TableCell>
                  <AppLink to={`/requests/${request.id}`} className="text-link">
                    {t("dashboard.table.viewDetails")}
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
  const { t, i18n } = useTranslation();
  const [request, setRequest] = useState<JoinRequest | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);

  const locale = i18n.resolvedLanguage ?? DEFAULT_LOCALE;

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
          setLoadError(apiErrorMessage(error, t, "errors.fallback.requestDetail"));
        }
      } finally {
        if (!silent) {
          setLoading(false);
        }
      }
    },
    [onUnauthorized, requestId, t],
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
      <ScreenSection caption={t("requestDetail.caption")} title={t("requestDetail.title")}>
        <p>{t("requestDetail.loading")}</p>
      </ScreenSection>
    );
  }

  if (loadError) {
    return (
      <ScreenSection caption={t("requestDetail.caption")} title={t("requestDetail.title")}>
        <InlineError
          message={loadError}
          action={
            <button type="button" className="button secondary" onClick={() => void loadRequest(false)}>
              {t("common.retry")}
            </button>
          }
        />
      </ScreenSection>
    );
  }

  if (!request) {
    return (
      <ScreenSection caption={t("requestDetail.caption")} title={t("requestDetail.title")}>
        <EmptyState
          title={t("requestDetail.empty.title")}
          description={t("requestDetail.empty.description")}
          action={
            <AppLink to="/dashboard" className="button secondary">
              {t("requestDetail.empty.backToDashboard")}
            </AppLink>
          }
        />
      </ScreenSection>
    );
  }

  return (
    <ScreenSection
      caption={t("requestDetail.caption")}
      title={t("requestDetail.title")}
      action={<StatusBadge status={request.status} />}
    >
      <p className="caption minor">
        {t("requestDetail.header", {
          requestId: request.id,
          refreshedAt: formatDateTime(lastUpdated, locale, t),
        })}
      </p>
      {request.status === "failed" && request.last_error ? (
        <InlineError message={t("requestDetail.failed", { error: request.last_error })} />
      ) : null}
      {request.status === "rejected" && request.reject_reason ? (
        <InlineError message={t("requestDetail.rejected", { reason: request.reject_reason })} />
      ) : null}

      <DefinitionGrid
        rows={[
          { label: t("labels.asn"), value: <code className="mono">AS{request.asn}</code> },
          { label: t("labels.network"), value: <code className="mono">{request.zt_network_id}</code> },
          {
            label: t("labels.nodeId"),
            value: request.node_id ? <code className="mono">{request.node_id}</code> : t("common.notSet"),
          },
          { label: t("labels.requested"), value: formatDateTime(request.requested_at, locale, t) },
          { label: t("labels.updated"), value: formatDateTime(request.updated_at, locale, t) },
          { label: t("labels.retries"), value: String(request.retry_count) },
        ]}
      />

      <h2>{t("requestDetail.membership.title")}</h2>
      {request.membership ? (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t("requestDetail.membership.memberId")}</TableHead>
              <TableHead>{t("requestDetail.membership.node")}</TableHead>
              <TableHead>{t("requestDetail.membership.authorized")}</TableHead>
              <TableHead>{t("requestDetail.membership.assignedIps")}</TableHead>
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
              <TableCell>
                {request.membership.is_authorized ? t("common.yes") : t("common.no")}
              </TableCell>
              <TableCell>
                {request.membership.assigned_ips.length > 0
                  ? request.membership.assigned_ips.join(", ")
                  : t("common.notAssigned")}
              </TableCell>
            </TableRow>
          </TableBody>
        </Table>
      ) : (
        <EmptyState
          title={t("requestDetail.membership.empty.title")}
          description={t("requestDetail.membership.empty.description")}
        />
      )}

      <div className="button-row">
        <AppLink to="/dashboard" className="button secondary">
          {t("requestDetail.backToDashboard")}
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
  const { t, i18n } = useTranslation();
  const [statusFilter, setStatusFilter] = useState<RequestStatus | "">("");
  const [asnFilter, setAsnFilter] = useState("");
  const [networkFilter, setNetworkFilter] = useState("");
  const [minAgeFilter, setMinAgeFilter] = useState("");

  const [appliedFilters, setAppliedFilters] = useState<AdminRequestFilters>({});
  const [requests, setRequests] = useState<JoinRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);

  const locale = i18n.resolvedLanguage ?? DEFAULT_LOCALE;

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
          setLoadError(apiErrorMessage(error, t, "errors.fallback.adminQueue"));
        }
      } finally {
        if (!silent) {
          setLoading(false);
        }
      }
    },
    [onUnauthorized, t],
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
      <ScreenSection caption={t("adminQueue.caption")} title={t("adminQueue.title")}>
        <p>{t("adminQueue.loading")}</p>
      </ScreenSection>
    );
  }

  if (loadError) {
    return (
      <ScreenSection caption={t("adminQueue.caption")} title={t("adminQueue.title")}>
        <InlineError
          message={loadError}
          action={
            <button
              type="button"
              className="button secondary"
              onClick={() => void loadRequests(false, appliedFilters)}
            >
              {t("common.retry")}
            </button>
          }
        />
      </ScreenSection>
    );
  }

  return (
    <ScreenSection
      caption={t("adminQueue.caption")}
      title={t("adminQueue.title")}
      action={
        <button
          type="button"
          className="button secondary"
          onClick={() => void loadRequests(false, appliedFilters)}
        >
          {t("common.refresh")}
        </button>
      }
    >
      <form className="filter-grid" onSubmit={applyFilters}>
        <label>
          {t("adminQueue.filters.status")}
          <select
            value={statusFilter}
            onChange={(event) => setStatusFilter(event.currentTarget.value as RequestStatus | "")}
          >
            <option value="">{t("adminQueue.filters.all")}</option>
            {STATUS_ORDER.map((status) => (
              <option key={status} value={status}>
                {statusLabel(status, t)}
              </option>
            ))}
          </select>
        </label>
        <label>
          {t("adminQueue.filters.asn")}
          <input
            value={asnFilter}
            onChange={(event) => setAsnFilter(event.currentTarget.value)}
            placeholder={t("adminQueue.filters.asnPlaceholder")}
          />
        </label>
        <label>
          {t("adminQueue.filters.network")}
          <input
            value={networkFilter}
            onChange={(event) => setNetworkFilter(event.currentTarget.value)}
            placeholder={t("adminQueue.filters.networkPlaceholder")}
          />
        </label>
        <label>
          {t("adminQueue.filters.minAge")}
          <input
            value={minAgeFilter}
            onChange={(event) => setMinAgeFilter(event.currentTarget.value)}
            placeholder={t("adminQueue.filters.minAgePlaceholder")}
          />
        </label>
        <div className="button-row">
          <button type="submit" className="button primary">
            {t("adminQueue.filters.apply")}
          </button>
          <button type="button" className="button secondary" onClick={clearFilters}>
            {t("adminQueue.filters.clear")}
          </button>
        </div>
      </form>

      <p className="caption minor">
        {t("adminQueue.polling", {
          seconds: ADMIN_POLL_INTERVAL_MS / 1000,
          refreshedAt: formatDateTime(lastUpdated, locale, t),
        })}
      </p>

      {requests.length === 0 ? (
        <EmptyState
          title={t("adminQueue.empty.title")}
          description={t("adminQueue.empty.description")}
          action={
            <button type="button" className="button secondary" onClick={clearFilters}>
              {t("adminQueue.empty.reset")}
            </button>
          }
        />
      ) : (
        <Table>
          <TableCaption>{t("adminQueue.table.caption")}</TableCaption>
          <TableHeader>
            <TableRow>
              <TableHead>{t("adminQueue.table.request")}</TableHead>
              <TableHead>{t("adminQueue.table.asn")}</TableHead>
              <TableHead>{t("adminQueue.table.network")}</TableHead>
              <TableHead>{t("adminQueue.table.status")}</TableHead>
              <TableHead>{t("adminQueue.table.user")}</TableHead>
              <TableHead>{t("adminQueue.table.assignedIpv6")}</TableHead>
              <TableHead>{t("adminQueue.table.updated")}</TableHead>
              <TableHead>{t("adminQueue.table.action")}</TableHead>
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
                  <code className="mono">{formatAssignedIpv6(request.assigned_ipv6, t)}</code>
                </TableCell>
                <TableCell>{formatDateTime(request.updated_at, locale, t)}</TableCell>
                <TableCell>
                  <AppLink to={`/admin/requests/${request.id}`} className="text-link">
                    {t("adminQueue.table.review")}
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
  const { t, i18n } = useTranslation();
  const [detail, setDetail] = useState<AdminRequestDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionInfo, setActionInfo] = useState<string | null>(null);
  const [actionBusy, setActionBusy] = useState(false);
  const [rejectReason, setRejectReason] = useState("");

  const locale = i18n.resolvedLanguage ?? DEFAULT_LOCALE;

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
          setLoadError(apiErrorMessage(error, t, "errors.fallback.adminDetail"));
        }
      } finally {
        if (!silent) {
          setLoading(false);
        }
      }
    },
    [onUnauthorized, requestId, t],
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
        setActionError(t("adminReview.validation.rejectReasonRequired"));
        return;
      }

      setActionBusy(true);
      setActionError(null);
      setActionInfo(null);

      try {
        if (action === "approve") {
          await api.approveRequest(detail.request.id);
          setActionInfo(t("adminReview.actions.approveSuccess"));
        } else if (action === "retry") {
          await api.retryRequest(detail.request.id);
          setActionInfo(t("adminReview.actions.retrySuccess"));
        } else {
          await api.rejectRequest(detail.request.id, rejectReason.trim());
          setActionInfo(t("adminReview.actions.rejectSuccess"));
          setRejectReason("");
        }

        await loadDetail(true);
      } catch (error) {
        setActionError(apiErrorMessage(error, t, "errors.fallback.adminAction"));
      } finally {
        setActionBusy(false);
      }
    },
    [detail, loadDetail, rejectReason, t],
  );

  if (loading) {
    return (
      <ScreenSection caption={t("adminReview.caption")} title={t("adminReview.title")}>
        <p>{t("adminReview.loading")}</p>
      </ScreenSection>
    );
  }

  if (loadError) {
    return (
      <ScreenSection caption={t("adminReview.caption")} title={t("adminReview.title")}>
        <InlineError
          message={loadError}
          action={
            <button type="button" className="button secondary" onClick={() => void loadDetail(false)}>
              {t("common.retry")}
            </button>
          }
        />
      </ScreenSection>
    );
  }

  if (!detail) {
    return (
      <ScreenSection caption={t("adminReview.caption")} title={t("adminReview.title")}>
        <EmptyState
          title={t("adminReview.empty.title")}
          description={t("adminReview.empty.description")}
          action={
            <AppLink to="/admin/requests" className="button secondary">
              {t("adminReview.empty.backToQueue")}
            </AppLink>
          }
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
      caption={t("adminReview.caption")}
      title={t("adminReview.title")}
      action={<StatusBadge status={request.status} />}
    >
      <p className="caption minor">{t("adminReview.header", { requestId: request.id })}</p>
      {actionError ? <InlineError message={actionError} /> : null}
      {actionInfo ? <InlineInfo message={actionInfo} /> : null}

      <DefinitionGrid
        rows={[
          { label: t("labels.asn"), value: <code className="mono">AS{request.asn}</code> },
          { label: t("labels.network"), value: <code className="mono">{request.zt_network_id}</code> },
          { label: t("adminReview.labels.submitted"), value: formatDateTime(request.requested_at, locale, t) },
          { label: t("adminReview.labels.updated"), value: formatDateTime(request.updated_at, locale, t) },
          { label: t("adminReview.labels.retryCount"), value: String(request.retry_count) },
          {
            label: t("adminReview.labels.lastError"),
            value: request.last_error ? request.last_error : t("adminReview.labels.noError"),
          },
        ]}
      />

      <div className="action-panel">
        <h2>{t("adminReview.actions.title")}</h2>
        <div className="button-row">
          <button
            type="button"
            className="button primary"
            disabled={actionBusy || !canApprove}
            onClick={() => void performAction("approve")}
          >
            {t("adminReview.actions.approve")}
          </button>
          <button
            type="button"
            className="button secondary"
            disabled={actionBusy || !canRetry}
            onClick={() => void performAction("retry")}
          >
            {t("adminReview.actions.retry")}
          </button>
        </div>
        <label>
          {t("adminReview.actions.rejectReason")}
          <textarea
            value={rejectReason}
            onChange={(event) => setRejectReason(event.currentTarget.value)}
            rows={3}
            placeholder={t("adminReview.actions.rejectPlaceholder")}
            disabled={actionBusy || !canReject}
          />
        </label>
        <button
          type="button"
          className="button secondary"
          disabled={actionBusy || !canReject}
          onClick={() => void performAction("reject")}
        >
          {t("adminReview.actions.reject")}
        </button>
      </div>

      <h2>{t("adminReview.audit.title")}</h2>
      {detail.audit_events.length === 0 ? (
        <EmptyState
          title={t("adminReview.audit.empty.title")}
          description={t("adminReview.audit.empty.description")}
        />
      ) : (
        <Table>
          <TableCaption>{t("adminReview.audit.caption")}</TableCaption>
          <TableHeader>
            <TableRow>
              <TableHead>{t("adminReview.audit.table.time")}</TableHead>
              <TableHead>{t("adminReview.audit.table.action")}</TableHead>
              <TableHead>{t("adminReview.audit.table.actor")}</TableHead>
              <TableHead>{t("adminReview.audit.table.metadata")}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {detail.audit_events.map((event, index) => (
              <TableRow key={event.id} className={`stagger-row-${Math.min(index + 1, 8)}`}>
                <TableCell>{formatDateTime(event.created_at, locale, t)}</TableCell>
                <TableCell>{event.action}</TableCell>
                <TableCell>
                  {event.actor_user_id ? <code className="mono">{event.actor_user_id}</code> : t("common.system")}
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
          {t("adminReview.backToQueue")}
        </AppLink>
      </div>
    </ScreenSection>
  );
}

function NotFoundScreen() {
  const { t } = useTranslation();

  return (
    <ScreenSection caption={t("notFound.caption")} title={t("notFound.title")}>
      <EmptyState
        title={t("notFound.empty.title")}
        description={t("notFound.empty.description")}
        action={
          <AppLink to="/" className="button secondary">
            {t("notFound.empty.backHome")}
          </AppLink>
        }
      />
    </ScreenSection>
  );
}

function ForbiddenScreen() {
  const { t } = useTranslation();

  return (
    <ScreenSection caption={t("forbidden.caption")} title={t("forbidden.title")}>
      <InlineError
        message={t("forbidden.message")}
        action={
          <AppLink to="/dashboard" className="button secondary">
            {t("forbidden.openDashboard")}
          </AppLink>
        }
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
  const { t } = useTranslation();

  return (
    <ScreenSection caption={t("session.caption")} title={t("session.errorTitle")}>
      <InlineError
        message={message}
        action={
          <button type="button" className="button secondary" onClick={() => void onRetry()}>
            {t("session.retry")}
          </button>
        }
      />
    </ScreenSection>
  );
}

export function App() {
  const { t, i18n } = useTranslation();
  const [pathname, setPathname] = useState(() => normalizePath(window.location.pathname));
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [session, setSession] = useState<SessionState>({ status: "loading" });
  const [logoutBusy, setLogoutBusy] = useState(false);

  const matchedRoute = useMemo(() => matchRoute(pathname), [pathname]);

  useEffect(() => {
    document.title = branding.appName;
  }, []);

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
      setSession({ status: "error", message: apiErrorMessage(error, t, "errors.fallback.sessionCheck") });
    }
  }, [t]);

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
    const items: NavItem[] = [{ labelKey: "nav.home", path: "/" }];

    if (!isAuthenticated) {
      items.push({ labelKey: "nav.login", path: "/login" });
      return items;
    }

    items.push({ labelKey: "nav.onboarding", path: "/onboarding" });
    items.push({ labelKey: "nav.dashboard", path: "/dashboard" });
    if (isAdmin) {
      items.push({ labelKey: "nav.adminQueue", path: "/admin/requests" });
    }

    return items;
  }, [isAdmin, isAuthenticated]);

  const currentLocale = resolveSupportedLocale(i18n.resolvedLanguage) ?? DEFAULT_LOCALE;

  let content: ReactNode = <NotFoundScreen />;

  if (!matchedRoute) {
    content = <NotFoundScreen />;
  } else if (matchedRoute.route.requiresAuth && session.status === "loading") {
    content = (
      <ScreenSection caption={t("session.caption")} title={t("session.loadingTitle")}>
        <p>{t("session.loadingRoute")}</p>
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

  const sessionChipText =
    session.status === "authenticated"
      ? t("shell.sessionUser", { username: session.user.username })
      : t(`session.states.${session.status}`);

  return (
    <div className="app-canvas">
      <div className="shell-grid">
        <aside className={cx("sidebar", mobileNavOpen && "open")}>
          <div className="brand-block">
            <div className="brand-identity">
              <img src={branding.logoPath} alt={t("shell.logoAlt", { name: branding.appName })} className="brand-logo" />
              <div>
                <p className="caption">{branding.shortName}</p>
                <h2>{branding.appName}</h2>
              </div>
            </div>
            <p className="muted">{t("shell.brandSummary")}</p>
          </div>
          <nav id="primary-navigation" aria-label={t("shell.primaryNavigation")} className="nav-list">
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
                  <span>{t(item.labelKey)}</span>
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
              {t("shell.menu")}
            </button>
            <div className="topbar-meta">
              <div className="language-control">
                <label htmlFor="language-switcher" className="language-label">
                  {t("language.label")}
                </label>
                <select
                  id="language-switcher"
                  className="language-select"
                  value={currentLocale}
                  onChange={(event) => {
                    const nextLocale = resolveSupportedLocale(event.currentTarget.value) as
                      | SupportedLocale
                      | undefined;
                    if (nextLocale && nextLocale !== currentLocale) {
                      void i18n.changeLanguage(nextLocale);
                    }
                  }}
                >
                  {LOCALE_OPTIONS.map((option) => (
                    <option key={option.code} value={option.code}>
                      {t("language.option", {
                        flag: option.flag,
                        name: t(`language.names.${option.code}`),
                      })}
                    </option>
                  ))}
                </select>
              </div>
              <span className="topbar-chip">{sessionChipText}</span>
              <span className="topbar-chip">{t("shell.path", { path: pathname })}</span>
              {isAuthenticated ? (
                <button
                  type="button"
                  className="button secondary"
                  onClick={() => void handleLogout()}
                  disabled={logoutBusy}
                >
                  {logoutBusy ? t("shell.logoutBusy") : t("shell.logout")}
                </button>
              ) : null}
            </div>
          </header>

          {content}

          <footer className="app-footer">
            <a className="text-link" href={branding.supportUrl}>
              {t("shell.support")}
            </a>
            {branding.footerGithubUrl ? (
              <a
                className="text-link"
                href={branding.footerGithubUrl}
                target={isHttpUrl(branding.footerGithubUrl) ? "_blank" : undefined}
                rel={isHttpUrl(branding.footerGithubUrl) ? "noreferrer" : undefined}
              >
                {t("shell.github")}
              </a>
            ) : null}
            <span className="muted">{branding.footerText}</span>
          </footer>
        </main>
      </div>
    </div>
  );
}
