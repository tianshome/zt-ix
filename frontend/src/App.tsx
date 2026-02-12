import { useEffect, useMemo, useState } from "react";

const NAV_ITEMS = [
  { label: "Home", path: "/" },
  { label: "Login", path: "/login" },
  { label: "Onboarding", path: "/onboarding" },
  { label: "Dashboard", path: "/dashboard" },
  { label: "Admin Queue", path: "/admin/requests" },
];

const ROUTE_DEFINITIONS = [
  {
    key: "home",
    pattern: /^\/$/,
    template: "/",
    title: "Route Shell Home",
    description: "SPA app entry route and platform health surface.",
  },
  {
    key: "login",
    pattern: /^\/login\/?$/,
    template: "/login",
    title: "Login Screen",
    description: "Auth selection shell for local and PeeringDB login paths.",
  },
  {
    key: "auth_callback",
    pattern: /^\/auth\/callback\/?$/,
    template: "/auth/callback",
    title: "OAuth Callback",
    description: "Callback processing shell for auth code/state handling.",
  },
  {
    key: "onboarding",
    pattern: /^\/onboarding\/?$/,
    template: "/onboarding",
    title: "Onboarding",
    description: "Request initiation surface for ASN + target network selection.",
  },
  {
    key: "dashboard",
    pattern: /^\/dashboard\/?$/,
    template: "/dashboard",
    title: "Operator Dashboard",
    description: "Operator status overview for submitted requests.",
  },
  {
    key: "request_detail",
    pattern: /^\/requests\/([^/]+)\/?$/,
    params: ["id"],
    template: "/requests/:id",
    title: "Request Detail",
    description: "Per-request status and remediation context view.",
  },
  {
    key: "admin_requests",
    pattern: /^\/admin\/requests\/?$/,
    template: "/admin/requests",
    title: "Admin Queue",
    description: "Admin review queue and filtering shell.",
  },
  {
    key: "admin_request_detail",
    pattern: /^\/admin\/requests\/([^/]+)\/?$/,
    params: ["id"],
    template: "/admin/requests/:id",
    title: "Admin Request Detail",
    description: "Decision and retry action surface for a selected request.",
  },
];

function normalizePath(pathname: string): string {
  if (pathname.length > 1 && pathname.endsWith("/")) {
    return pathname.slice(0, -1);
  }
  return pathname || "/";
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

function matchRoute(pathname: string):
  | {
      route: (typeof ROUTE_DEFINITIONS)[number];
      params: Record<string, string>;
    }
  | undefined {
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

function AppLink({
  to,
  children,
  className,
  onNavigate,
}: {
  to: string;
  children: any;
  className?: string;
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

function PlaceholderCard({
  title,
  description,
  routeTemplate,
  params,
}: {
  title: string;
  description: string;
  routeTemplate: string;
  params: Record<string, string>;
}) {
  const entries = Object.entries(params);

  return (
    <section className="panel route-view" aria-live="polite">
      <div className="panel-header">
        <p className="caption">Phase 10 Route Shell</p>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      <dl className="meta-grid">
        <div>
          <dt>Route Template</dt>
          <dd>
            <code>{routeTemplate}</code>
          </dd>
        </div>
        <div>
          <dt>Current Path</dt>
          <dd>
            <code>{window.location.pathname}</code>
          </dd>
        </div>
        <div>
          <dt>Path Params</dt>
          <dd>
            {entries.length === 0 ? (
              <span className="muted">None</span>
            ) : (
              entries.map(([key, value]) => (
                <span key={key} className="pill">
                  {key}: <code>{value}</code>
                </span>
              ))
            )}
          </dd>
        </div>
      </dl>
      <div className="quick-links">
        <AppLink to="/requests/demo-request">
          Open example `/requests/:id`
        </AppLink>
        <AppLink to="/admin/requests/demo-request">
          Open example `/admin/requests/:id`
        </AppLink>
      </div>
    </section>
  );
}

export function App() {
  const [pathname, setPathname] = useState(() => normalizePath(window.location.pathname));
  const [mobileNavOpen, setMobileNavOpen] = useState(false);

  useEffect(() => {
    const onLocationChange = () => {
      setPathname(normalizePath(window.location.pathname));
    };

    window.addEventListener("popstate", onLocationChange);
    return () => {
      window.removeEventListener("popstate", onLocationChange);
    };
  }, []);

  const matched = useMemo(() => matchRoute(pathname), [pathname]);

  return (
    <div className="app-canvas">
      <div className="shell-grid">
        <aside className={`sidebar ${mobileNavOpen ? "open" : ""}`}>
          <div className="brand-block">
            <p className="caption">ZT-IX</p>
            <h2>Operator Console</h2>
            <p className="muted">SPA router shell (Phase 10)</p>
          </div>
          <nav id="primary-navigation" aria-label="Primary" className="nav-list">
            {NAV_ITEMS.map((item, index) => {
              const active =
                item.path === "/"
                  ? pathname === item.path
                  : pathname === item.path || pathname.startsWith(`${item.path}/`);
              return (
                <AppLink
                  key={item.path}
                  to={item.path}
                  className={`nav-item ${active ? "active" : ""}`}
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
              className="menu-button"
              onClick={() => setMobileNavOpen((state) => !state)}
              aria-expanded={mobileNavOpen}
              aria-controls="primary-navigation"
            >
              Menu
            </button>
            <div className="status-block">
              <span className="status-pill">SPA Router Active</span>
              <code>{pathname}</code>
            </div>
          </header>

          {matched ? (
            <PlaceholderCard
              title={matched.route.title}
              description={matched.route.description}
              routeTemplate={matched.route.template}
              params={matched.params}
            />
          ) : (
            <section className="panel route-view">
              <div className="panel-header">
                <p className="caption">Route Not Found</p>
                <h1>Unknown Path</h1>
                <p>
                  This path is outside the planned Phase 10 route set. Use navigation to return to a
                  supported route.
                </p>
              </div>
              <div className="quick-links">
                <AppLink to="/">
                  Back to home route
                </AppLink>
              </div>
            </section>
          )}
        </main>
      </div>
    </div>
  );
}
