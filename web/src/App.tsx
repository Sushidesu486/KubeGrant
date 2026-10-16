import { useCallback, useEffect, useState } from "react";
import {
  ApiError,
  errorMessage,
  getSession,
  getSystemStatus,
  login,
} from "./api";
import type { Session, SystemStatus } from "./api";
import { Console } from "./Console";
import { useTheme } from "./theme";
import type { Theme } from "./theme";

export function ThemeSelect({
  theme,
  onChange,
}: {
  theme: Theme;
  onChange: (value: Theme) => void;
}) {
  return (
    <select
      className="theme-select"
      aria-label="主题"
      value={theme}
      onChange={(event) => onChange(event.target.value as Theme)}
    >
      <option value="system">跟随系统</option>
      <option value="light">浅色</option>
      <option value="dark">深色</option>
    </select>
  );
}

export default function App() {
  const { theme, changeTheme } = useTheme();
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [attempt, setAttempt] = useState(0);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const expired = useCallback(() => {
    setSession(null);
    setError("会话已过期，请重新登录");
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError("");
    (async () => {
      const next = await getSystemStatus(controller.signal);
      setStatus(next);
      if (next.features.login) {
        try {
          setSession(await getSession(controller.signal));
        } catch (error) {
          if (!(error instanceof ApiError && error.status === 401)) throw error;
        }
      }
    })()
      .catch((error) => {
        if (!controller.signal.aborted) setError(errorMessage(error));
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [attempt]);

  useEffect(() => {
    if (!session) return;
    const timer = window.setTimeout(
      expired,
      Math.max(0, Date.parse(session.expires_at) - Date.now()),
    );
    return () => window.clearTimeout(timer);
  }, [session, expired]);

  const selector = <ThemeSelect theme={theme} onChange={changeTheme} />;
  if (session && status)
    return (
      <Console
        session={session}
        status={status}
        themeSelect={selector}
        onExpired={expired}
        onLoggedOut={() => {
          setSession(null);
          setError("");
        }}
      />
    );

  return (
    <main className="login-page">
      {selector}
      <section className="login-panel" aria-labelledby="title">
        <h1 id="title">KubeGrant</h1>
        <form
          onSubmit={async (event) => {
            event.preventDefault();
            setSubmitting(true);
            setError("");
            try {
              setSession(await login(username, password));
            } catch (error) {
              setError(errorMessage(error));
            } finally {
              setPassword("");
              setSubmitting(false);
            }
          }}
        >
          {status?.features.login && (
            <div className="login-fields">
              <label>
                用户名
                <input
                  name="username"
                  autoComplete="username"
                  required
                  maxLength={64}
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                  disabled={submitting}
                />
              </label>
              <label>
                密码
                <input
                  name="password"
                  type="password"
                  autoComplete="current-password"
                  required
                  maxLength={4096}
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  disabled={submitting}
                />
              </label>
            </div>
          )}
          <button
            className="login-button"
            disabled={loading || submitting || !status?.features.login}
          >
            {loading
              ? "正在连接…"
              : submitting
                ? "正在登录…"
                : "使用 FreeIPA 登录"}
          </button>
        </form>
        <div className="login-status" role="status" aria-live="polite">
          {error ? (
            <>
              <span>{error}</span>
              {!status && (
                <button
                  className="retry-button"
                  onClick={() => setAttempt((n) => n + 1)}
                >
                  重试
                </button>
              )}
            </>
          ) : !loading && !status?.features.login ? (
            "登录暂未开放"
          ) : null}
        </div>
      </section>
    </main>
  );
}
