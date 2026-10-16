import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import {
  ApiError,
  createGrant,
  errorMessage,
  listAudit,
  listGrants,
  listMembers,
  logout,
  revokeGrant,
} from "./api";
import type { AuditEvent, Grant, Member, Session, SystemStatus } from "./api";

type Tab = "mine" | "manage" | "audit";
function date(value: string) {
  return new Date(value).toLocaleString("zh-CN", { hour12: false });
}
function grantState(grant: Grant) {
  if (grant.revoked_at) return "已撤回";
  return Date.parse(grant.expires_at) <= Date.now() ? "已到期" : "有效";
}
function localDate(time: number) {
  const date = new Date(time);
  return new Date(date.getTime() - date.getTimezoneOffset() * 60000)
    .toISOString()
    .slice(0, 16);
}
function duration(seconds: number) {
  if (seconds >= 86400) return `${seconds / 86400} 天`;
  if (seconds >= 3600) return `${seconds / 3600} 小时`;
  return `${seconds / 60} 分钟`;
}
const actions: Record<string, string> = {
  "session.login": "登录",
  "session.logout": "退出",
  "grant.created": "创建授权",
  "grant.revoked": "撤回授权",
  "session.reset": "重置所有会话",
};

export function Console({
  session,
  status,
  themeSelect,
  onExpired,
  onLoggedOut,
}: {
  session: Session;
  status: SystemStatus;
  themeSelect: ReactNode;
  onExpired: () => void;
  onLoggedOut: () => void;
}) {
  const [tab, setTab] = useState<Tab>("mine");
  const [grants, setGrants] = useState<Grant[]>([]);
  const [members, setMembers] = useState<Member[]>([]);
  const [audit, setAudit] = useState<AuditEvent[]>([]);
  const [member, setMember] = useState("");
  const [expiry, setExpiry] = useState(() =>
    localDate(
      Date.now() + Math.min(86400, status.grant_target.max_ttl_seconds) * 1000,
    ),
  );
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [refresh, setRefresh] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError("");
    (async () => {
      if (tab === "audit") {
        setAudit((await listAudit(controller.signal)).items);
        return;
      }
      setGrants((await listGrants(tab === "manage", controller.signal)).items);
      if (tab === "manage")
        setMembers((await listMembers(controller.signal)).items);
    })()
      .catch((error) => {
        if (controller.signal.aborted) return;
        if (error instanceof ApiError && error.status === 401) onExpired();
        else setError(errorMessage(error));
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [tab, refresh, onExpired]);

  async function mutate(operation: () => Promise<unknown>) {
    setBusy(true);
    setError("");
    try {
      await operation();
      setRefresh((n) => n + 1);
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) onExpired();
      else setError(errorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="console">
      <header className="console-header">
        <span className="console-brand">KubeGrant</span>
        <div className="console-actions">
          <span>{session.member.username}</span>
          {themeSelect}
          <button
            className="secondary-button"
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              try {
                await logout();
                onLoggedOut();
              } catch (error) {
                if (error instanceof ApiError && error.status === 401)
                  onLoggedOut();
                else setError(errorMessage(error));
              } finally {
                setBusy(false);
              }
            }}
          >
            退出
          </button>
        </div>
      </header>
      <main className="console-main">
        <nav className="tabs" aria-label="功能">
          <button
            aria-current={tab === "mine" ? "page" : undefined}
            onClick={() => setTab("mine")}
          >
            我的授权
          </button>
          {session.administrator && (
            <>
              <button
                aria-current={tab === "manage" ? "page" : undefined}
                onClick={() => setTab("manage")}
              >
                授权管理
              </button>
              <button
                aria-current={tab === "audit" ? "page" : undefined}
                onClick={() => setTab("audit")}
              >
                审计
              </button>
            </>
          )}
        </nav>
        {!status.features.kubeconfig_download && (
          <p className="notice">凭据签发尚未接入，当前仅管理授权记录。</p>
        )}
        {error && (
          <p className="error-message" role="alert">
            {error}
          </p>
        )}
        <div className="section-heading">
          <h1>
            {tab === "mine"
              ? "我的授权"
              : tab === "manage"
                ? "授权管理"
                : "审计"}
          </h1>
          <button
            className="secondary-button"
            disabled={loading || busy}
            onClick={() => setRefresh((n) => n + 1)}
          >
            刷新
          </button>
        </div>
        {tab === "manage" && status.features.grant_management && (
          <form
            className="grant-form"
            onSubmit={(event) => {
              event.preventDefault();
              void mutate(() =>
                createGrant(member, new Date(expiry).toISOString()),
              );
            }}
          >
            <label>
              成员
              <select
                required
                value={member}
                onChange={(event) => setMember(event.target.value)}
                disabled={busy}
              >
                <option value="">选择成员</option>
                {members.map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.username}
                    {item.display_name ? ` · ${item.display_name}` : ""}
                  </option>
                ))}
              </select>
            </label>
            <label>
              到期时间
              <input
                type="datetime-local"
                min={localDate(Date.now())}
                max={localDate(
                  Date.now() + status.grant_target.max_ttl_seconds * 1000,
                )}
                required
                value={expiry}
                onChange={(event) => setExpiry(event.target.value)}
                disabled={busy}
              />
            </label>
            <button className="primary-button" disabled={busy || !member}>
              创建授权
            </button>
            <p className="grant-target">
              集群：{status.grant_target.cluster_id}　权限：
              {status.grant_target.permission_ref}　最长{" "}
              {duration(status.grant_target.max_ttl_seconds)}
            </p>
          </form>
        )}
        {loading ? (
          <p className="empty-state">正在加载…</p>
        ) : tab === "audit" ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>时间</th>
                  <th>操作</th>
                  <th>操作者</th>
                  <th>对象</th>
                </tr>
              </thead>
              <tbody>
                {audit.map((item) => (
                  <tr key={item.id}>
                    <td>{date(item.at)}</td>
                    <td>{actions[item.action] ?? item.action}</td>
                    <td>{item.actor_username}</td>
                    <td>{item.target_label}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {audit.length === 0 && <p className="empty-state">暂无记录</p>}
          </div>
        ) : (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  {tab === "manage" && <th>成员</th>}
                  <th>集群</th>
                  <th>权限</th>
                  <th>到期时间</th>
                  <th>状态</th>
                  {tab === "manage" && <th>操作</th>}
                </tr>
              </thead>
              <tbody>
                {grants.map((item) => (
                  <tr key={item.id}>
                    {tab === "manage" && <td>{item.username}</td>}
                    <td>{item.cluster_id}</td>
                    <td>{item.permission_ref}</td>
                    <td>{date(item.expires_at)}</td>
                    <td>{grantState(item)}</td>
                    {tab === "manage" && (
                      <td>
                        {!item.revoked_at && (
                          <button
                            className="secondary-button"
                            disabled={busy}
                            onClick={() =>
                              void mutate(() => revokeGrant(item.id))
                            }
                          >
                            撤回
                          </button>
                        )}
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
            {grants.length === 0 && <p className="empty-state">暂无授权</p>}
          </div>
        )}
      </main>
    </div>
  );
}
