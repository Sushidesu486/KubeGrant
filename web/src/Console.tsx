import { useEffect, useState } from "react";
import { Users } from "./Users";
import type { ReactNode } from "react";
import {
  ApiError,
  downloadKubeconfig,
  listCredentials,
  getSystemStatus,
  createGrant,
  errorMessage,
  listAudit,
  listGrants,
  listMembers,
  logout,
  revokeGrant,
} from "./api";
import type {
  AuditEvent,
  Credential,
  Grant,
  Member,
  Session,
  SystemStatus,
} from "./api";

type Tab = "mine" | "manage" | "credentials" | "audit" | "users";
function date(value: string) {
  return new Date(value).toLocaleString("zh-CN", { hour12: false });
}
function grantActive(grant: Grant) {
  return (
    !grant.revoked_at &&
    (grant.permanent ||
      (!!grant.expires_at && Date.parse(grant.expires_at) > Date.now()))
  );
}
function grantState(grant: Grant) {
  const state = grant.execution?.state ?? "pending";
  if (grant.revoked_at)
    return state === "revoked"
      ? "已撤回"
      : state === "error"
        ? "撤回失败"
        : "撤回中";
  if (!grantActive(grant))
    return state === "expired"
      ? "已到期并回收"
      : state === "error"
        ? "到期，回收失败"
        : "到期，回收中";
  return {
    pending: "待生效",
    applied: "已生效",
    error: "执行失败",
    revoking: "回收中",
    revoked: "已回收",
    expired: "已回收",
  }[state];
}
function credentialState(item: Credential) {
  if (
    item.state === "issued" &&
    item.expires_at &&
    Date.parse(item.expires_at) - Date.now() <
      (item.credential_policy === "operations" ? 7 * 86400000 : 3600000)
  )
    return "即将到期，请换领";
  return (
    (
      {
        pending: "签发中",
        issued: "已签发",
        failed: "签发失败",
        abandoned: "未领取",
        expired: "已到期",
        grant_inactive: "授权已结束",
      } as Record<string, string>
    )[item.state] ?? item.state
  );
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
  "member.imported": "导入用户",
  "member.updated": "更新用户资料",
  "directory.imported": "完成目录导入",
  "session.login": "登录",
  "session.logout": "退出",
  "grant.created": "创建授权",
  "grant.revoked": "撤回授权",
  "session.reset": "重置所有会话",
  "grant.execution.applied": "权限已生效",
  "grant.execution.revoked": "撤回完成",
  "grant.execution.expired": "到期回收完成",
  "grant.execution.error": "权限执行失败",
  "credential.requested": "申请凭据",
  "credential.issued": "签发凭据",
  "credential.prepared": "准备凭据下载",
  "credential.failed": "凭据签发失败",
  "credential.abandoned": "凭据未领取",
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
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [system, setSystem] = useState(status);
  const [permanent, setPermanent] = useState(false);
  const [policy, setPolicy] = useState<"standard" | "operations">("standard");
  const [success, setSuccess] = useState("");
  const [member, setMember] = useState("");
  const [selectedUser, setSelectedUser] = useState<Member | null>(null);
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
      setSystem(await getSystemStatus(controller.signal));
      if (tab === "users") return;
      if (tab === "audit") {
        setAudit((await listAudit(controller.signal)).items);
        return;
      }
      if (tab === "credentials") {
        setCredentials(
          (await listCredentials(session.administrator, controller.signal))
            .items,
        );
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
  }, [tab, refresh, onExpired, session.administrator]);

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

  async function download(id: string) {
    await mutate(async () => {
      setSuccess("");
      const expiry = await downloadKubeconfig(id);
      setSuccess(expiry ? `已下载，有效期至 ${date(expiry)}` : "已下载");
    });
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
          <button
            aria-current={tab === "credentials" ? "page" : undefined}
            onClick={() => setTab("credentials")}
          >
            凭据
          </button>
          {session.administrator && (
            <>
              <button
                aria-current={tab === "users" ? "page" : undefined}
                onClick={() => setTab("users")}
              >
                用户
              </button>
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
        {!system.features.kubeconfig_download && (
          <p className="notice">
            {system.signing?.enabled
              ? "签发服务暂不可用，请稍后重试。"
              : "凭据签发未启用，当前仅管理授权记录。"}
          </p>
        )}
        {success && (
          <p className="notice" role="status">
            {success}
          </p>
        )}
        {error && (
          <p className="error-message" role="alert">
            {error}
          </p>
        )}
        <div className="section-heading">
          <h1>
            {tab === "users"
              ? "用户"
              : tab === "mine"
                ? "我的授权"
                : tab === "manage"
                  ? "授权管理"
                  : tab === "credentials"
                    ? "凭据"
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
                createGrant(
                  member,
                  permanent ? null : new Date(expiry).toISOString(),
                  policy,
                  permanent,
                ),
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
                {selectedUser?.id === member &&
                  !members.some((item) => item.id === member) && (
                    <option value={selectedUser.id}>
                      {selectedUser.username} · {selectedUser.display_name}
                    </option>
                  )}
                {members.map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.username}
                    {item.display_name ? ` · ${item.display_name}` : ""}
                  </option>
                ))}
              </select>
            </label>
            <label>
              授权期限
              <select
                value={permanent ? "permanent" : "finite"}
                disabled={busy}
                onChange={(event) =>
                  setPermanent(event.target.value === "permanent")
                }
              >
                <option value="finite">指定到期时间</option>
                <option value="permanent">长期有效</option>
              </select>
            </label>
            <label>
              凭据有效期
              <select
                value={policy}
                disabled={busy}
                onChange={(event) =>
                  setPolicy(event.target.value as "standard" | "operations")
                }
              >
                <option value="standard">24 小时</option>
                <option value="operations">1 年（运维成员）</option>
              </select>
            </label>
            {!permanent && (
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
            )}
            <button className="primary-button" disabled={busy || !member}>
              创建授权
            </button>
            <p className="grant-target">
              集群：{status.grant_target.cluster_id}　权限：
              {status.grant_target.permission_ref}　有限期授权最长{" "}
              {duration(status.grant_target.max_ttl_seconds)}
            </p>
          </form>
        )}
        {tab === "users" ? (
          <Users
            username={session.member.username}
            importEnabled={!!system.features.user_import}
            refresh={refresh}
            onExpired={onExpired}
            grantState={grantState}
            onAssign={(user) => {
              setSelectedUser(user);
              setMember(user.id);
              setTab("manage");
            }}
          />
        ) : loading ? (
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
        ) : tab === "credentials" ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  {session.administrator && <th>成员</th>}
                  <th>公钥指纹</th>
                  <th>签发策略</th>
                  <th>申请时间</th>
                  <th>凭据到期时间</th>
                  <th>状态</th>
                </tr>
              </thead>
              <tbody>
                {credentials.map((item) => (
                  <tr key={item.id}>
                    {session.administrator && <td>{item.username}</td>}
                    <td title={item.public_key_sha256}>
                      {item.public_key_sha256.slice(0, 16)}
                    </td>
                    <td>
                      {item.credential_policy === "operations"
                        ? "1 年"
                        : "24 小时"}
                    </td>
                    <td>{date(item.created_at)}</td>
                    <td>{item.expires_at ? date(item.expires_at) : "—"}</td>
                    <td>{credentialState(item)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {credentials.length === 0 && (
              <p className="empty-state">暂无凭据</p>
            )}
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
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {grants.map((item) => (
                  <tr key={item.id}>
                    {tab === "manage" && <td>{item.username}</td>}
                    <td>{item.cluster_id}</td>
                    <td>{item.permission_ref}</td>
                    <td>
                      {item.permanent
                        ? "长期有效"
                        : item.expires_at
                          ? date(item.expires_at)
                          : "—"}
                    </td>
                    <td>{grantState(item)}</td>
                    <td>
                      {tab === "mine"
                        ? grantActive(item) && (
                            <button
                              className="secondary-button"
                              disabled={
                                busy ||
                                !system.features.kubeconfig_download ||
                                item.execution?.state !== "applied"
                              }
                              onClick={() => void download(item.id)}
                            >
                              {busy ? "处理中…" : "下载 kubeconfig"}
                            </button>
                          )
                        : !item.revoked_at && (
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
