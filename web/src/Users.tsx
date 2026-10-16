import { useEffect, useState } from "react";
import {
  ApiError,
  errorMessage,
  importUsers,
  listUsers,
  listUserGrants,
  revokeGrant,
} from "./api";
import type { Grant, Member, Page, UserSummary } from "./api";

const empty = <T,>(): Page<T> => ({
  items: [],
  total: 0,
  limit: 20,
  offset: 0,
});
const date = (value: string) =>
  new Date(value).toLocaleString("zh-CN", { hour12: false });

export function Users({
  username,
  importEnabled,
  refresh,
  onExpired,
  onAssign,
  grantState,
}: {
  username: string;
  importEnabled: boolean;
  refresh: number;
  onExpired: () => void;
  onAssign: (user: Member) => void;
  grantState: (grant: Grant) => string;
}) {
  const [query, setQuery] = useState("");
  const [search, setSearch] = useState("");
  const [offset, setOffset] = useState(0);
  const [users, setUsers] = useState(empty<UserSummary>);
  const [selected, setSelected] = useState<UserSummary | null>(null);
  const [grantOffset, setGrantOffset] = useState(0);
  const [grants, setGrants] = useState(empty<Grant>);
  const [showImport, setShowImport] = useState(false);
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [loading, setLoading] = useState(false);
  const [grantsLoading, setGrantsLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [revision, setRevision] = useState(0);
  function failed(error: unknown) {
    if (error instanceof ApiError && error.status === 401) onExpired();
    else setError(errorMessage(error));
  }
  useEffect(() => {
    const c = new AbortController();
    setLoading(true);
    setError("");
    listUsers(search, offset, c.signal)
      .then(setUsers)
      .catch((e) => {
        if (!c.signal.aborted) {
          if (e instanceof ApiError && e.status === 401) onExpired();
          else setError(errorMessage(e));
        }
      })
      .finally(() => {
        if (!c.signal.aborted) setLoading(false);
      });
    return () => c.abort();
  }, [search, offset, revision, refresh, onExpired]);
  useEffect(() => {
    if (!selected) return;
    const c = new AbortController();
    setGrantsLoading(true);
    setGrants(empty());
    listUserGrants(selected.id, grantOffset, c.signal)
      .then(setGrants)
      .catch((e) => {
        if (!c.signal.aborted) {
          if (e instanceof ApiError && e.status === 401) onExpired();
          else setError(errorMessage(e));
        }
      })
      .finally(() => {
        if (!c.signal.aborted) setGrantsLoading(false);
      });
    return () => c.abort();
  }, [selected, grantOffset, revision, refresh, onExpired]);
  async function importAll() {
    const secret = password;
    setPassword("");
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const result = await importUsers(secret);
      setNotice(
        `导入完成：新增 ${result.created} 人，更新 ${result.updated} 人，未变更 ${result.unchanged} 人。`,
      );
      setShowImport(false);
      setOffset(0);
      setRevision((n) => n + 1);
    } catch (e) {
      failed(e);
    } finally {
      setBusy(false);
    }
  }
  async function revoke(id: string) {
    setBusy(true);
    setError("");
    try {
      await revokeGrant(id);
      setRevision((n) => n + 1);
    } catch (e) {
      failed(e);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <div className="user-toolbar">
        <form
          className="user-search"
          onSubmit={(e) => {
            e.preventDefault();
            setOffset(0);
            setSearch(query.trim());
          }}
        >
          <input
            aria-label="搜索用户"
            placeholder="用户名或姓名"
            maxLength={128}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <button className="secondary-button" disabled={busy}>
            搜索
          </button>
        </form>
        <button
          className="primary-button"
          disabled={busy || !importEnabled}
          onClick={() => {
            setShowImport((v) => !v);
            setPassword("");
            setError("");
          }}
        >
          从 FreeIPA 导入
        </button>
      </div>
      {showImport && (
        <form
          className="import-form"
          onSubmit={(e) => {
            e.preventDefault();
            void importAll();
          }}
        >
          <label>
            管理员账号
            <input value={username} readOnly autoComplete="username" />
          </label>
          <label>
            FreeIPA 密码
            <input
              type="password"
              autoComplete="current-password"
              required
              maxLength={4096}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={busy}
            />
          </label>
          <p className="grant-target">
            导入全部目录用户，仅登记身份，不分配集群权限。
          </p>
          <button
            className="secondary-button"
            type="button"
            disabled={busy}
            onClick={() => {
              setShowImport(false);
              setPassword("");
            }}
          >
            取消
          </button>
          <button className="primary-button" disabled={busy || !password}>
            {busy ? "正在导入…" : "验证并导入全部用户"}
          </button>
        </form>
      )}
      {error && (
        <p className="error-message" role="alert">
          {error}
        </p>
      )}
      {notice && (
        <p className="notice" role="status">
          {notice}
        </p>
      )}
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>用户名</th>
              <th>姓名</th>
              <th>身份来源</th>
              <th>最近登录</th>
              <th>有效授权</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            {!loading &&
              users.items.map((user) => (
                <tr key={user.id} aria-selected={selected?.id === user.id}>
                  <td>{user.username}</td>
                  <td>{user.display_name || "—"}</td>
                  <td>
                    {user.sources === "freeipa"
                      ? "FreeIPA"
                      : user.sources || "—"}
                  </td>
                  <td>
                    {user.last_login ? date(user.last_login) : "尚未登录"}
                  </td>
                  <td>{user.active_grants}</td>
                  <td>
                    <div className="row-actions">
                      <button
                        className="secondary-button"
                        disabled={busy}
                        onClick={() => {
                          setGrantOffset(0);
                          setSelected(user);
                        }}
                      >
                        查看权限
                      </button>
                      <button
                        className="secondary-button"
                        disabled={busy}
                        onClick={() => onAssign(user)}
                      >
                        分配权限
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
          </tbody>
        </table>
        {loading ? (
          <p className="empty-state">正在加载…</p>
        ) : (
          users.items.length === 0 && (
            <p className="empty-state">没有匹配的用户</p>
          )
        )}
      </div>
      <div className="pagination">
        <span>共 {users.total} 人</span>
        <div className="row-actions">
          <button
            className="secondary-button"
            disabled={busy || loading || offset === 0}
            onClick={() => setOffset(Math.max(0, offset - 20))}
          >
            上一页
          </button>
          <button
            className="secondary-button"
            disabled={busy || loading || offset + 20 >= users.total}
            onClick={() => setOffset(offset + 20)}
          >
            下一页
          </button>
        </div>
      </div>
      {selected && (
        <section
          className="user-permissions"
          aria-label={`${selected.username} 的权限`}
        >
          <div className="section-heading">
            <h2>{selected.username} 的权限</h2>
            <div className="row-actions">
              <button
                className="primary-button"
                disabled={busy}
                onClick={() => onAssign(selected)}
              >
                分配权限
              </button>
              <button
                className="secondary-button"
                onClick={() => setSelected(null)}
              >
                关闭
              </button>
            </div>
          </div>
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>集群</th>
                  <th>权限</th>
                  <th>授权到期</th>
                  <th>凭据有效期</th>
                  <th>执行状态</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {!grantsLoading &&
                  grants.items.map((g) => (
                    <tr key={g.id}>
                      <td>{g.cluster_id}</td>
                      <td>{g.permission_ref}</td>
                      <td>
                        {g.permanent
                          ? "长期有效"
                          : g.expires_at
                            ? date(g.expires_at)
                            : "—"}
                      </td>
                      <td>
                        {g.credential_policy === "operations"
                          ? "1 年"
                          : "24 小时"}
                      </td>
                      <td>{grantState(g)}</td>
                      <td>
                        {!g.revoked_at && (
                          <button
                            className="secondary-button"
                            disabled={busy}
                            onClick={() => void revoke(g.id)}
                          >
                            撤回
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
            {grantsLoading ? (
              <p className="empty-state">正在加载…</p>
            ) : (
              grants.items.length === 0 && (
                <p className="empty-state">暂无授权</p>
              )
            )}
          </div>
          <div className="pagination">
            <span>共 {grants.total} 条授权</span>
            <div className="row-actions">
              <button
                className="secondary-button"
                disabled={busy || grantsLoading || grantOffset === 0}
                onClick={() => setGrantOffset(Math.max(0, grantOffset - 20))}
              >
                上一页
              </button>
              <button
                className="secondary-button"
                disabled={
                  busy || grantsLoading || grantOffset + 20 >= grants.total
                }
                onClick={() => setGrantOffset(grantOffset + 20)}
              >
                下一页
              </button>
            </div>
          </div>
        </section>
      )}
    </>
  );
}
