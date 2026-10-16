export interface SystemStatus {
  service: "kubegrant";
  phase: "foundation" | "access_management";
  identity_provider: "freeipa";
  features: {
    login: boolean;
    grant_management: boolean;
    kubeconfig_download: boolean;
  };
  grant_target: {
    cluster_id: string;
    permission_ref: string;
    max_ttl_seconds: number;
  };
}
export interface Member {
  id: string;
  username: string;
  display_name: string;
}
export interface Session {
  member: Member;
  administrator: boolean;
  expires_at: string;
}
export interface Grant {
  id: string;
  member_id: string;
  username: string;
  cluster_id: string;
  permission_ref: string;
  created_at: string;
  expires_at: string;
  revoked_at?: string;
}
export interface AuditEvent {
  id: number;
  at: string;
  actor_id: string;
  action: string;
  target_id: string;
  actor_username: string;
  target_label: string;
}

const messages: Record<string, string> = {
  invalid_credentials: "用户名或密码不正确，或账号不可用",
  identity_unavailable: "暂时无法连接 FreeIPA",
  authentication_not_configured: "登录暂未开放",
  authentication_required: "请重新登录",
  administrator_required: "需要管理员权限",
  storage_unavailable: "数据服务暂时不可用",
  too_many_attempts: "尝试次数过多，请一分钟后重试",
  invalid_origin: "请求来源不匹配，请从配置的平台地址访问",
  invalid_grant: "请选择成员，并设置有效范围内的到期时间",
  member_not_found: "成员不存在，请刷新后重试",
  grant_not_found: "授权不存在，请刷新后重试",
  grant_target_not_configured: "集群权限尚未配置",
};
export class ApiError extends Error {
  constructor(
    public status: number,
    code: string,
  ) {
    super(messages[code] ?? "请求失败，请稍后重试");
  }
}
export function errorMessage(error: unknown): string {
  return error instanceof ApiError ? error.message : "暂时无法连接服务";
}

async function request<T>(
  path: string,
  method = "GET",
  body?: unknown,
  signal?: AbortSignal,
): Promise<T> {
  const response = await fetch(`/api/v1${path}`, {
    method,
    credentials: "same-origin",
    cache: "no-store",
    headers: {
      Accept: "application/json",
      ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
    },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    signal: signal
      ? AbortSignal.any([signal, AbortSignal.timeout(15000)])
      : AbortSignal.timeout(15000),
  });
  if (!response.ok) {
    const value = await response.json().catch(() => ({}));
    throw new ApiError(
      response.status,
      typeof value.error === "string" ? value.error : "unknown",
    );
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}
export async function getSystemStatus(
  signal: AbortSignal,
): Promise<SystemStatus> {
  const value = await request<SystemStatus>(
    "/status",
    "GET",
    undefined,
    signal,
  );
  if (
    value.service !== "kubegrant" ||
    !["foundation", "access_management"].includes(value.phase) ||
    value.identity_provider !== "freeipa" ||
    typeof value.features?.login !== "boolean" ||
    typeof value.features?.grant_management !== "boolean" ||
    typeof value.features?.kubeconfig_download !== "boolean" ||
    typeof value.grant_target?.cluster_id !== "string"
  )
    throw new Error("Unexpected service status");
  return value;
}
export const getSession = (signal?: AbortSignal) =>
  request<Session>("/me", "GET", undefined, signal);
export const login = (username: string, password: string) =>
  request<Session>("/auth/login", "POST", { username, password });
export const logout = () => request<void>("/auth/logout", "POST");
export const listGrants = (admin: boolean, signal?: AbortSignal) =>
  request<{ items: Grant[] }>(
    admin ? "/admin/grants" : "/grants",
    "GET",
    undefined,
    signal,
  );
export const listMembers = (signal?: AbortSignal) =>
  request<{ items: Member[] }>("/admin/members", "GET", undefined, signal);
export const listAudit = (signal?: AbortSignal) =>
  request<{ items: AuditEvent[] }>("/admin/audit", "GET", undefined, signal);
export const createGrant = (memberID: string, expiresAt: string) =>
  request<Grant>("/admin/grants", "POST", {
    member_id: memberID,
    expires_at: expiresAt,
  });
export const revokeGrant = (id: string) =>
  request<void>(`/admin/grants/${encodeURIComponent(id)}/revoke`, "POST");
