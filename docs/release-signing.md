# 权限执行与 kubeconfig 分发：生产发布

状态：2026-10-16（Asia/Shanghai）用户确认提交并继续上线后，已完成源码推送、完整 CI、镜像发布与 Argo 生产更新。服务端验收通过，用户已明确确认真实账号领取、kubectl 访问与撤回后拒绝均正常。

## 本次行为变化

- 管理员可以显式创建有限期或长期授权，并选择 24 小时或 365 天的凭据策略。成员不能更改目标集群、角色、策略或期限；FreeIPA admins 身份只授予平台管理资格。
- 新增独立控制器，为每条授权创建独立 User 主体和 ClusterRoleBinding，审批自己创建且通过校验的 CSR；控制面签名，不接触 CA 私钥。
- 成员下载自包含 JSON kubeconfig，直接使用 kubectl。Web 请求内存持有私钥，数据库、队列、日志和审计不保存私钥。
- 撤回和到期会清理受管绑定；只有 API 确认删除后才显示回收完成。失败显示错误并重试，签发依赖近期控制器心跳和实际绑定状态。
- 凭据列表显示归属、公开指纹、申请与实际到期时间；接近到期提示换领。相同授权的多次领取统一收权，不支持逐份证书吊销。

## 已核验的环境与数据

- Kubernetes v1.35.0；个人 API 入口为 `https://k8s-api.clusters.zjusct.io:6444`，工作站使用集群公开 CA 验证 TLS 通过。公开 CA 到期为 2036-01-19。
- API Service 为 `172.27.0.1:443`，当前 EndpointSlice 指向 `172.25.4.11`、`.60`、`.61`、`.66` 的 6443 端口。生产 Cilium 1.19 的节点身份不匹配普通 CIDR 规则；实际 egress 使用 `CiliumNetworkPolicy` 的 `toEntities: [kube-apiserver]`，仅 TCP 443/6443，保持现有 DNS、IPA 和 Envoy 规则。
- 用户已确认生产 FreeIPA admins 账号能正常登录，并看到授权管理和审计入口。这是人工登录验收，不把模拟身份测试当作真实 FreeIPA 验收。
- 生产数据库已从运行中的旧版本执行一致性备份，保存于工作站忽略目录，0600 权限并通过 integrity_check。核验时 schema v1，成员 1，授权 0；因此启用控制器不会导入或自动授予历史成员权限。正式滚动更新前已再取新备份，迁移后的副本完整性与原成员、会话、审计保留均已验证。

## 本地与隔离验证

测试入口：`make test check build`；`npm --prefix web run format:check`。新增验证包括：

- 真实 v1 数据库迁移、会话/身份/审计保留、v2 一致性备份；NULL 长期授权语义、显式管理员选择和超过 500 条授权的回收遍历。
- 普通/运维策略隔离、有限期授权上限、CSR 和证书严格校验、私钥不序列化、真实双向 TLS；签发期间撤回、控制器重启、CSR UID 替换、所有权冲突和删除未确认。
- 下载的会话、Origin、成员归属与最终事务检查；管理员不能下载他人的私钥，下载参数不能更改策略。
- 实际 Kubernetes v1.35.0 的 CSR 签发、下载 API 返回的完整 kubeconfig 无需插件即可被真实 kubectl 使用、访问受限资源、撤回后相同配置新请求返回 403、控制器到期回收，以及准入拒绝共享绑定删除与任意主体。
- Linux amd64 容器在非 root、只读文件系统、无 capabilities 条件下启动、备份与优雅退出；独立测试 Pod 检查 Web/控制器分离和投射 token。

真实集群测试只允许显式指定的、API 位于 loopback 的 `kind-kubegrant-e2e`。固定 kind v0.33.0 二进制 SHA256，节点镜像 `kindest/node:v1.35.0@sha256:452d707d4862f52530247495d180205e029056831160e22870e37e3f6c1ac31f`。示例：

```sh
CGO_ENABLED=0 go test -c -o /tmp/controller-e2e.test ./internal/controller
bash scripts/test-cluster.sh /absolute/kind-admin.config /tmp/controller-e2e.test
```

测试使用专门只读节点角色，未向真实生产成员签发凭据。kind 的网络插件不能证明生产 Cilium 的 egress/DNAT 行为；生产已通过丢包观察定位并修正策略，实际 API 对账和控制器心跳正常，真实账号的领取、访问与撤回拒绝已由用户验收通过。

## Argo 交付差异

仅修改 `production/kubegrant`：

1. 固定新镜像 digest，Web 与控制器使用同一版本；保持现有 Harbor robot 与 imagePullSecret。
2. 单副本 StatefulSet 加入 controller sidecar，共享现有 SQLite/RBD PVC。保留非 root、只读文件系统等限制；只向控制器挂载自动轮换的短期 ServiceAccount token。
3. 增加公开集群 CA ConfigMap；没有管理员 kubeconfig、CA 私钥或用户密码。
4. 增加控制器 SA、必要 RBAC、参数化 ValidatingAdmissionPolicy 及其绑定；仅允许配置角色和受管绑定。按 sync wave 先配置参数与准入，再授予控制器权限，最后更新工作负载。
5. 增加仅面向 Cilium kube-apiserver 实体的 API egress，HTTPRoute 请求超时调整为 30 秒，覆盖最长 20 秒的签发等待；既有 openng、DNS 和 TLS 入口不变。

控制器有 CSR 审批和指定角色 bind 能力，属于高权限代理。CEL 约束资源归属、主体绑定、签名器和期限，但不解析 PEM/ASN.1；证书主体/组/扩展的检查仍由控制器执行。不能声称这已消除控制器被攻破后的提权风险。

首版角色仍由配置选取现有 ClusterRole；当前目标为 cluster-admin，但只有管理员明确创建授权后才会绑定个人身份，不自动给所有成员或 admins 组发放。多角色/namespace 范围的可配置目录仍属后续扩展。

## 数据库升级与回退

v1 → v2 是有事务保护的原地迁移：旧授权保留原到期时间与 standard 策略，新建长期授权的 expires_at 才为 NULL。新增授权执行、公开凭据申请和控制器心跳表。Web 与 controller 的迁移互斥，SQLite 写事务使用 immediate 模式和 busy timeout。

旧二进制拒绝 schema v2。升级后不直接滚回旧镜像，也不直接用旧备份覆盖现有数据库。故障时优先保留新版本 Web，将签发关闭并去掉 controller sidecar；记录已有凭据/绑定，必要时经独立运维入口清理受管绑定。仅更改开关但保留要求启用签发的 controller sidecar 会使其退出，不能这样保持整个 Pod Ready。

若必须恢复旧数据库，先暂停签发、保留最新数据库与审计，核对受管绑定及其撤回记录，再恢复并清空平台会话；对账完成前不能重放历史授权。回退到旧镜像意味着回到记录管理，旧平台不再执行回收。

## 生产验收

发布前完成源码提交确认、CI、镜像发布和新备份，再更新 Argo 配置。发布后确认应用 Synced/Healthy、双容器无重启、控制器日志正常、签发能力为 true，准入无 expression warnings。

用户用自己的 FreeIPA 账号领取首份配置，在本地执行允许的 kubectl 操作；密码和 kubeconfig 内容不进入聊天。随后撤回测试授权，确认原配置的新业务 API 请求被拒绝，再按正式需求重新授权。保留独立的 SSH、BMC 和离线应急配置。

永久授权、1 年证书、退出平台会话三者独立。FreeIPA 禁用账号不会吊销已签发证书，离队时必须显式撤回授权；cluster-admin 持有人自行建立的旁路权限和已有流式连接无法由平台保证连带回收。

本次检查通过：Go race、vet、前端类型检查/构建/格式检查、隔离集群真实下载与 kubectl、准入策略 typeChecking 零警告、候选容器启动/备份/退出、双容器 Pod 与签发能力、真实生产备份副本迁移，以及生产 Argo 清单服务端 dry-run。独立测试集群在检查后清理；生产服务端检查结果见下文，真实账号领取与撤回验收已由用户确认通过。

## 本次发布记录

- 运行镜像源码：`be9f7e5515261f00edcd4669385f0b974af90175`；[完整发布流程](https://github.com/Sushidesu486/KubeGrant/actions/runs/38877933445) 的常规检查、真实集群测试、容器冒烟测试与镜像推送全部通过。
- 镜像：`harbor.clusters.zjusct.io/ghcr.io/sushidesu486/kubegrant@sha256:645a994c8035addf1519ef299777dc5a6075a1bbcb59103b11ac6aa2e1a6fc51`。m601 验证 Harbor 实际拉取、amd64 和源码标签；生产 m602 也成功拉取。
- GitOps：`0616fd308e58fe7417574baee498faa14a947f76` 发布双容器与权限，`e6d33bd6f99240f6304c45f79bdb10acd78d30cf` 修正 Cilium API egress。只变更 `production/kubegrant`。
- 生产 SQLite schema 1 → 2 成功，成员、会话、审计逐行对比保留，未自动创建授权。上线前后的一致性备份位于本机忽略目录、0600 权限，integrity_check 均为 ok。
- Argo Synced/Healthy，双容器 Ready、零重启；公开接口 `signing.enabled=true`、`features.kubeconfig_download=true`。Web 不挂载 API token，两条准入策略 typeChecking 无警告。
- 外部 HTTPS 页面、livez、readyz、匿名接口拒绝、错误 Origin 拒绝、未知 API 404 和随机不存在 IPA 用户的 invalid_credentials/401 检查通过；本机验证显式绕过 HTTP 代理。
- CI 初次暴露准入策略异步生效的测试竞态，已加入有界 dry-run 生效探针；DELETE 的 dryRun 与 UID 条件同置于请求体，并在被允许的探针后检查资源 UID 不变。最终 push CI 与发布内 CI 均通过。

生产网络排障证据：Cilium drop monitor 显示 KubeGrant Pod 到 `kube-apiserver` 身份的 6443 SYN 被 Policy denied；改为实体规则后，无需重启 Pod，控制器恢复 API 对账，下载就绪变为 true。[Cilium CIDR 与集群节点匹配说明](https://docs.cilium.io/en/stable/security/policy/layer3/#selecting-pods-or-nodes-with-cidr-ipblock)。`deploy/k8s-signing` 因此明确针对当前 Cilium 集群；其他 CNI 需要替换这条 API egress 策略并实测。

2026-10-16 用户在真实生产入口完成了管理员测试授权、个人配置领取、kubectl 访问及撤回后原配置拒绝访问，明确回复“领取、访问和撤回后拒绝均正常”。该结论来自用户实际操作，密码和 kubeconfig 未进入聊天。离线应急入口及定时异地备份演练仍需按运维流程保留与执行。
