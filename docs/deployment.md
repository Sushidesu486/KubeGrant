# FreeIPA 接入、部署与应急运维

## 当前交付范围

生产已实现 FreeIPA LDAPS 登录、会话、有限期/长期授权、管理员成员列表、审计、个人 kubeconfig 下载，以及独立控制器的集群权限执行和撤回。FreeIPA 的 `admins` 组映射为平台管理员；实际集群权限仍需显式授权。运行版本、权限差异、schema v2 迁移和回退步骤见 [发布说明](release-signing.md)。

2026-10-16 已上线签发版本，服务端检查通过；用户真实账号领取与撤回验收待完成。保留现有独立运维入口，首次发布历史及本次签发发布记录见文末。

## 1. 如何接入 FreeIPA

```text
浏览器 ──HTTPS──> KubeGrant ──LDAPS:636──> FreeIPA
                     │
                     └── SQLite：身份关联、会话哈希、授权、审计
```

首版使用用户名和密码登录。KubeGrant 以登录用户自身的 DN 进行 TLS 加密的 LDAP bind，随后读取本人 `uid`、`cn`、`ipaUniqueID`、`memberOf` 和 `nsAccountLock`。不保存密码，不使用 Directory Manager，也不需要把宿主机加入 IPA 域或部署 sssd。后续 GitLab 接入仍通过独立的身份接口完成。

配置：

```sh
export KUBEGRANT_PUBLIC_URL=https://kubegrant.clusters.zjusct.io
export KUBEGRANT_LDAP_URLS=ldaps://ipa-01.clusters.zjusct.io:636,ldaps://ipa-02.clusters.zjusct.io:636,ldaps://ipa-03.clusters.zjusct.io:636
export KUBEGRANT_LDAP_BASE_DN=dc=clusters,dc=zjusct,dc=io
export KUBEGRANT_LDAP_CA_FILE=/etc/kubegrant/ipa/ca.crt
export KUBEGRANT_ADMIN_GROUPS=admins
export KUBEGRANT_CLUSTER_ID=zjusct
export KUBEGRANT_PERMISSION_REF=cluster-admin
```

- IPA 公共 CA 证书来自已入域主机的 `/etc/ipa/ca.crt`；不复制 CA 私钥。强制校验 LDAP 服务端证书及主机名，不提供跳过 TLS 校验的选项。
- `memberOf` 与 `cn=admins,cn=groups,cn=accounts,<baseDN>` 匹配才成为平台管理员。平台管理员身份不会自动创建集群授权。嵌套组、OTP 和密码到期行为以实际 IPA 策略为准，需用测试账号验收。
- 稳定身份使用 IPA 的 `ipaUniqueID` 加身份来源关联到平台 Member ID；不按同名用户名自动继承旧身份或授权。缺失稳定 ID 时拒绝登录。
- 不可达的 LDAP endpoint 可以切换；密码错误不在所有副本上重试，以避免重复触发账号锁定。
- 若读取本人属性的 ACI 不足，登录会失败；应精确补足本人属性读取权限，不授予目录管理权限。
- 成员首次登录后才出现在平台成员列表中，管理员可为其创建授权；当前不会批量抓取整个 IPA 用户目录。

2026-10-15 的只读核验：从 m601 和 `rook-ceph-tools` Pod 均能验证三个规范 IPA 主机名的 LDAPS TLS 证书。该核验不包含真实用户 bind、属性权限或 admins 映射；本次开发没有使用真实用户密码。

参考：[FreeIPA LDAP 接入](https://www.freeipa.org/page/HowTo/LDAP.html)、[用户生命周期及稳定 ID](https://www.freeipa.org/page/V4/User_Life-Cycle_Management.html)。

## 2. 会话与授权的有效期

平台会话使用随机 opaque token；数据库只保存 SHA-256 哈希。生产 cookie 为 `__Host-kubegrant`，设置 HttpOnly、Secure、SameSite=Strict。修改操作校验精确的 `Origin`，因此 PUBLIC_URL 必须与实际访问地址一致。生产要求 HTTPS；仅允许 loopback 地址使用 HTTP 开发。

默认会话有效期 30 分钟，可配置为 1 分钟至 24 小时。管理员组在登录时读取，存入当次会话；**移出 admins 或停用账号不会立即终止已有平台会话**，最长持续到会话到期。需要立即退出所有平台会话时，运维人员可在服务器本地执行 `clear-sessions`。

默认允许创建最长 30 天的有限期授权，可通过 `KUBEGRANT_GRANT_MAX_TTL` 调整；管理员也可显式选择长期授权。普通凭据最长 24 小时，运维策略最长 365 天，均不超过有限授权的到期时间。每条授权使用独立 User 和可撤回的 RBAC 绑定，不包含 `system:masters`。撤回绑定回收其业务权限，证书认证和已有长连接的边界见发布说明；退出会话、IPA 停用均不等同于撤回集群授权。

## 3. 是否部署到 Kubernetes

可以。建议日常平台放在 k8s，**应急路径独立保留**。

`deploy/k8s/` 提供面向当前环境的 Kustomize 模板：

- 1 个 StatefulSet 副本，SQLite 使用独立 `ceph-block` RBD PVC，申请 ReadWriteOncePod；不在 CephFS/NFS 上让多个实例并发打开数据库。
- 首发镜像为 Linux amd64，显式设置 nodeSelector，避免在现有 ARM/RISC-V 节点上启动不兼容镜像。后续增加多架构构建时再调整调度范围。
- 非 root、只读根文件系统、禁提权；不自动挂载 ServiceAccount token，没有集群管理 RBAC，没有 Kubernetes CA 私钥。
- HTTPRoute 接入现有 Envoy Gateway，采用与 Harbor 相同的不指定 sectionName 的 parentRef，同时接受匹配域名的 HTTP/HTTPS listener。openng 终止外部 TLS 后通过 HTTP 转发 Envoy，仅挂 HTTPS listener 会使这条上游路径返回 404。
- Namespace 防止 Argo 自动 prune，StatefulSet PVC 保留策略为 Retain。手动删除 PVC 仍可能触发 StorageClass 的 Delete 回收策略，不能视作备份。
- 网络策略允许网关入口、CoreDNS 和 freeipa namespace 的 TCP 636。需在真实目标 Pod 验证 Cilium/VIP/NAT 下的匹配；目前的 Pod TLS 核验没有套用这份新策略。

生产签发使用 `deploy/k8s-signing/` opt-in overlay：增加独立控制器、显式投射 token、公开集群 CA、必要 RBAC 和准入约束。API egress 使用 Cilium 的 `kube-apiserver` 实体及 TCP 443/6443；该 overlay 要求 Cilium CRD，其他 CNI 需替换策略并实测。Web 不挂载 API token。

新环境部署前需要：构建并推送真实镜像、替换 Kustomize 中的占位 tag、安装 IPA CA ConfigMap、初始化同命名空间的 `harbor-pull` Secret、验证 CSI 支持 RWOP、核对 DNS/HTTPRoute 和网络策略。`deploy/k8s/` 保留镜像占位符作为可复用模板，当前生产配置由 ops 仓库的 `production/kubegrant` 管理。

### 镜像发布与 GitOps 交付

`.github/workflows/release.yml` 仅通过 `workflow_dispatch` 手动发布。流程先复用完整 CI，再构建并运行 Linux amd64 容器；以非 root、只读根目录验证静态页面、健康状态、一致性备份和正常退出，通过后才推送 `ghcr.io/sushidesu486/kubegrant:sha-<完整源码 SHA>`。Dockerfile 的基础镜像也固定到 digest。发布流程使用 GitHub 临时 `GITHUB_TOKEN` 的 packages:write 权限，无需配置长期仓库推送密码。

镜像认证、默认可见性和 digest 用法参考 [GitHub Container registry 文档](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry)。

### Harbor 拉取凭据

StatefulSet 的 Pod 显式引用 `imagePullSecrets: [{name: harbor-pull}]`。该 Secret 必须位于 `kubegrant` 命名空间，类型为 `kubernetes.io/dockerconfigjson`，注册表键为 `harbor.clusters.zjusct.io`。使用 KubeGrant 专用的项目 robot，仅授予 `ghcr.io` 项目内的 `repository:pull`；不授予 push、删除或管理权限。当前 Harbor 项目级 robot 的权限覆盖该代理缓存项目，并非仅覆盖单个 kubegrant 镜像仓库。

Secret 中 `data` 的 base64 是可逆编码，不是加密。凭据不写入应用仓库或 ops Git 仓库，也不作为 Pod 环境变量或卷交给应用进程；由 kubelet 用于镜像拉取。生产应限制 Secret 读取和该命名空间的工作负载创建权限。参见 [Kubernetes 拉取私有镜像](https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/) 和 [Secret 说明](https://kubernetes.io/docs/concepts/configuration/secret/)。

恢复或轮换时，在受控管理机从 Harbor 获取专用 robot 凭据，用隔离的 Docker 配置文件生成 Secret；`config.json` 必须直接包含该 registry 的 auth，不应只包含本机 credential helper 引用：

```sh
kubectl -n kubegrant create secret generic harbor-pull \
  --type=kubernetes.io/dockerconfigjson \
  --from-file=.dockerconfigjson=/secure/kubegrant-harbor/config.json \
  --dry-run=client -o yaml | kubectl apply --server-side --field-manager=kubegrant-credentials -f -
```

该命令经 stdin 传递 Secret，避免把 token 放进命令行或 Git；不要额外输出渲染结果。Secret 由凭据初始化流程管理，Argo 仅管理其引用。重建命名空间后须先恢复该 Secret；镜像已缓存时 Pod 启动成功不能证明新凭据有效，发布验收仍需验证 registry 认证和实际镜像拉取。Harbor 上游访问 GHCR 的凭据与 kubelet 访问 Harbor 的凭据分开处理。

2026-10-16（Asia/Shanghai）已初始化 `kubegrant` Namespace 和 `harbor-pull` Secret，使用 `robot$ghcr.io+kubegrant-pull`。已通过 Harbor 实际签发的 registry token 验证该账号具有 pull 权限、没有 push 权限；未发布镜像，因此尚未完成 KubeGrant 镜像的实际拉取。此 robot 有效期 90 天，至 **2027-01-14 10:25:09 +08:00**；到期前需轮换。账号 ID 与到期时间记在 Secret 的 `kubegrant.io/harbor-robot-id`、`kubegrant.io/credential-expires-at` 注解中，token 本身不进入 Git。本次未创建 StatefulSet、PVC 或应用入口。

### 发布步骤

1. 获得确认后提交并推送 KubeGrant 的发布准备变更，运行 `Publish image`，保留源码 SHA、工作流链接和摘要中的 registry digest。
2. 核实 GHCR 包可通过现有 Harbor GHCR 代理缓存读取。公开源码仓库不代表新建 GHCR 包自动公开；当前采用公开镜像路线，应将该包设为公开并验证匿名读取。生产镜像引用为 `harbor.clusters.zjusct.io/ghcr.io/sushidesu486/kubegrant@sha256:...`；发布流程仍推送 GHCR，没有直接推送 Harbor，也没有 Harbor 推送凭据。若改为私有镜像，需另外设计 Harbor 上游认证或普通项目直推及节点拉取凭据，不能仅给 Pod 添加 GHCR 凭据就视为已接通代理缓存。
3. ops 仓库 `production/kubegrant/` 保存公共 IPA CA 和独立资源清单。发布成功后将 images 配置改为 `digest: sha256:...`，删除 newTag；从实际节点验证带 Harbor 前缀的 digest 可被拉取，再运行该仓库针对变更文件的校验。**不得推送带占位镜像的 Argo 配置。**
4. 核对生产 ApplicationSet：目前监听 ops 仓库 `production/*`，自动 selfHeal/prune；新增目录一旦进入其目标 revision 就可能上线。按发布范围确认后交付该目录，保留其他工作树修改。
5. 等待 PVC Bound、Pod Ready、HTTPRoute Accepted/ResolvedRefs，并确认 DNS 与 HTTPS。当前 ExternalDNS 已启用 gateway-httproute source，预期由新路由创建 `kubegrant.clusters.zjusct.io` 的记录，不另行手工维护同一记录。
6. 使用真实测试账号验收：普通成员看不到管理接口；admins 成员有管理权限；创建授权后实际生效，下载配置可直接 kubectl；撤回后原配置的新业务请求被拒绝；审计一致且退出后旧平台会话不可用。

出现问题时，优先回退到已验证镜像 digest，并保留 PVC。首次发布尚无旧镜像可回退时，可暂停该应用自动同步并将副本调整为 0，保留数据库和审计；不要删除 Namespace/PVC。涉及数据库格式变更的版本，镜像回退前另行核对兼容性，不能直接让旧程序打开未知版本数据库。

2026-10-16（Asia/Shanghai）的发布前核验：m601 上从提交 `392bd82` 成功构建容器；Gateway 通配 HTTPS listener 和证书校验通过。当时平台路由尚未发布，返回 404。后续正式发布结果见文末，不以此准备阶段的观察代替线上现状。

在已入域的管理机上生成公共 CA 配置清单：

```sh
kubectl -n kubegrant create configmap kubegrant-ipa-ca \
  --from-file=ca.crt=/etc/ipa/ca.crt --dry-run=client -o yaml > kubegrant-ipa-ca.yaml
```

这是客户端生成文件，不会修改集群。将公共 CA 清单与该目录通过 ops GitOps 仓库交付，固定镜像 digest/版本。TLS 证书是公开信任材料，但不要将管理员 kubeconfig、CA 私钥或密码提交到仓库。

本地先渲染检查：

```sh
kubectl kustomize deploy/k8s
```

`/livez` 检查 HTTP 进程；`/readyz` 检查认证配置存在和数据库可用，不会在每次探针时连接 IPA。IPA 故障应使新登录失败，不应触发所有平台 Pod 反复重启。Ready 不表示凭据签发已实现，具体能力看 `/api/v1/status`。

参考：[StatefulSet 和 PVC 保留](https://kubernetes.io/docs/concepts/workloads/controllers/statefulset/)、[持久卷访问模式](https://kubernetes.io/docs/concepts/storage/persistent-volumes/)。

## 4. 如何保留运维入口

保留三条独立路径：

```text
日常：成员 → HTTPS/KubeGrant → FreeIPA → 后续个人 kubeconfig → apiserver
应急：运维工作站 → 离线应急 kubeconfig → apiserver
底层：运维工作站 → 本地 SSH 账号 / BMC → 控制面主机、etcd 与平台恢复
```

### 独立的主机入口

每台控制面主机保留专用的本地运维账号及本地公钥；账号 home、authorized_keys 和 sudo 规则都位于本机磁盘，不依赖 IPA、sssd、NFS home 或平台网关。BMC、管理网络路径和 SSH 入口也不能只通过集群内的 openng/Ingress。

这需要检查实际 sshd/PAM/NSS 配置，并在断开 LDAP/DNS/NFS 的测试条件下验证“SSH 公钥登录 → sudo → 查看/恢复静态 Pod”。在备用连接通过之前保留原连接。本次开发没有自动创建本地账号或修改主机 SSH。

### 独立的 Kubernetes 应急凭据

由现有运维流程确认并离线安全保管应急 kubeconfig、集群公共 CA、API endpoint、必要的地址映射、证书到期信息和恢复手册。不能只放在本集群 Secret、Ceph、Harbor、IPA 或 KubeGrant 数据库中。

kubeadm 的 `super-admin.conf` 若在现场存在，其 `system:masters` 身份可绕过 RBAC，用于授权配置本身损坏时的应急；它不是普通用户发放物。`admin.conf` 的普通管理员绑定与它含义不同。先核实现场文件、权限和证书，不由平台自动生成或分发这类凭据。[kubeadm 官方说明](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/create-cluster-kubeadm/)。

应急 API 地址必须能脱离集群 DNS/Ingress 使用，并与证书 SAN 匹配；可预先准备本地 hosts 映射和可达的控制面/管理 VIP，不使用跳过 TLS 验证作为恢复办法。

### 各种故障时走哪条路

| 故障 | 日常影响 | 恢复入口 |
|---|---|---|
| KubeGrant 停机 | 不能登录平台或领取新的凭据 | 离线 kubeconfig 直连 API；已签发个人证书未来也应直连 API |
| FreeIPA 停机 | 新平台登录失败 | 离线 x509 kubeconfig、本地主机 SSH |
| Ceph 停机 | 平台数据库可能不可用 | 离线 kubeconfig、本地 SSH；恢复存储或在独立机器恢复平台备份 |
| Ingress/DNS 故障 | 平台域名不可用 | 管理网 SSH、预先验证的 API endpoint/hosts 映射 |
| apiserver/etcd 故障 | kubeconfig 本身也无法恢复 API | 本地 SSH/BMC 进入控制面，执行独立的 etcd/PKI 恢复流程 |

当前 FreeIPA 本身运行在 k8s 中，存在启动依赖；在其迁出前，应急路径仍必须绕过 IPA。平台是否位于 k8s 内不会替代这条要求。m604 当前不可用，不应作为唯一恢复演练环境。

## 5. 备份与恢复

使用一致性 SQLite 快照，不能仅复制运行中的 `.db` 而忽略 WAL：

```sh
KUBEGRANT_DATABASE_PATH=data/kubegrant.db ./bin/kubegrant backup --output /safe/new-backup.db
```

容器无需 tar，备份可直接输出到本地文件：

```sh
umask 077
kubectl -n kubegrant exec kubegrant-0 -- /kubegrant backup --output - > kubegrant-backup.db
```

备份日志写 stderr，stdout 仅包含 SQLite 数据。该操作会在源数据库目录创建临时一致性快照，需要额外空闲空间；完成后自动移除临时快照。输出文件必须离开同一存储和集群故障域，限制权限并加密保管。此命令只备份平台数据，不备份 etcd、IPA、PKI 或业务 PVC。

恢复时停止唯一写入实例，保护原文件，将备份放到干净的数据库目录；不要混用旧的 `-wal/-shm`。以同一 UID/GID 启动前先清空恢复出来的平台会话：

```sh
KUBEGRANT_DATABASE_PATH=/restored/kubegrant.db ./bin/kubegrant clear-sessions
```

然后核对授权及审计，恢复入口并验证登录。恢复备份可能带回旧的授权记录；未来接入签发后，必须先和真实集群状态对账，不得直接重放旧授权。

## 6. 也可在独立管理机运行

若想先在 k8s 外联调，可用同一二进制和前端资源；`deploy/systemd/kubegrant.service` 是运行模板。为服务单独创建低权限系统账号，文件放 `/opt/kubegrant`，数据库在 `/var/lib/kubegrant`，配置在 `/etc/kubegrant/config.env`，通过管理机上的 HTTPS 反向代理访问。

systemd 模板只监听 127.0.0.1:8080，使用本地 StateDirectory。不要同时让 systemd 实例和 k8s 实例写同一数据库。即使平台在管理机，若 IPA 或数据库仍依赖原集群，它也不构成完全独立的容灾系统。

## 7. 联调与验收边界

本地自动测试覆盖受信任/不受信任 LDAPS、错误密码、缺失稳定 ID、锁定账号、管理员组映射、会话哈希/过期/退出、成员隔离、CSRF、管理员操作、限流和一致性备份。真实 IPA 的账号属性 ACI、OTP、账号停用与组移除仍需用测试账号实测。

个人凭据签发、按授权回收和到期执行已完成隔离集群验证并上线。正式推广前仍须完成真实生产账号的领取/撤回验收，保留故障恢复与离线入口演练。控制器不读取或挂载 Kubernetes CA 私钥。

## 8. 首次生产发布与验收记录

2026-10-16（Asia/Shanghai）通过 GitOps 发布，入口为 <https://kubegrant.clusters.zjusct.io>。集群内 DNS 解析为 Envoy Gateway 的 172.28.0.1。首次发布只完成内部 HTTPS 检查，外部入口存在接入遗漏；随后已修复并完成外部入口检查，具体记录见下文。

- 应用源码：`274ab330d7fee67e823c91687029b41a21658ded`。[镜像发布工作流](https://github.com/Sushidesu486/KubeGrant/actions/runs/38840929690) 的完整检查、容器验证和发布均通过。
- ops 发布提交：`aaf0779910b942b55c6a1d747055ec74fc5cb52b`，仅新增 `production/kubegrant`。从线上仓库建立隔离发布目录，未推送其他工作树中未发布的改动。
- 生产镜像：`harbor.clusters.zjusct.io/ghcr.io/sushidesu486/kubegrant@sha256:f8abef658937ae51f4a2b61d06e152bfd127e389ff3b5ba77d4728b33d3030b9`。专用 pull Secret 的实际拉取通过，镜像源码标签与上述版本一致。
- Argo Application 为 Synced/Healthy；`kubegrant-0` 在 `m602.clusters.zjusct.io` 运行，1/1 Ready、0 次重启。`data-kubegrant-0` 为 2Gi ceph-block/RWOP，状态 Bound；HTTPRoute 的 Accepted/ResolvedRefs 均为 True。
- 从 m601 经正式域名和 HTTPS 验证 livez、readyz、静态页面和能力接口；匿名成员/管理接口均为 401，错误 Origin 的登录请求为 403，未知 API 为 404。
- 在已部署网络策略下，以随机不存在的用户名做单次登录测试，返回 invalid_credentials/401，验证 LDAP 连接与 TLS 未被策略阻断；不等同于真实账号的属性读取和 admins 组映射验收。
- 已获取运行中数据库的一致性快照到本机受限目录，并通过 SQLite integrity_check；该快照未进入 Git，尚未配置定时异地备份。

首次发布时仅管理授权记录，`kubeconfig_download=false`。用户随后已确认实际 admins 登录及管理员入口正常；新版签发发布结果见下节。

### 外部入口接入缺口

用户报告外部站点无法加载后核查，实际链路为：客户端 HTTPS → openng TLS 终止和域名策略 → Envoy HTTP listener → KubeGrant Service。openng 已有通配转发到 `http://envoy-proxy.envoy-gateway.svc.cluster.local`，无需另加专用 backend。

修复前存在两处可复现的缺口：域名未加入 `production/openng/resources/secret.yaml` 中 policyd 的 Public Hosts，未登录客户端被 302 到 NetGATE；HTTPRoute 限定 HTTPS listener，openng 所用 HTTP 上游返回 404。经用户确认，按现有 Harbor 模式，仅将 KubeGrant 域名纳入 Public Hosts，由应用自己的 FreeIPA 登录和接口授权保护功能；移除该 HTTPRoute 的 sectionName 限定，保留内部 HTTPS 访问能力。ops 修正提交为 `90cca9f138b2981c3fd4e71678f5f263809f858d`，只改动上述两处。

外部回归命令：`bash scripts/check-public-entry.sh`。该检查从可直连校网入口的客户端执行，不携带 NetGATE cookie，也不通过本机 HTTP 代理；必须直接返回 200 和 KubeGrant 页面，302 到网关登录或 404 都会失败。修复前实测 FAIL/302，修复后实测 PASS/200。

修复后 openng 的 4 个实例滚动重载完成，openng 与 kubegrant 两个 Argo Application 均为 Synced/Healthy，revision 为上述修正提交。原 HTTP 上游由 404 变为 200，内部 HTTPS 仍为 200。本机直连和通过现有 HTTP 代理访问外部入口均返回 200；内置浏览器实际加载了用户名、密码和“使用 FreeIPA 登录”表单。经完整外部路径复查，匿名成员/管理 API 为 401，错误 Origin 登录请求为 403，错误用户名为 invalid_credentials/401，静态页面、livez、readyz 和能力接口正常。真实账号登录及管理员映射仍待用户验收。

## 9. 权限执行与 kubeconfig 签发发布

2026-10-16 用户确认提交并继续上线。运行镜像源码为 `be9f7e5515261f00edcd4669385f0b974af90175`，GitOps 最终提交为 `e6d33bd6f99240f6304c45f79bdb10acd78d30cf`；镜像 digest 为 `sha256:645a994c8035addf1519ef299777dc5a6075a1bbcb59103b11ac6aa2e1a6fc51`，通过现有 Harbor 代理拉取。完整验证、数据库备份迁移、Cilium 策略修正、剩余人工验收及回退限制统一记录于 [本次发布说明](release-signing.md)。schema v2 不兼容首次发布的旧二进制，不能直接回滚旧镜像。
