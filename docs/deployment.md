# FreeIPA 接入、部署与应急运维

## 当前交付范围

已实现 FreeIPA LDAPS 登录、服务端会话、授权记录、管理员成员列表和审计记录的 SQLite 持久化，以及简洁的前端操作界面。FreeIPA 的 `admins` 组映射为平台管理员。**尚未实现 Kubernetes 凭据签发和集群侧收权**；创建/撤回授权目前只改变平台记录，界面会明确提示。

因此现在可以部署为身份与授权管理的联调环境，不能替代当前 kubeconfig 分发和集群运维流程。

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

默认允许创建最长 30 天的有限期授权，可通过 `KUBEGRANT_GRANT_MAX_TTL` 调整；这不是凭据 TTL。凭据签发未实现，平台授权到期也尚未执行 Kubernetes 收权。后续需通过独立的个人认证身份及可撤回的绑定执行授权，不能把普通成员放入绕过授权层的 `system:masters`。

## 3. 是否部署到 Kubernetes

可以。建议日常平台放在 k8s，**应急路径独立保留**。

`deploy/k8s/` 提供面向当前环境的 Kustomize 模板：

- 1 个 StatefulSet 副本，SQLite 使用独立 `ceph-block` RBD PVC，申请 ReadWriteOncePod；不在 CephFS/NFS 上让多个实例并发打开数据库。
- 非 root、只读根文件系统、禁提权；不自动挂载 ServiceAccount token，没有集群管理 RBAC，没有 Kubernetes CA 私钥。
- 接入现有 Envoy Gateway 的 `https-wildcard-clusters-zjusct-io` listener；平台域名规划为 `kubegrant.clusters.zjusct.io`，需核实 DNS 和证书覆盖。
- Namespace 防止 Argo 自动 prune，StatefulSet PVC 保留策略为 Retain。手动删除 PVC 仍可能触发 StorageClass 的 Delete 回收策略，不能视作备份。
- 网络策略允许网关入口、CoreDNS 和 freeipa namespace 的 TCP 636。需在真实目标 Pod 验证 Cilium/VIP/NAT 下的匹配；目前的 Pod TLS 核验没有套用这份新策略。

部署前需要：构建并推送真实镜像、替换 Kustomize 中的占位 tag、安装 IPA CA ConfigMap、验证 CSI 支持 RWOP、核对 DNS/HTTPRoute 和网络策略。当前模板尚未部署到生产集群。

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

正式替代旧 kubeconfig 分发之前，还要完成个人凭据签发、按授权回收、到期执行、故障恢复与离线入口演练。当前配置不会获取或分发任何真实 Kubernetes 管理凭据。
