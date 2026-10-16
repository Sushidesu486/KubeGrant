# KubeGrant

基于 Kubernetes 的内部权限控制平台，向成员分发受管理的个人 kubeconfig。管理员分配角色、范围和有效期，成员通过 FreeIPA 登录领取；GitLab 身份适配留待后续。

## 当前进度

已上线功能：

- FreeIPA LDAPS 登录，以 `ipaUniqueID` 关联稳定身份，`admins` 组映射为平台管理员。
- 服务端会话、退出与到期失效；密码不保存，数据库只保存会话 token 哈希。
- 成员查看个人授权；管理员创建有限期/长期授权，选择 24 小时或 1 年凭据策略，查看成员与审计。
- 独立控制器执行 RBAC 绑定、Kubernetes CSR 签发、撤回与到期回收；成员下载个人 kubeconfig，查看凭据记录与到期提示。
- SQLite 持久化、一致性备份及运维会话重置命令。
- 简洁的 React + TypeScript 界面，支持浅色、深色和跟随系统。
- 本地测试、CI、Dockerfile、手动镜像发布流程、Kubernetes 和 systemd 部署模板。

生产已启用权限执行和个人 kubeconfig 下载，入口为 https://kubegrant.clusters.zjusct.io 。当前只接入现有单集群和服务端配置的角色；用户已确认真实账号领取、kubectl 访问与撤回后拒绝均正常。新环境默认关闭签发，只有显式配置集群、部署控制器并完成对账后才开放下载。私钥只在下载请求内存中保留。

范围与进度见 [开发计划](docs/credential-plan.md)，本次权限差异、迁移、验证和回退步骤见 [发布说明](docs/release-signing.md)。本次发布已获用户提交与上线确认；后续提交继续遵守确认约定。

当前工作区另已实现用户搜索、个人权限查看及 FreeIPA 批量导入，尚未发布，见 [用户导入说明](docs/user-import.md)。

## 本地开发

要求 Go 1.27+、Node.js 22.12+、npm。依赖由 `go.sum`、`web/package-lock.json` 固定。

```sh
make install-web
make dev-api
```

另一个终端：

```sh
make dev-web
```

打开 <http://127.0.0.1:5173>。未配置 FreeIPA 时可查看页面，但登录保持关闭。

启用真实登录需按照 [.env.example](.env.example) 设置环境变量；服务不自动读取 `.env`。开发代理下 PUBLIC_URL 应设置为实际前端地址 `http://127.0.0.1:5173`，不能仍用后端 8080 地址。生产必须是 HTTPS origin。

没有全局 Go 时，本次下载的工具链位于忽略的 `.tools/go`，例如：

```sh
make GO="$PWD/.tools/go/bin/go" dev-api
```

## 验证与构建

```sh
make test check build
npm --prefix web run format:check
```

容器构建与验证（需要 Docker、curl、Python 3）：

```sh
docker build --platform linux/amd64 --build-arg SOURCE_REVISION="$(git rev-parse HEAD)" -t kubegrant:local .
bash scripts/smoke-container.sh kubegrant:local
```

GitHub Actions 的 `Publish image` 手动执行；完整测试和容器验证通过后，发布带完整源码 SHA 的 GHCR 镜像，并在运行摘要输出不可变 digest。不会自动部署到集群。

生产节点按 ops 仓库约定通过现有 Harbor GHCR 代理缓存拉取：`harbor.clusters.zjusct.io/ghcr.io/sushidesu486/kubegrant@sha256:...`。Pod 引用同命名空间的 `harbor-pull` imagePullSecret，使用专用只读 robot 账号；凭据独立初始化，不提交 Git。当前没有直接向 Harbor 推送镜像的流程或写入凭据配置。

单进程运行构建后的前后端：

```sh
KUBEGRANT_STATIC_DIR=web/dist ./bin/kubegrant
```

`/livez` 检查进程，`/readyz` 检查认证配置和数据库，`/api/v1/status` 返回当前能力。Ready 不代表凭据签发已实现。

## 数据与备份

数据库默认保存在 `data/kubegrant.db`，该目录已忽略，不应提交。单实例使用本地磁盘或独立 RBD 卷；不使用多副本共享 SQLite。

```sh
./bin/kubegrant backup --output /safe/new-backup.db
./bin/kubegrant backup --output - > /safe/new-backup.db
./bin/kubegrant clear-sessions
```

备份必须离开原集群故障域。`clear-sessions` 是服务器本地运维命令，终止全部平台会话并记录审计；它不会撤销集群凭据。

## 部署和应急入口

详见 [FreeIPA 接入、部署与应急运维](docs/deployment.md)。

- `deploy/k8s/`：面向现有 Envoy Gateway/ceph-block 的单实例模板；首版仅调度至 Linux amd64 节点，需替换镜像、添加 IPA CA 并验收后交付。
- `deploy/k8s-signing/`：显式启用签发的 overlay，包含 controller、受约束 RBAC、准入策略和 API egress；需要补充公开集群 CA。
- `deploy/systemd/`：独立管理机 Web 模板；启用签发还需独立运行 controller。
- 日常平台可以部署在 k8s；本地主机 SSH、离线应急 kubeconfig 和 BMC 必须独立保留。
- 不给当前阶段的平台挂载集群管理 kubeconfig 或 CA 私钥，也不向其授予 cluster-admin。

生产验收入口：[kubegrant.clusters.zjusct.io](https://kubegrant.clusters.zjusct.io)。2026-10-16 已通过 Argo CD 部署登录、授权记录与审计版本；外部 openng 接入已修复，并通过外部检查与浏览器登录页验证。用户已确认真实 admins 账号登录与管理员入口正常；生产 kubeconfig 签发仍未开放。版本及检查结果见 [部署记录](docs/deployment.md#8-首次生产发布与验收记录)。

## 结构

```text
cmd/kubegrant/       服务、备份与会话重置入口
internal/config/    配置及安全默认值
internal/identity/  FreeIPA 身份核验
internal/storage/   SQLite 身份、会话、授权与审计
internal/grant/     授权有效期与撤回规则
internal/httpapi/   登录、成员/管理员接口及权限校验
web/                前端
deploy/             k8s / systemd 模板
docs/               设计及部署恢复说明
```

产品决定见 [docs/design.md](docs/design.md)，领域术语见 [CONTEXT.md](CONTEXT.md)。所有修改在获得用户确认前不 commit、不 push。
