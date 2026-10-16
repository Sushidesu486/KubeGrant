# KubeGrant

KubeGrant 管理成员的 Kubernetes 集群访问授权，并提供 kubeconfig 领取入口。

## Language

**管理员（Administrator）**：为成员分配集群访问权限与有效期的人。

**成员（Member）**：获得访问授权、登录平台并领取 kubeconfig 的人。

**身份来源（Identity Provider）**：管理成员账号并核验其登录身份的外部系统。
_Avoid_：用“授权管理”指代身份核验。

**授权（Grant）**：管理员授予某成员的集群访问许可，记录该许可的权限范围与有效期。
_Avoid_：用“kubeconfig”或“凭据”指代授权本身。
