#!/usr/bin/env bash
# Requires a disposable kind cluster named kubegrant-e2e. Never reads the default
# kubeconfig and never prints the ServiceAccount token or member private keys.
set -euo pipefail
if [[ $# != 2 ]]; then
  echo 'Usage: test-cluster.sh /absolute/kind-admin.config /absolute/controller-e2e.test' >&2
  exit 2
fi
umask 077
admin_config=$1
test_binary=$2
context=$(kubectl --kubeconfig "$admin_config" config current-context)
if [[ "$context" != kind-kubegrant-e2e ]]; then
  echo 'Refusing a non-test kubeconfig' >&2
  exit 1
fi
runtime_dir=$(mktemp -d)
trap 'rm -rf "$runtime_dir"' EXIT
python3 - <<'PY' > "$runtime_dir/access.yaml"
from pathlib import Path
import hashlib
print('''apiVersion: v1
kind: Namespace
metadata:
  name: kubegrant
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: kubegrant-e2e-reader
rules:
  - apiGroups: [""]
    resources: [nodes]
    verbs: [get, list]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: kubegrant-e2e-foreign
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: kubegrant-e2e-reader
subjects:
  - kind: User
    name: kubegrant-e2e-foreign
    apiGroup: rbac.authorization.k8s.io
---''')
prod_instance=hashlib.sha256(b'zjusct').hexdigest()[:24]
instance=hashlib.sha256(b'cluster').hexdigest()[:24]
for name in ('rbac.yaml','admission.yaml'):
    print(Path('deploy/k8s-signing',name).read_text().replace('cluster-admin','kubegrant-e2e-reader').replace(prod_instance,instance))
    print('---')
PY
kubectl --kubeconfig "$admin_config" -n kubegrant apply -f "$runtime_dir/access.yaml"
kubectl --kubeconfig "$admin_config" -n kubegrant get configmap kube-root-ca.crt -o jsonpath='{.data.ca\.crt}' > "$runtime_dir/ca.crt"
kubectl --kubeconfig "$admin_config" -n kubegrant create token kubegrant-controller --duration=1h > "$runtime_dir/token"
export KUBEGRANT_E2E_API
KUBEGRANT_E2E_API=$(kubectl --kubeconfig "$admin_config" config view --minify -o jsonpath='{.clusters[0].cluster.server}')
export KUBEGRANT_E2E_CA="$runtime_dir/ca.crt"
export KUBEGRANT_E2E_TOKEN_FILE="$runtime_dir/token"
export KUBEGRANT_E2E_CONFIRM=kind-kubegrant-e2e
"$test_binary" -test.run '^TestRealClusterSigningRevocationAndAdmission$' -test.v
kubectl --kubeconfig "$admin_config" get validatingadmissionpolicies kubegrant-managed-bindings kubegrant-managed-csrs -o jsonpath='{range .items[*]}{.metadata.name}{" warnings="}{.status.typeChecking.expressionWarnings}{"\n"}{end}'
