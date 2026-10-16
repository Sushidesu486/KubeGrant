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
# Admission policy watches are asynchronous. Probe actual enforcement without
# mutating the foreign binding before running assertions or signing anything.
python3 - <<'PY'
import ipaddress, json, os, pathlib, ssl, time, urllib.error, urllib.parse, urllib.request
endpoint = os.environ['KUBEGRANT_E2E_API']
if not ipaddress.ip_address(urllib.parse.urlsplit(endpoint).hostname).is_loopback:
    raise SystemExit('Refusing a non-loopback test API')
context = ssl.create_default_context(cafile=os.environ['KUBEGRANT_E2E_CA'])
headers = {'Authorization': 'Bearer ' + pathlib.Path(os.environ['KUBEGRANT_E2E_TOKEN_FILE']).read_text().strip(), 'Content-Type': 'application/json'}
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
url = endpoint + '/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/kubegrant-e2e-foreign'
with opener.open(urllib.request.Request(url, headers=headers), timeout=5) as response:
    uid = json.load(response)['metadata']['uid']
body = json.dumps({'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {'uid': uid}}).encode()
deadline = time.monotonic() + 30
while True:
    try:
        request = urllib.request.Request(url + '?dryRun=All', data=body, headers=headers, method='DELETE')
        with opener.open(request, timeout=5) as response:
            response.read()
    except urllib.error.HTTPError as error:
        message = error.read().decode()
        if error.code in (403, 422) and 'kubegrant-managed-bindings' in message:
            print('PASS: admission enforcement observed with a dry-run deletion')
            break
        raise SystemExit('Unexpected admission probe response: HTTP ' + str(error.code))
    if time.monotonic() >= deadline:
        raise SystemExit('Admission did not enforce the binding policy within 30 seconds')
    time.sleep(0.2)
PY
"$test_binary" -test.run '^TestRealClusterSigningRevocationAndAdmission$' -test.v
kubectl --kubeconfig "$admin_config" get validatingadmissionpolicies kubegrant-managed-bindings kubegrant-managed-csrs -o jsonpath='{range .items[*]}{.metadata.name}{" warnings="}{.status.typeChecking.expressionWarnings}{"\n"}{end}'
