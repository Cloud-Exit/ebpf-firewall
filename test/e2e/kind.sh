#!/usr/bin/env bash
set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-ebpf-firewall-e2e}"
APP_IMAGE="${APP_IMAGE:-localhost/ebpf-allowlist-firewall:dev}"
HTTP_IMAGE="${HTTP_IMAGE:-localhost/e2e-http-server:dev}"
KEEP_KIND_CLUSTER="${KEEP_KIND_CLUSTER:-false}"
KIND_CMD="${KIND_CMD:-kind}"
if [[ -z "${RESPECT_KIND_ALIAS:-}" ]]; then
  if [[ -n "${CI:-}" ]]; then
    RESPECT_KIND_ALIAS=false
  else
    RESPECT_KIND_ALIAS=true
  fi
fi

require() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

dump_debug() {
  set +e
  echo "e2e failed; dumping Kubernetes diagnostics" >&2
  kubectl get nodes -o wide >&2
  kubectl get pods -A -o wide >&2
  kubectl -n ebpf-firewall describe daemonset/ebpf-firewall >&2
  kubectl -n ebpf-firewall describe pods -l app.kubernetes.io/name=ebpf-firewall >&2
  kubectl -n ebpf-firewall logs -l app.kubernetes.io/name=ebpf-firewall --all-containers --tail=200 >&2
  kubectl -n ebpf-firewall logs -l app.kubernetes.io/name=ebpf-firewall --all-containers --previous --tail=200 >&2
  kubectl -n ebpf-firewall get events --sort-by=.lastTimestamp >&2
  cat >&2 <<'EOF'

If ebpf-firewall logs contain "map create: operation not permitted", the Kind node
container cannot create eBPF maps. This usually happens with rootless Podman or
another unprivileged container runtime. Run this e2e test with rootful Docker or
rootful Podman so the Kind node container can pass BPF privileges to the
privileged DaemonSet pod.

EOF
  kubectl -n e2e describe deployment/allowlist-server >&2
  kubectl -n e2e describe pods -l app=allowlist-server >&2
  kubectl -n e2e logs -l app=allowlist-server --all-containers --tail=100 >&2
  kubectl -n e2e get events --sort-by=.lastTimestamp >&2
  set -e
}

cleanup() {
  if [[ "$KEEP_KIND_CLUSTER" != "true" ]]; then
    kind_cmd delete cluster --name "$CLUSTER_NAME" >/dev/null 2>&1 || true
  fi
}

finish() {
  local status=$?
  if [[ "$status" -ne 0 ]]; then
    dump_debug
  fi
  cleanup
  exit "$status"
}

kind_cmd() {
  if [[ "$RESPECT_KIND_ALIAS" == "true" && "$KIND_CMD" == "kind" ]]; then
    local quoted_args=()
    printf -v quoted_args[0] "%q" "kind"
    local arg
    for arg in "$@"; do
      printf -v quoted_args[${#quoted_args[@]}] "%q" "$arg"
    done

    "${SHELL:-/bin/sh}" -ic "${quoted_args[*]}"
    return
  fi

  # shellcheck disable=SC2086
  $KIND_CMD "$@"
}

require docker
require kubectl
require helm

trap finish EXIT

kind_cmd delete cluster --name "$CLUSTER_NAME" >/dev/null 2>&1 || true
kind_cmd create cluster --name "$CLUSTER_NAME" --config test/e2e/kind-cluster.yaml

docker build -t "$APP_IMAGE" .
docker build -t "$HTTP_IMAGE" test/e2e/http-server
kind_cmd load docker-image --name "$CLUSTER_NAME" "$APP_IMAGE"
kind_cmd load docker-image --name "$CLUSTER_NAME" "$HTTP_IMAGE"

sed "s|image: e2e-http-server:dev|image: ${HTTP_IMAGE}|g" test/e2e/fixtures.yaml | kubectl apply -f -
echo "waiting for e2e allowlist-server deployment"
kubectl -n e2e rollout status deployment/allowlist-server --timeout=120s
echo "waiting for e2e protected-server daemonset"
kubectl -n e2e rollout status daemonset/protected-server --timeout=120s

kubectl -n e2e run e2e-client \
  --restart=Never \
  --image="$HTTP_IMAGE" \
  --image-pull-policy=IfNotPresent \
  --overrides="{\"spec\":{\"nodeName\":\"${CLUSTER_NAME}-worker\"}}" \
  --env="LISTEN_ADDR=127.0.0.1:18081"
kubectl -n e2e wait --for=condition=Ready pod/e2e-client --timeout=120s

helm upgrade --install ebpf-firewall charts/ebpf-firewall \
  --namespace ebpf-firewall \
  --create-namespace \
  --set image.repository="${APP_IMAGE%:*}" \
  --set image.tag="${APP_IMAGE##*:}" \
  --set-string config.sourceUrl="http://allowlist-server.e2e.svc.cluster.local:8080/allowlist.txt" \
  --set-string config.protectedPorts="18080" \
  --set-string config.interfaceGlobs='eth0\,cni0\,veth*' \
  --set-string config.refreshInterval="2s" \
  --set-string config.maxEntries="32"

echo "waiting for ebpf-firewall daemonset"
kubectl -n ebpf-firewall rollout status daemonset/ebpf-firewall --timeout=120s
sleep 8

NODE_IP="$(kubectl get node "$CLUSTER_NAME-worker" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')"

kubectl -n e2e exec e2e-client -- /e2e-http-server \
  --client-url="http://${NODE_IP}:18080" \
  --expect-body="protected-ok"

kubectl -n e2e create configmap allowlist \
  --from-literal=allowlist.txt="203.0.113.1/32" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl -n e2e rollout restart deployment/allowlist-server
kubectl -n e2e rollout status deployment/allowlist-server --timeout=120s

sleep 8

kubectl -n e2e exec e2e-client -- /e2e-http-server \
  --client-url="http://${NODE_IP}:18080" \
  --expect-failure

echo "kind e2e passed"
