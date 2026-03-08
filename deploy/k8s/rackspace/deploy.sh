#!/usr/bin/env bash
set -euo pipefail

# Conduit Multi-Node Deployment Script
#
# Deploys N stateless proxy replicas behind a cloud LoadBalancer.
# All pods schedule freely (no node selectors). Shared state lives in Dragonfly.
#
# Prerequisites:
#   - kubectl configured for your cluster
#   - Docker images built and available
#
# Usage:
#   ./deploy.sh setup              # Deploy infra + proxy (3 replicas) + seed
#   ./deploy.sh build-push         # Build and push Docker images
#   ./deploy.sh seed               # Re-run seed job (threat feeds, categories)
#   ./deploy.sh scale N            # Scale proxy to N replicas
#   ./deploy.sh lb-ip              # Get the external LoadBalancer IP
#   ./deploy.sh run [TIER]         # Run a stress test (default: medium)
#   ./deploy.sh logs [proxy|k6]    # Stream logs
#   ./deploy.sh results            # Fetch results from k6 pod
#   ./deploy.sh metrics            # Curl proxy metrics (all pods)
#   ./deploy.sh teardown           # Delete everything

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${SCRIPT_DIR}/../../.."
NAMESPACE="conduit-stress"

cmd="${1:-help}"
shift || true

case "$cmd" in
  setup)
    echo "=== Deploying Conduit (multi-node) ==="

    # Create namespace
    kubectl apply -f "${SCRIPT_DIR}/namespace.yaml"

    # Apply node tuning
    echo "Applying OS tuning..."
    kubectl apply -f "${SCRIPT_DIR}/node-tuning.yaml"
    echo "Waiting for tuning to apply..."
    kubectl -n "$NAMESPACE" rollout status daemonset/node-tuning --timeout=60s

    # Deploy Dragonfly
    echo "Deploying Dragonfly..."
    kubectl apply -f "${SCRIPT_DIR}/dragonfly.yaml"
    kubectl -n "$NAMESPACE" rollout status deployment/dragonfly --timeout=120s

    # Deploy config
    kubectl apply -f "${SCRIPT_DIR}/conduit-config.yaml"

    # Deploy mock upstream
    echo "Deploying mock upstream..."
    kubectl apply -f "${SCRIPT_DIR}/mock-upstream.yaml"
    kubectl -n "$NAMESPACE" rollout status deployment/mock-upstream --timeout=60s

    # Deploy API
    echo "Deploying conduit-api..."
    kubectl apply -f "${SCRIPT_DIR}/api.yaml"
    kubectl -n "$NAMESPACE" rollout status deployment/conduit-api --timeout=120s

    # Deploy proxy (3 replicas behind LoadBalancer)
    echo "Deploying conduit-proxy (3 replicas)..."
    kubectl apply -f "${SCRIPT_DIR}/proxy.yaml"
    kubectl -n "$NAMESPACE" rollout status deployment/conduit-proxy --timeout=120s

    # Deploy k6 scripts
    kubectl apply -f "${SCRIPT_DIR}/k6-configmap.yaml"

    # Seed Dragonfly
    echo "Seeding Dragonfly..."
    kubectl -n "$NAMESPACE" delete job seed-dragonfly --ignore-not-found
    kubectl apply -f "${SCRIPT_DIR}/seed-job.yaml"
    kubectl -n "$NAMESPACE" wait --for=condition=complete job/seed-dragonfly --timeout=120s && \
      echo "Seed complete" || echo "Seed job may still be running — check: kubectl -n $NAMESPACE logs job/seed-dragonfly"

    echo ""
    echo "=== Setup complete ==="
    echo ""
    kubectl -n "$NAMESPACE" get pods -o wide
    echo ""
    echo "Waiting for LoadBalancer IP..."
    for i in $(seq 1 30); do
      LB_IP=$(kubectl -n "$NAMESPACE" get svc conduit-proxy -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || true)
      if [ -n "$LB_IP" ]; then
        echo "LoadBalancer IP: $LB_IP"
        echo "  Proxy:   http://${LB_IP}:8888"
        echo "  API:     http://${LB_IP}:8443"
        break
      fi
      sleep 2
    done
    [ -z "${LB_IP:-}" ] && echo "LB IP not assigned yet. Run: ./deploy.sh lb-ip"
    ;;

  seed)
    echo "Seeding Dragonfly..."
    kubectl -n "$NAMESPACE" delete job seed-dragonfly --ignore-not-found
    kubectl apply -f "${SCRIPT_DIR}/seed-job.yaml"
    echo "Waiting for seed to complete..."
    kubectl -n "$NAMESPACE" logs -f job/seed-dragonfly
    ;;

  build-push)
    REGISTRY="${REGISTRY:-}"
    if [ -z "$REGISTRY" ]; then
      echo "Set REGISTRY env var to your container registry (e.g., REGISTRY=myregistry.io/conduit)"
      echo "Or load images directly into nodes with: docker save | ssh node docker load"
      exit 1
    fi

    echo "Building images..."
    cd "$REPO_ROOT"

    docker build --target proxy -t "${REGISTRY}/conduit-proxy:latest" .
    docker push "${REGISTRY}/conduit-proxy:latest"

    docker build --target api -t "${REGISTRY}/conduit-api:latest" .
    docker push "${REGISTRY}/conduit-api:latest"

    docker build -f deploy/k8s/rackspace/Dockerfile.mock -t "${REGISTRY}/conduit-mock:latest" .
    docker push "${REGISTRY}/conduit-mock:latest"

    echo "Images pushed to ${REGISTRY}"

    kubectl -n "$NAMESPACE" set image deployment/conduit-proxy proxy="${REGISTRY}/conduit-proxy:latest"
    kubectl -n "$NAMESPACE" set image deployment/conduit-api api="${REGISTRY}/conduit-api:latest"
    kubectl -n "$NAMESPACE" set image deployment/mock-upstream mock="${REGISTRY}/conduit-mock:latest"
    ;;

  scale)
    REPLICAS="${1:?Usage: ./deploy.sh scale N}"
    echo "Scaling conduit-proxy to ${REPLICAS} replicas..."
    kubectl -n "$NAMESPACE" scale deployment/conduit-proxy --replicas="$REPLICAS"
    kubectl -n "$NAMESPACE" rollout status deployment/conduit-proxy --timeout=120s
    echo ""
    kubectl -n "$NAMESPACE" get pods -l app=conduit-proxy -o wide
    ;;

  lb-ip)
    LB_IP=$(kubectl -n "$NAMESPACE" get svc conduit-proxy -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || true)
    if [ -n "$LB_IP" ]; then
      echo "LoadBalancer IP: $LB_IP"
      echo "  Proxy:   http://${LB_IP}:8888"
      echo "  API:     http://${LB_IP}:8443"
      echo ""
      echo "Test:  curl -x http://${LB_IP}:8888 http://example.com"
    else
      echo "No external IP assigned yet. Check: kubectl -n $NAMESPACE get svc conduit-proxy"
    fi
    ;;

  run)
    TIER="${1:-medium}"
    JOB_NAME="k6-stress-${TIER}"

    kubectl -n "$NAMESPACE" delete job "$JOB_NAME" --ignore-not-found

    echo "Starting stress test: tier=${TIER}"
    export STRESS_TIER="$TIER"
    envsubst < "${SCRIPT_DIR}/k6-job.yaml" | kubectl apply -f -

    echo "Streaming logs (Ctrl+C to detach, test continues)..."
    sleep 5
    kubectl -n "$NAMESPACE" logs -f "job/${JOB_NAME}" || true
    ;;

  logs)
    TARGET="${1:-proxy}"
    case "$TARGET" in
      proxy)
        echo "=== Logs from all proxy pods ==="
        kubectl -n "$NAMESPACE" logs -l app=conduit-proxy --all-containers --prefix --tail=100 -f
        ;;
      k6)
        TIER="${2:-medium}"
        kubectl -n "$NAMESPACE" logs -f "job/k6-stress-${TIER}"
        ;;
      *)
        kubectl -n "$NAMESPACE" logs -l "app=${TARGET}" --all-containers --prefix --tail=100 -f
        ;;
    esac
    ;;

  results)
    TIER="${1:-medium}"
    POD=$(kubectl -n "$NAMESPACE" get pods -l job-name="k6-stress-${TIER}" -o jsonpath='{.items[0].metadata.name}')
    echo "Fetching results from ${POD}..."
    mkdir -p "${SCRIPT_DIR}/results"
    kubectl -n "$NAMESPACE" cp "${POD}:/results/" "${SCRIPT_DIR}/results/${TIER}/" 2>/dev/null || \
      echo "No results dir found — check if the test completed"
    echo "Results saved to ${SCRIPT_DIR}/results/${TIER}/"
    ;;

  metrics)
    echo "=== Metrics from all proxy pods ==="
    for POD in $(kubectl -n "$NAMESPACE" get pods -l app=conduit-proxy -o jsonpath='{.items[*].metadata.name}'); do
      echo "--- ${POD} ---"
      kubectl -n "$NAMESPACE" exec "$POD" -- curl -s http://localhost:9091/metrics | grep -E '^(conduit_|# TYPE conduit_)' | head -30
      echo ""
    done
    ;;

  status)
    echo "=== Pods ==="
    kubectl -n "$NAMESPACE" get pods -o wide
    echo ""
    echo "=== Services ==="
    kubectl -n "$NAMESPACE" get svc
    echo ""
    echo "=== Jobs ==="
    kubectl -n "$NAMESPACE" get jobs
    echo ""
    echo "=== Proxy Replicas ==="
    kubectl -n "$NAMESPACE" get deployment conduit-proxy
    ;;

  teardown)
    echo "Tearing down conduit-stress namespace..."
    kubectl delete namespace "$NAMESPACE" --ignore-not-found
    echo "Done."
    ;;

  help|*)
    echo "Usage: ./deploy.sh <command> [args]"
    echo ""
    echo "Commands:"
    echo "  setup              Deploy all components (3 proxy replicas behind LB)"
    echo "  build-push         Build and push Docker images (set REGISTRY env var)"
    echo "  seed               Re-run Dragonfly seed (threat feeds, categories)"
    echo "  scale N            Scale proxy to N replicas"
    echo "  lb-ip              Show the external LoadBalancer IP"
    echo "  run [TIER]         Run stress test (smoke|small|medium|large|enterprise)"
    echo "  logs [proxy|k6]    Stream logs from proxy pods or k6 job"
    echo "  results [TIER]     Copy results from k6 pod"
    echo "  metrics            Fetch metrics from all proxy pods"
    echo "  status             Show all resources"
    echo "  teardown           Delete everything"
    ;;
esac
