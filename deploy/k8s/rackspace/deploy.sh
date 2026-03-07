#!/usr/bin/env bash
set -euo pipefail

# Conduit Stress Test — Kubernetes Deployment Script
#
# Prerequisites:
#   - kubectl configured for your Rackspace cluster
#   - Docker images built and available (or use local registry)
#   - Nodes labeled: conduit-role=proxy and conduit-role=loadgen
#
# Usage:
#   ./deploy.sh setup              # Label nodes, apply tuning, deploy infra + seed
#   ./deploy.sh build-push         # Build and push Docker images
#   ./deploy.sh seed               # Re-run seed job (threat feeds, categories)
#   ./deploy.sh run [TIER]         # Run a stress test (default: medium)
#   ./deploy.sh logs               # Stream k6 job logs
#   ./deploy.sh results            # Fetch results from k6 pod
#   ./deploy.sh metrics            # Curl proxy metrics
#   ./deploy.sh teardown           # Delete everything

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${SCRIPT_DIR}/../../.."
NAMESPACE="conduit-stress"

cmd="${1:-help}"
shift || true

case "$cmd" in
  setup)
    echo "=== Setting up cluster ==="

    # Get node names
    NODES=($(kubectl get nodes -o jsonpath='{.items[*].metadata.name}'))
    if [ ${#NODES[@]} -lt 2 ]; then
      echo "Warning: Only ${#NODES[@]} node(s) found. Need 2 for proper isolation."
      echo "Labeling single node with both roles."
      kubectl label node "${NODES[0]}" conduit-role=proxy --overwrite
      kubectl label node "${NODES[0]}" conduit-role=loadgen --overwrite
    else
      echo "Labeling ${NODES[0]} as proxy node"
      kubectl label node "${NODES[0]}" conduit-role=proxy --overwrite
      echo "Labeling ${NODES[1]} as loadgen node"
      kubectl label node "${NODES[1]}" conduit-role=loadgen --overwrite
    fi

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

    # Deploy proxy
    echo "Deploying conduit-proxy..."
    kubectl apply -f "${SCRIPT_DIR}/proxy.yaml"
    kubectl -n "$NAMESPACE" rollout status deployment/conduit-proxy --timeout=120s

    # Deploy k6 scripts
    kubectl apply -f "${SCRIPT_DIR}/k6-configmap.yaml"

    # Seed Dragonfly (threat feeds, etc.)
    echo "Seeding Dragonfly..."
    kubectl -n "$NAMESPACE" delete job seed-dragonfly --ignore-not-found
    kubectl apply -f "${SCRIPT_DIR}/seed-job.yaml"
    kubectl -n "$NAMESPACE" wait --for=condition=complete job/seed-dragonfly --timeout=120s && \
      echo "Seed complete" || echo "Seed job may still be running — check: kubectl -n $NAMESPACE logs job/seed-dragonfly"

    echo ""
    echo "=== Setup complete ==="
    echo ""
    kubectl -n "$NAMESPACE" get pods -o wide
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

    # Build proxy
    docker build --target proxy -t "${REGISTRY}/conduit-proxy:latest" .
    docker push "${REGISTRY}/conduit-proxy:latest"

    # Build API
    docker build --target api -t "${REGISTRY}/conduit-api:latest" .
    docker push "${REGISTRY}/conduit-api:latest"

    # Build mock
    docker build -f deploy/k8s/rackspace/Dockerfile.mock -t "${REGISTRY}/conduit-mock:latest" .
    docker push "${REGISTRY}/conduit-mock:latest"

    echo "Images pushed to ${REGISTRY}"

    # Update deployments to use registry images
    kubectl -n "$NAMESPACE" set image deployment/conduit-proxy proxy="${REGISTRY}/conduit-proxy:latest"
    kubectl -n "$NAMESPACE" set image deployment/conduit-api api="${REGISTRY}/conduit-api:latest"
    kubectl -n "$NAMESPACE" set image deployment/mock-upstream mock="${REGISTRY}/conduit-mock:latest"
    ;;

  run)
    TIER="${1:-medium}"
    JOB_NAME="k6-stress-${TIER}"

    # Delete previous job if exists
    kubectl -n "$NAMESPACE" delete job "$JOB_NAME" --ignore-not-found

    echo "Starting stress test: tier=${TIER}"
    export STRESS_TIER="$TIER"
    envsubst < "${SCRIPT_DIR}/k6-job.yaml" | kubectl apply -f -

    echo "Streaming logs (Ctrl+C to detach, test continues)..."
    sleep 5
    kubectl -n "$NAMESPACE" logs -f "job/${JOB_NAME}" || true
    ;;

  logs)
    TIER="${1:-medium}"
    kubectl -n "$NAMESPACE" logs -f "job/k6-stress-${TIER}"
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
    kubectl -n "$NAMESPACE" exec deployment/conduit-proxy -- \
      curl -s http://localhost:9091/metrics
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
    echo "=== Node Labels ==="
    kubectl get nodes --show-labels | grep conduit-role || echo "No nodes labeled"
    ;;

  teardown)
    echo "Tearing down conduit-stress namespace..."
    kubectl delete namespace "$NAMESPACE" --ignore-not-found
    echo "Removing node labels..."
    for node in $(kubectl get nodes -o jsonpath='{.items[*].metadata.name}'); do
      kubectl label node "$node" conduit-role- 2>/dev/null || true
    done
    echo "Done."
    ;;

  help|*)
    echo "Usage: ./deploy.sh <command> [args]"
    echo ""
    echo "Commands:"
    echo "  setup              Label nodes, apply tuning, deploy all + seed"
    echo "  build-push         Build and push Docker images (set REGISTRY env var)"
    echo "  seed               Re-run Dragonfly seed (threat feeds, categories)"
    echo "  run [TIER]         Run stress test (smoke|small|medium|large|enterprise)"
    echo "  logs [TIER]        Stream k6 job logs"
    echo "  results [TIER]     Copy results from k6 pod"
    echo "  metrics            Fetch Prometheus metrics from proxy"
    echo "  status             Show all resources"
    echo "  teardown           Delete everything"
    ;;
esac
