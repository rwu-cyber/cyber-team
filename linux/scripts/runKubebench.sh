#!/bin/bash

DIR=$(dirname "$0")
JOB_NAME="kube-bench"

# Apply the job
kubectl apply -f "$DIR/job.yaml"

# Wait for pod to start and complete
POD=$(kubectl get pods -l app=$JOB_NAME -o jsonpath="{.items[0].metadata.name}")
kubectl wait --for=condition=complete pod/$POD --timeout=120s

# Get logs
kubectl logs $POD
