#!/usr/bin/env bash

KUBECONFIG="admin-kubeconfig.yaml"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_FILE="secrets-dump-${TIMESTAMP}.yaml"

echo " Dumping all secrets from cluster..."
echo "Using kubeconfig: $KUBECONFIG"
echo "Output file: $OUTPUT_FILE"

kubectl --kubeconfig=$KUBECONFIG get secrets -A -o yaml > "$OUTPUT_FILE"

if [ $? -eq 0 ]; then
    echo "Success! Secrets saved to $OUTPUT_FILE"
    echo "Total secrets found: $(kubectl --kubeconfig=$KUBECONFIG get secrets -A --no-headers | wc -l)"
    echo "File size: $(ls -lh $OUTPUT_FILE | awk '{print $5}')"
else
    echo "Failed to dump secrets. Check kubeconfig and connectivity."
fi
