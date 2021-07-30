#!/bin/bash

# Configure index state management (ISM) policy for pscheduler indices
echo "[Configure policy]"
echo ${ADMIN_PASS}
echo "[Trying to start elastic]"
echo "[Status 1]"
systemctl status elasticsearch
echo "[Start]"
systemctl start elasticsearch
echo "[Sleeping]"
sleep 100
echo "[Status 2]"
systemctl status elasticsearch
echo "[Trying to create policy]"
# Create policy
curl -v -k -u admin:${ADMIN_PASS} -H 'Content-Type: application/json' -X PUT "https://localhost:9200/_opendistro/_ism/policies/policy_1" -d "@/usr/lib/perfsonar/archive/pselastic_setup/conf.d/ilm/install/pscheduler_default_policy.json"
echo "[Applying policy]"
# Apply policy to index
curl -v -k -u admin:${ADMIN_PASS} -H 'Content-Type: application/json' -X POST "https://localhost:9200/_opendistro/_ism/add/pscheduler*" -d '{ "policy_id": "policy_1" }'
echo "[DONE]"
echo ""
