#!/bin/bash

PASSWORD_FILE=/etc/perfsonar/elastic/auth_setup.out
# Get password for admin user
ADMIN_PASS=$(grep "admin " $PASSWORD_FILE | head -n 1 | sed 's/^admin //')
if [ $? -ne 0 ]; then
    echo "Failed to parse password"
    exit 1
elif [ -z "$ADMIN_PASS" ]; then
    echo "Unable to find admin password in $PASSWORD_FILE. Exiting."
    exit 1
fi

# Configure index state management (ISM) policy for pscheduler indices
echo "[Create policy]"
# Create index policy
curl -v -k -u admin:${ADMIN_PASS} -H 'Content-Type: application/json' -X PUT "https://localhost:9200/_opendistro/_ism/policies/policy_1" -d "@/usr/lib/perfsonar/archive/pselastic_setup/conf.d/ilm/install/pscheduler_default_policy.json"
echo "[Applying policy]"
# Apply policy to index
curl -v -k -u admin:${ADMIN_PASS} -H 'Content-Type: application/json' -X POST "https://localhost:9200/_opendistro/_ism/add/pscheduler*" -d '{ "policy_id": "policy_1" }'
echo "[DONE]"
echo ""
