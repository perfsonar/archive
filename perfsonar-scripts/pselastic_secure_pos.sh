#!/bin/bash

#OPENDISTRO_SECURITY_PLUGIN=/usr/share/elasticsearch/plugins/opendistro_security
#ELASTIC_CONFIG_DIR=/etc/elasticsearch

# Apply Pre Script Changes
#bash ${OPENDISTRO_SECURITY_PLUGIN}/tools/securityadmin.sh -cd ${OPENDISTRO_SECURITY_PLUGIN}/securityconfig -icl -nhnv -cacert ${ELASTIC_CONFIG_DIR}/root-ca.pem -cert ${ELASTIC_CONFIG_DIR}/admin.pem -key ${ELASTIC_CONFIG_DIR}/admin-key.pem

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

echo "Waiting elasticsearch API to start..."
api_status=$(curl -s -o /dev/null -w "%{http_code}" -u admin:${ADMIN_PASS} -k https://localhost:9200/_cluster/health)
i=0
while [[ $api_status -ne 200 ]]
do
    sleep 1
    ((i++))
    # Wait a maximum of 100 seconds for the API to start
    if [[ $i -eq 100 ]]; then
        echo "[ERROR] API start timeout"
        exit 1
    fi
    api_status=$(curl -s -o /dev/null -w "%{http_code}" -u admin:${ADMIN_PASS} -k https://localhost:9200/_cluster/health)
done

echo "API started!"

# Configure index state management (ISM) policy for pscheduler indices
echo "[Create policy]"
# Create index policy
curl -k -u admin:${ADMIN_PASS} -H 'Content-Type: application/json' -X PUT "https://localhost:9200/_opendistro/_ism/policies/pscheduler_default_policy" -d "@/usr/lib/perfsonar/archive/pselastic_setup/conf.d/ilm/install/pscheduler_default_policy.json" 2>/dev/null
echo -e "\n[Applying policy]"
# Apply policy to index
curl -k -u admin:${ADMIN_PASS} -H 'Content-Type: application/json' -X POST "https://localhost:9200/_opendistro/_ism/add/pscheduler*" -d '{ "policy_id": "pscheduler_default_policy" }' 2>/dev/null
echo -e "\n[DONE]"
echo ""

# Configure index template for pscheduler index patterns
echo "[Create template]"
# Update template
curl -k -u admin:${ADMIN_PASS} -H 'Content-Type: application/json' -XPUT "https://localhost:9200/_index_template/pscheduler" -d @/etc/perfsonar/logstash/index_template-pscheduler.json
echo -e "\n[DONE]"
echo ""
