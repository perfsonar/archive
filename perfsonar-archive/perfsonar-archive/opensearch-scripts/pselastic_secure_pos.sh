#!/bin/bash

OPENSEARCH_CONFIG_DIR=/etc/opensearch
OPENSEARCH_SECURITY_PLUGIN=/usr/share/opensearch/plugins/opensearch-security
OPENSEARCH_SECURITY_CONFIG=${OPENSEARCH_CONFIG_DIR}/opensearch-security
PASSWORD_FILE=/etc/perfsonar/opensearch/auth_setup.out

# Run securityadmin to enact permission changes
OPENSEARCH_JAVA_HOME=/usr/share/opensearch/jdk bash ${OPENSEARCH_SECURITY_PLUGIN}/tools/securityadmin.sh -cd ${OPENSEARCH_SECURITY_CONFIG} -icl -nhnv -cacert ${OPENSEARCH_CONFIG_DIR}/root-ca.pem -cert ${OPENSEARCH_CONFIG_DIR}/admin.pem -key ${OPENSEARCH_CONFIG_DIR}/admin-key.pem

# Get password for admin user
ADMIN_PASS=$(grep -w "admin" $PASSWORD_FILE | head -n 1 | awk '{print $2}')
if [ $? -ne 0 ]; then
    echo "Failed to parse password"
    exit 1
elif [ -z "$ADMIN_PASS" ]; then
    echo "Unable to find admin password in $PASSWORD_FILE. Exiting."
    exit 1
fi

echo "Waiting for opensearch API to start..."
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
# Check if the policy already exists
policy_status=$(curl -s -o /dev/null -w "%{http_code}" -u admin:${ADMIN_PASS} -k https://localhost:9200/_plugins/_ism/policies/pscheduler_default_policy)
if [ $policy_status -ne 200 ]; then
    echo "[Create pscheduler policy]"
    # Create index policy
    curl -k -u admin:${ADMIN_PASS} -H 'Content-Type: application/json' -X PUT "https://localhost:9200/_plugins/_ism/policies/pscheduler_default_policy" -d "@/usr/lib/perfsonar/archive/config/ilm/install/pscheduler_default_policy.json" 2>/dev/null
    echo -e "\n[Applying policy]"
    # Apply policy to index
    curl -k -u admin:${ADMIN_PASS} -H 'Content-Type: application/json' -X POST "https://localhost:9200/_plugins/_ism/add/pscheduler*" -d '{ "policy_id": "pscheduler_default_policy" }' 2>/dev/null
    echo -e "\n[DONE]"
    echo ""
fi

# Configure index state management (ISM) policy for prometheus indices
# Check if the policy already exists
policy_status=$(curl -s -o /dev/null -w "%{http_code}" -u admin:${ADMIN_PASS} -k https://localhost:9200/_plugins/_ism/policies/prometheus_default_policy)
if [ $policy_status -ne 200 ]; then
    echo "[Create prometheus policy]"
    # Create index policy
    curl -k -u admin:${ADMIN_PASS} -H 'Content-Type: application/json' -X PUT "https://localhost:9200/_plugins/_ism/policies/prometheus_default_policy" -d "@/usr/lib/perfsonar/archive/config/ilm/install/prometheus_default_policy.json" 2>/dev/null
    echo -e "\n[Applying policy]"
    # Apply policy to index
    curl -k -u admin:${ADMIN_PASS} -H 'Content-Type: application/json' -X POST "https://localhost:9200/_plugins/_ism/add/prometheus*" -d '{ "policy_id": "prometheus_default_policy" }' 2>/dev/null
    echo -e "\n[DONE]"
    echo ""
fi

# Configure index template for pscheduler index patterns
echo "[Create pscheduler template]"
# Update template
curl -k -u admin:${ADMIN_PASS} -s -H 'Content-Type: application/json' -XPUT "https://localhost:9200/_index_template/pscheduler_default_policy" -d @/usr/lib/perfsonar/archive/config/index_template-pscheduler.json
echo ""
status=$(curl -k -u admin:${ADMIN_PASS} -s -o /dev/null -w "%{http_code}" -H "Content-Type: application/json" -XPUT "https://localhost:9200/pscheduler*/_settings" -d '{"index" : {"number_of_replicas" : 0}}')
if [ $status -eq 200 ]; then
    echo "[Index pscheduler updated successfully]"
fi
echo -e "\n[DONE]"
echo ""

# Configure index template for prometheus index patterns
echo "[Create prometheus template]"
# Update template
echo ""
curl -k -u admin:${ADMIN_PASS} -s -H 'Content-Type: application/json' -XPUT "https://localhost:9200/_index_template/prometheus_template" -d @/usr/lib/perfsonar/archive/config/index_template-prometheus.json
echo -e "\n[DONE]"
echo ""

# Disabling opensearch internal indexes replicas
echo "[Update internal indexes]"
# Configure index template for security-auditlog index pattern
curl -k -u admin:${ADMIN_PASS} -s -H 'Content-Type: application/json' -XPUT "https://localhost:9200/_index_template/auditlog" -d @/usr/lib/perfsonar/archive/config/index_template-auditlog.json
echo ""
status=$(curl -k -u admin:${ADMIN_PASS} -s -o /dev/null -w "%{http_code}" -H "Content-Type: application/json" -XPUT "https://localhost:9200/security-auditlog*/_settings" -d '{"index" : {"number_of_replicas" : 0}}')
if [ $status -eq 200 ]; then
    echo "[Index security-auditlog updated successfully]"
fi

# Configure index template for opendistro-ism index pattern
curl -k -u admin:${ADMIN_PASS} -s -H 'Content-Type: application/json' -XPUT "https://localhost:9200/_index_template/opendistro_ism" -d @/usr/lib/perfsonar/archive/config/index_template-opendistro-ism.json
echo ""
status=$(curl -k -u admin:${ADMIN_PASS} -s -o /dev/null -w "%{http_code}" -H "Content-Type: application/json" -XPUT "https://localhost:9200/.opendistro-ism-managed-index-history*/_settings" -d '{"index" : {"number_of_replicas" : 0}}')
if [ $status -eq 200 ]; then
    echo "[Index opendistro-ism-managed-index-history updated successfully]"
fi
echo -e "\n[DONE]"
echo ""