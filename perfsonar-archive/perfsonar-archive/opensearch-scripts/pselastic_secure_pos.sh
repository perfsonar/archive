#!/bin/bash

OPENSEARCH_CONFIG_DIR=/etc/opensearch
OPENSEARCH_SECURITY_PLUGIN=/usr/share/opensearch/plugins/opensearch-security
OPENSEARCH_SECURITY_CONFIG=${OPENSEARCH_CONFIG_DIR}/opensearch-security
PASSWORD_FILE=/etc/perfsonar/opensearch/auth_setup.out


# Update Existing roles - remove after 5.1.0 EOL
LOGSTASH_USER=pscheduler_logstash
echo "[Update prometheus roles]"
grep "prometheus" $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
if [ $? -eq 0 ]; then
    echo "Role already created"
else
    # pscheduler_logstash
    echo "[Creating $LOGSTASH_USER role]"
    echo | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "$LOGSTASH_USER:" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "  cluster_permissions:" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "    - 'cluster_monitor'" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "    - 'cluster_manage_index_templates'" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "  index_permissions:" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "    - index_patterns:" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "      - 'pscheduler_*'" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "      - 'prometheus_*'" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "      allowed_actions:" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "      - 'write'" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "      - 'read'" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "      - 'delete'" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "      - 'create_index'" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "      - 'manage'" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "      - 'indices:admin/template/delete'" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "      - 'indices:admin/template/get'" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "      - 'indices:admin/template/put'" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null

    # pscheduler_reader => read-only access to the pscheduler indices
    echo "[Creating pscheduler_reader role]"
    echo | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "pscheduler_reader:" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "  reserved: true" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "  index_permissions:" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "    - index_patterns:" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "      - 'pscheduler*'" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "      - 'prometheus*'" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "      allowed_actions:" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "      - 'read'" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "      - 'indices:admin/mappings/get'" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null

    # pscheduler_writer => write-only access to the pscheduler indices
    echo "[Creating pscheduler_writer role]"
    echo | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "pscheduler_writer:" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "  reserved: true" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "  index_permissions:" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "    - index_patterns:" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "      - 'pscheduler*'" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "      - 'prometheus*'" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "      allowed_actions:" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "      - 'write'" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null

    # anonymous_reader => read-only access to the pscheduler indices
    echo "[Creating opendistro_security_anonymous role]"
    echo | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "opendistro_security_anonymous:" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "  reserved: true" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "  cluster_permissions:" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "    - 'cluster_monitor'" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
fi
echo "[DONE]"
echo ""

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
    echo "[Create policy]"
    # Create index policy
    curl -k -u admin:${ADMIN_PASS} -H 'Content-Type: application/json' -X PUT "https://localhost:9200/_plugins/_ism/policies/pscheduler_default_policy" -d "@/usr/lib/perfsonar/archive/config/ilm/install/pscheduler_default_policy.json" 2>/dev/null
    echo -e "\n[Applying policy]"
    # Apply policy to index
    curl -k -u admin:${ADMIN_PASS} -H 'Content-Type: application/json' -X POST "https://localhost:9200/_plugins/_ism/add/pscheduler*" -d '{ "policy_id": "pscheduler_default_policy" }' 2>/dev/null
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
status=$(curl -k -u admin:${ADMIN_PASS} -s -H 'Content-Type: application/json' -XPUT "https://localhost:9200/_index_template/prometheus_template" -d @/usr/lib/perfsonar/archive/config/index_template-prometheus.json)
if [ $status -eq 200 ]; then
    echo "[Index prometheus updated successfully]"
fi
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