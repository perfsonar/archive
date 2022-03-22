ELASTIC_PASSWORD_FILE=/etc/perfsonar/opensearch/auth_setup.out
ELMOND_CONFIG_FILE=/etc/perfsonar/elmond/elmond.json
TEMP_DIR=/tmp

ADMIN_PW=$(grep admin ${ELASTIC_PASSWORD_FILE} | awk '{print $2}')
jq --arg elasticURL  "https://admin:${ADMIN_PW}@localhost:9200" '.ELASTIC_HOSTS[0] = $elasticURL' ${ELMOND_CONFIG_FILE} > ${TEMP_DIR}/elmond_config_temp.json

mv -f ${TEMP_DIR}/elmond_config_temp.json ${ELMOND_CONFIG_FILE}

jq --arg rootCert   '/etc/elasticsearch/root-ca.pem' \
   --arg adminCert  '/etc/elasticsearch/admin.pem' \
   --arg adminKey   '/etc/elasticsearch/admin-key.pem' \
   '.use_ssl = true | .ca_certs = $rootCert | .client_cert = $adminCert | .client_key = $adminKey' \
   <<< {} > ${TEMP_DIR}/elastic_params_temp.json

jq '.ELASTIC_PARAMS = $params' --argjson params "$(<${TEMP_DIR}/elastic_params_temp.json)" ${ELMOND_CONFIG_FILE} > ${TEMP_DIR}/elmond_config_temp.json

mv -f ${TEMP_DIR}/elmond_config_temp.json ${ELMOND_CONFIG_FILE}

rm -f ${TEMP_DIR}/elastic_params_temp.json
