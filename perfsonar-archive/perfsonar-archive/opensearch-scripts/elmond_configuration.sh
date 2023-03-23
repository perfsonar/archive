ELASTIC_PASSWORD_FILE=/etc/perfsonar/opensearch/auth_setup.out
ELMOND_CONFIG_FILE=/etc/perfsonar/elmond/elmond.json
TEMP_DIR=/tmp

READER_PW=$(grep pscheduler_reader ${ELASTIC_PASSWORD_FILE} | awk '{print $2}' | head -1)
jq --arg elasticURL  "https://pscheduler_reader:${READER_PW}@localhost:9200" '.ELASTIC_HOSTS[0] = $elasticURL' ${ELMOND_CONFIG_FILE} > ${TEMP_DIR}/elmond_config_temp.json

mv -f ${TEMP_DIR}/elmond_config_temp.json ${ELMOND_CONFIG_FILE}

jq --arg rootCert   '/etc/opensearch/root-ca.pem' \
   '.use_ssl = true | .ca_certs = $rootCert' \
   <<< {} > ${TEMP_DIR}/elastic_params_temp.json

jq '.ELASTIC_PARAMS = $params' --argjson params "$(<${TEMP_DIR}/elastic_params_temp.json)" ${ELMOND_CONFIG_FILE} > ${TEMP_DIR}/elmond_config_temp.json

mv -f ${TEMP_DIR}/elmond_config_temp.json ${ELMOND_CONFIG_FILE}

rm -f ${TEMP_DIR}/elastic_params_temp.json
