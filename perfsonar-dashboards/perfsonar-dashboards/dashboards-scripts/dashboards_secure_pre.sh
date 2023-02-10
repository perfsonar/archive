#!/bin/bash

# Configure opensearch dashboards to use new kibanaserver password
echo "[Configure Opensearch-Dashboards]"
OPENSEARCHDASH_CONFIG=/etc/opensearch-dashboards/opensearch_dashboards.yml
DASHBOARDS_PASS=$(grep "kibanaserver " /etc/perfsonar/opensearch/auth_setup.out | head -n 1 | awk '{print $2}')
sed -i "s/^opensearch.password: kibanaserver/opensearch.password: ${DASHBOARDS_PASS}/g" $OPENSEARCHDASH_CONFIG
# Clear and then set reverse proxy settings
sed -i '/^server.basePath:.*/d' $OPENSEARCHDASH_CONFIG
sed -i '/^server.host:.*/d' $OPENSEARCHDASH_CONFIG
echo "server.basePath: /opensearchdash" | tee -a $OPENSEARCHDASH_CONFIG > /dev/null
echo "server.host: 127.0.0.1" | tee -a $OPENSEARCHDASH_CONFIG > /dev/null
echo "[DONE]"
echo ""
