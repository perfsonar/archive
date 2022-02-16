#!/bin/bash

# Configure opensearch dashboards to use new kibanaserver password
echo "[Configure kibana]"
DASHBOARDS_PASS=$(grep "kibanaserver " /etc/perfsonar/elastic/auth_setup.out | head -n 1 | sed 's/^kibanaserver //')
sed -i "s/opensearch.password: kibanaserver/opensearch.password: ${DASHBOARDS_PASS}/g" /etc/opensearch-dashboards/opensearch_dashboards.yml
echo "[DONE]"
echo ""
