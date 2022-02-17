#!/bin/bash

# Configure kibana to use new kibanaserver password
echo "[Configure kibana]"
KIBANA_PASS=$(grep "kibanaserver " /etc/perfsonar/elastic/auth_setup.out | head -n 1 | sed 's/^kibanaserver //')
sed -i "s/elasticsearch.password: kibanaserver/elasticsearch.password: ${KIBANA_PASS}/g" /etc/kibana/kibana.yml
echo "[DONE]"
echo ""
