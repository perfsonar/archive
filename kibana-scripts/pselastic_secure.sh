#!/bin/bash

# 1. Configure kibana to use new kibanaserver password
echo "[Configure kibana]"
KIBANA_PASS=$(grep "kibanaserver " /etc/perfsonar/elastic/auth_setup.out | head -n 1 | sed 's/^kibanaserver //')
sed -i "s/elasticsearch.password: kibanaserver/elasticsearch.password: ${KIBANA_PASS}/g" /etc/kibana/kibana.yml
echo "[DONE]"
echo ""
#!/bin/bash

# 2. Pre configure kibana's index patterns
echo "[Add default index-pattern]"
ADMIN_PASS=$(grep "admin " /etc/perfsonar/elastic/auth_setup.out | head -n 1 | sed 's/^admin //')
KIBANA_VERSION=$(/usr/share/kibana/bin/kibana --config /etc/kibana/kibana.yml --allow-root --version)
curl -v -4 -X POST -u admin:${ADMIN_PASS} http://localhost:5601/api/saved_objects/index-pattern -H "kbn-version: ${KIBANA_VERSION}" -H "kbn-xsrf: true" -H "content-type: application/json; charset=utf-8" -d '{"attributes":{"title":"pscheduler-*","timeFieldName":"start_time","fields":"[]"}}'
echo "[DONE]"
echo ""
