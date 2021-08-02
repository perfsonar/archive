#!/bin/bash

# Pre configure kibana's index patterns
echo "[Add default index-pattern]"
ADMIN_PASS=$(grep "admin " /etc/perfsonar/elastic/auth_setup.out | head -n 1 | sed 's/^admin //')
KIBANA_VERSION=$(/usr/share/kibana/bin/kibana --config /etc/kibana/kibana.yml --allow-root --version)
curl -v -4 -X POST -u admin:${ADMIN_PASS} http://localhost:5601/api/saved_objects/index-pattern -H "kbn-version: ${KIBANA_VERSION}" -H "kbn-xsrf: true" -H "content-type: application/json; charset=utf-8" -d '{"attributes":{"title":"pscheduler*","timeFieldName":"pscheduler.start_time","fields":"[]"}}'
echo "[DONE]"
echo ""
