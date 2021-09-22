#!/bin/bash

ADMIN_PASS=$(grep "admin " /etc/perfsonar/elastic/auth_setup.out | head -n 1 | sed 's/^admin //')
KIBANA_VERSION=$(/usr/share/kibana/bin/kibana --config /etc/kibana/kibana.yml --allow-root --version)

# Check if the API is running
echo "Waiting kibana API to start..."
api_status=$(curl -s -o /dev/null -w "%{http_code}" -u admin:${ADMIN_PASS} http://localhost:5601/api/status)
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
    api_status=$(curl -s -o /dev/null -w "%{http_code}" -u admin:${ADMIN_PASS} http://localhost:5601/api/status)
done

echo "API started!"

# Pre configure kibana's index patterns
echo "[Add default index-pattern]"
curl -4 -X POST -u admin:${ADMIN_PASS} http://localhost:5601/api/saved_objects/index-pattern -H "kbn-version: ${KIBANA_VERSION}" -H "kbn-xsrf: true" -H "content-type: application/json; charset=utf-8" -d '{"attributes":{"title":"pscheduler*","timeFieldName":"pscheduler.start_time","fields":"[]"}}' 2>/dev/null
echo -e "\n[DONE]"
echo ""
