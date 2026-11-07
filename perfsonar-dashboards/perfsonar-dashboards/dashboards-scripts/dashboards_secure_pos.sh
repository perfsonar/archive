#!/bin/bash

ADMIN_PASS=$(grep "admin" /etc/perfsonar/opensearch/auth_setup.out | head -n 1 | awk '{print $2}')
DASHBOARDS_VERSION=$(/usr/share/opensearch-dashboards/bin/opensearch-dashboards --config /etc/opensearch-dashboards/opensearch_dashboards.yml --allow-root --version)

# curl as admin; the password goes to curl on stdin, not on its command line
os_curl () {
    local pass=${ADMIN_PASS//\\/\\\\}
    pass=${pass//\"/\\\"}
    printf 'user = "admin:%s"\n' "$pass" | curl -K - "$@"
}

# Check if the API is running
echo "Waiting for opensearch dashboards API to start..."
api_status=$(os_curl -s -o /dev/null -w "%{http_code}" http://localhost:5601/api/status)
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
    api_status=$(os_curl -s -o /dev/null -w "%{http_code}" http://localhost:5601/api/status)
done

echo "API started!"

# Pre configure opensearch dashboards's index patterns
# Check if the index pattern already exists
response=$(os_curl -s -X GET "http://localhost:5601/api/saved_objects/_find?type=index-pattern&search_fields=title&search=pscheduler")
total=$(echo "$response" | jq -r '.total')
if [[ "$total" -eq 0 ]]; then
    echo "[Add default index-pattern]"
    os_curl -X POST http://localhost:5601/api/saved_objects/index-pattern -H "osd-version: ${DASHBOARDS_VERSION}" -H "osd-xsrf: true" -H "content-type: application/json; charset=utf-8" -d '{"attributes":{"title":"pscheduler*","timeFieldName":"pscheduler.start_time","fields":"[]"}}' 2>/dev/null
    echo -e "\n[DONE]"
    echo ""
fi
