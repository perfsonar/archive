#!/bin/bash

#####
# Helper script to output a psConfig archive definition. 
#
# Params:
#   hostname: A vaid hostname of the archive server. Defaults to psconfig variable {% scheduled_by_address %}
####

ARCHIVE_HOST=${1:-'{% scheduled_by_address %}'}
AUTH_HEADER=`cat /etc/perfsonar/logstash/proxy_auth.json`
cat << EOF
{
    "archiver": "http",
    "data": {
        "schema": 2,
        "_url": "https://${ARCHIVE_HOST}/logstash",
        "op": "put",
        "_headers": {
            "x-ps-observer": "{% scheduled_by_address %}",
            "content-type": "application/json", 
            ${AUTH_HEADER}
        },
        "_meta": {
            "esmond_url": "https://${ARCHIVE_HOST}/esmond/perfsonar/archive/"
        }
    }
}
EOF

