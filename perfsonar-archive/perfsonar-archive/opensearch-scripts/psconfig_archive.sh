#!/bin/bash

#####
# Helper script to output a psConfig archive definition. 
#
# Params:
#   -n hostname: A vaid hostname of the archive server. Defaults to psconfig variable {% scheduled_by_address %}
#   -a authtype: Authorization. Valid values are 'basic' and 'none'. Default is 'basic'.
####

DEFAULT_ARCHIVE_HOST='{% scheduled_by_address %}'
AUTH_TYPE='basic'
while getopts n:a: flag
do
    case "${flag}" in
        n) ARCHIVE_HOST=${OPTARG};;
        a) AUTH_TYPE=${OPTARG};;
    esac
done

#determin auth strategy
AUTH_HEADER=""
if [ "$AUTH_TYPE" == "basic" ]; then
    AUTH_HEADER=`cat /etc/perfsonar/logstash/proxy_auth.json`
    AUTH_HEADER=`printf ",\n            $AUTH_HEADER"`
fi


#check if this is a remote MA
if [ -n "$ARCHIVE_HOST" ]; then

cat << EOF
{
    "archiver": "http",
    "data": {
        "schema": 3,
        "_url": "https://${ARCHIVE_HOST}/logstash",
        "verify-ssl": false,
        "op": "put",
        "_headers": {
            "x-ps-observer": "{% scheduled_by_address %}",
            "content-type": "application/json"${AUTH_HEADER}
        }
    },
    "_meta": {
        "esmond_url": "https://${ARCHIVE_HOST}/esmond/perfsonar/archive/"
    }
}
EOF

else

cat << EOF
{
    "archiver": "http",
    "data": {
        "schema": 2,
        "_url": "https://${DEFAULT_ARCHIVE_HOST}/logstash",
        "op": "put",
        "_headers": {
            "x-ps-observer": "{% scheduled_by_address %}",
            "content-type": "application/json"${AUTH_HEADER}
        }
    }
}
EOF

fi
