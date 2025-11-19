#!/bin/bash
set -e

# Define paths to perfSONAR scripts and the original OpenSearch entrypoint
PRE_SCRIPT="/usr/lib/perfsonar/archive/perfsonar-scripts/pselastic_secure_pre.sh"
POST_SCRIPT="/usr/lib/perfsonar/archive/perfsonar-scripts/pselastic_secure_pos.sh"
PASSWORD_HASH_TOOL="/usr/share/opensearch/plugins/opensearch-security/tools/hash.sh"
OPENSEARCH_USERS_CONFIG="/usr/share/opensearch/config/opensearch-security/internal_users.yml"
ORIGINAL_ENTRYPOINT="/usr/share/opensearch/opensearch-docker-entrypoint.sh"
INIT_GUARD_FILE="/usr/share/opensearch/data/.initialized"

if [ ! -f "$INIT_GUARD_FILE" ]; then
    # Disable htpasswd in secure_pre.sh
    sed -i '/htpasswd -bc/s/^/#/' "$PRE_SCRIPT"

    echo "Running pre-startup script..."
    if bash "$PRE_SCRIPT" install; then
        echo "Pre-startup script completed successfully."
    else
        echo "Error: pselastic_secure_pre.sh failed!" >&2
        exit 1
    fi

    ## How to manage the password file in helm chart? Secrets?
    ## admin password need to be available for dashboard service
    ## pscheduler_logstash password need to be available for logstash service
    ##
    ## Possible solution:
    ## - create a k8s secret with the passwords
    ## - mount the secret as a file in the perfsonar-archive pod
    ## - read the passwords from the mounted file here and update the password file, and opensearch config
    ##
    ## Steps to update password file and opensearch config:
    ##
    ## sed -i "s/^admin .*/admin $NEW_PASS/" /etc/perfsonar/opensearch/auth_setup.out
    ## sed -i "s/^pscheduler_logstash .*/pscheduler_logstash $NEW_PASS/" /etc/perfsonar/opensearch/auth_setup.out
    ##
    ## HASHED_PASS=$(OPENSEARCH_JAVA_HOME=/usr/share/opensearch/jdk ${PASSWORD_HASH_TOOL} -p $NEW_PASS)
    ## sed -i -e "/^admin:/,/^ /s/^\(  hash: \).*/\1\"$HASHED_PASS\"/" "$OPENSEARCH_USERS_CONFIG"
    ## sed -i -e "/^pscheduler_logstash:/,/^ /s/^\(  hash: \).*/\1\"$HASHED_PASS\"/" "$OPENSEARCH_USERS_CONFIG"

    #cp /etc/perfsonar/opensearch/auth_setup.out /usr/lib/perfsonar/archive/
fi

echo "Starting OpenSearch..."
# Drop privileges and start OpenSearch
gosu opensearch "$ORIGINAL_ENTRYPOINT" opensearch &
OPENSEARCH_PID=$!

# Wait for OpenSearch to start
echo "Waiting for OpenSearch..."
until curl -k https://localhost:9200 --silent; do
    sleep 5
done

if [ ! -f "$INIT_GUARD_FILE" ]; then

    # Override systemd status checks to always assume OpenSearch and Logstash are active since systemctl is not available inside the container
    sed -i 's|opensearch_systemctl_status=.*|opensearch_systemctl_status=active|' "$POST_SCRIPT"
    sed -i 's|logstash_systemctl_status=.*|logstash_systemctl_status=active|' "$POST_SCRIPT"

    echo "Running post-startup script..."
    if bash "$POST_SCRIPT"; then
        touch "$INIT_GUARD_FILE"
        echo "Post-startup script completed successfully."
    else
        echo "Error: pselastic_secure_pos.sh failed!" >&2
        exit 1
    fi
fi

# Re-parent OpenSearch to PID 1 and forward signals
trap 'kill -TERM $OPENSEARCH_PID' TERM INT
wait $OPENSEARCH_PID