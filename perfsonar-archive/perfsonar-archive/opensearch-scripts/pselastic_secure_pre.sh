#!/bin/bash

##  GATHERING INFO

if [ -e '/etc/redhat-release' ]; then
    OS="redhat"
elif [ -e '/etc/debian_version' ]; then
    OS="debian"
else
    OS="Unknown"
fi

PASSWORD_DIR=/etc/perfsonar/opensearch
PASSWORD_FILE=${PASSWORD_DIR}/auth_setup.out
ADMIN_LOGIN_FILE=${PASSWORD_DIR}/opensearch_login
PROXY_AUTH_JSON=/etc/perfsonar/logstash/proxy_auth.json
LOGSTASH_PROXY_LOGIN_FILE=${PASSWORD_DIR}/logstash_login
LOGSTASH_PROXY_USER=perfsonar
LOGSTASH_USER=pscheduler_logstash
OPENSEARCH_CONFIG_DIR=/etc/opensearch
OPENSEARCH_CONFIG_FILE=${OPENSEARCH_CONFIG_DIR}/opensearch.yml
JVM_FILE=${OPENSEARCH_CONFIG_DIR}/jvm.options
OPENSEARCH_SECURITY_PLUGIN=/usr/share/opensearch/plugins/opensearch-security
OPENSEARCH_SECURITY_CONFIG=${OPENSEARCH_CONFIG_DIR}/opensearch-security

if [[ $OS == "redhat" ]]; then
    CACERTS_FILE=/etc/pki/java/cacerts
    LOGSTASH_SYSCONFIG=/etc/sysconfig/logstash
elif [[ $OS == "debian" ]]; then
    CACERTS_FILE=/usr/share/opensearch/jdk/lib/security/cacerts
    LOGSTASH_SYSCONFIG=/etc/default/logstash
else
    echo "$0 - [ERROR]: Unknown operating system"
    exit 1
fi

## CONFIGURING TLS

# Delete demo certificate files
rm -f ${OPENSEARCH_CONFIG_DIR}/*.pem

# Create a private key for the root certificate
openssl genrsa -out ${OPENSEARCH_CONFIG_DIR}/root-ca-key.pem 2048
# Use the private key to create a self-signed root certificate
openssl req -new -x509 -sha256 -key ${OPENSEARCH_CONFIG_DIR}/root-ca-key.pem -subj "/O=perfSONAR/OU=Archive/CN=root" -out ${OPENSEARCH_CONFIG_DIR}/root-ca.pem -days 7300

# Create a private key for the admin certificate
openssl genrsa -out ${OPENSEARCH_CONFIG_DIR}/admin-key-temp.pem 2048
# Convert the private key to PKCS#8
openssl pkcs8 -inform pem -outform pem -in ${OPENSEARCH_CONFIG_DIR}/admin-key-temp.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out ${OPENSEARCH_CONFIG_DIR}/admin-key.pem
# Create the certficiate signing request (CSR)
openssl req -new -key ${OPENSEARCH_CONFIG_DIR}/admin-key.pem -subj "/O=perfSONAR/OU=Archive/CN=admin" -out ${OPENSEARCH_CONFIG_DIR}/admin.csr
# Sign the admin certificate with the root certificate and private key created earlier
openssl x509 -req -in ${OPENSEARCH_CONFIG_DIR}/admin.csr -CA ${OPENSEARCH_CONFIG_DIR}/root-ca.pem -CAkey ${OPENSEARCH_CONFIG_DIR}/root-ca-key.pem -CAcreateserial -sha256 -out ${OPENSEARCH_CONFIG_DIR}/admin.pem -days 7300

# Create a private key for the node certificate
openssl genrsa -out ${OPENSEARCH_CONFIG_DIR}/node-key-temp.pem 2048
# Convert the private key to PKCS#8
openssl pkcs8 -inform pem -outform pem -in ${OPENSEARCH_CONFIG_DIR}/node-key-temp.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out ${OPENSEARCH_CONFIG_DIR}/node-key.pem
# Create the CSR. The CN should match a DNS A record for the host
openssl req -new -key ${OPENSEARCH_CONFIG_DIR}/node-key.pem -subj "/O=perfSONAR/OU=Archive/CN=localhost" -out ${OPENSEARCH_CONFIG_DIR}/node.csr
# Create an extension file that defines a SAN DNS name for the host. This should match the DNS A record of the host.
echo subjectAltName=DNS:localhost > ${OPENSEARCH_CONFIG_DIR}/node.ext
# Sign the node certificate with the root certificate and private key created earlier
openssl x509 -req -in ${OPENSEARCH_CONFIG_DIR}/node.csr -CA ${OPENSEARCH_CONFIG_DIR}/root-ca.pem -CAkey ${OPENSEARCH_CONFIG_DIR}/root-ca-key.pem -CAcreateserial -sha256 -out ${OPENSEARCH_CONFIG_DIR}/node.pem -days 7300 -extfile ${OPENSEARCH_CONFIG_DIR}/node.ext

# Cleanup
rm -f ${OPENSEARCH_CONFIG_DIR}/admin-key-temp.pem ${OPENSEARCH_CONFIG_DIR}/admin.csr ${OPENSEARCH_CONFIG_DIR}/node-key-temp.pem ${OPENSEARCH_CONFIG_DIR}/node.csr ${OPENSEARCH_CONFIG_DIR}/node.ext
chown opensearch:opensearch ${OPENSEARCH_CONFIG_DIR}/admin-key.pem ${OPENSEARCH_CONFIG_DIR}/admin.pem ${OPENSEARCH_CONFIG_DIR}/node-key.pem ${OPENSEARCH_CONFIG_DIR}/node.pem ${OPENSEARCH_CONFIG_DIR}/root-ca-key.pem ${OPENSEARCH_CONFIG_DIR}/root-ca.pem ${OPENSEARCH_CONFIG_DIR}/root-ca.srl

# Add to Java cacerts
openssl x509 -in ${OPENSEARCH_CONFIG_DIR}/root-ca.pem -inform pem -out ${OPENSEARCH_CONFIG_DIR}/root-ca.der -outform der
/usr/share/opensearch/jdk/bin/keytool -import -alias node -keystore ${CACERTS_FILE} -file ${OPENSEARCH_CONFIG_DIR}/root-ca.der -storepass changeit -noprompt

# Remove old settings
sed -i '/^plugins.security.ssl.transport.pemcert_filepath:.*/d' $OPENSEARCH_CONFIG_FILE
sed -i '/^plugins.security.ssl.transport.pemkey_filepath:.*/d' $OPENSEARCH_CONFIG_FILE
sed -i '/^plugins.security.ssl.transport.pemtrustedcas_filepath:.*/d' $OPENSEARCH_CONFIG_FILE
sed -i '/^plugins.security.ssl.http.enabled:.*/d' $OPENSEARCH_CONFIG_FILE
sed -i '/^plugins.security.ssl.http.pemcert_filepath:.*/d' $OPENSEARCH_CONFIG_FILE
sed -i '/^plugins.security.ssl.http.pemkey_filepath:.*/d' $OPENSEARCH_CONFIG_FILE
sed -i '/^plugins.security.ssl.http.pemtrustedcas_filepath:.*/d' $OPENSEARCH_CONFIG_FILE
sed -i '/^plugins.security.allow_default_init_securityindex:.*/d' $OPENSEARCH_CONFIG_FILE
sed -i '/^plugins.security.authcz.admin_dn:.*/{n;d;}' $OPENSEARCH_CONFIG_FILE
sed -i '/^plugins.security.authcz.admin_dn:.*/d' $OPENSEARCH_CONFIG_FILE
sed -i '/^plugins.security.nodes_dn:.*/{n;d;}' $OPENSEARCH_CONFIG_FILE
sed -i '/^plugins.security.nodes_dn:.*/d' $OPENSEARCH_CONFIG_FILE
sed -i '/^plugins.security.audit.type:.*/d' $OPENSEARCH_CONFIG_FILE
sed -i '/^plugins.security.enable_snapshot_restore_privilege:.*/d' $OPENSEARCH_CONFIG_FILE
sed -i '/^plugins.security.check_snapshot_restore_write_privileges:.*/d' $OPENSEARCH_CONFIG_FILE
sed -i '/^plugins.security.restapi.roles_enabled:.*/d' $OPENSEARCH_CONFIG_FILE
sed -i '/^plugins.security.allow_unsafe_democertificates:.*/d' $OPENSEARCH_CONFIG_FILE
sed -i '/^plugins.security.ssl.transport.enforce_hostname_verification:.*/d' $OPENSEARCH_CONFIG_FILE
sed -i '/^discovery.type:.*/d' $OPENSEARCH_CONFIG_FILE

# Apply new settings
echo -e '\n######## Start OpenSearch Security PerfSONAR Configuration ########\n' | tee -a $OPENSEARCH_CONFIG_FILE > /dev/null
echo 'plugins.security.ssl.transport.pemcert_filepath: node.pem' | tee -a $OPENSEARCH_CONFIG_FILE > /dev/null
echo 'plugins.security.ssl.transport.pemkey_filepath: node-key.pem' | tee -a $OPENSEARCH_CONFIG_FILE > /dev/null
echo 'plugins.security.ssl.transport.pemtrustedcas_filepath: root-ca.pem' | tee -a $OPENSEARCH_CONFIG_FILE > /dev/null
echo 'plugins.security.ssl.http.enabled: true' | tee -a $OPENSEARCH_CONFIG_FILE > /dev/null
echo 'plugins.security.ssl.http.pemcert_filepath: node.pem' | tee -a $OPENSEARCH_CONFIG_FILE > /dev/null
echo 'plugins.security.ssl.http.pemkey_filepath: node-key.pem' | tee -a $OPENSEARCH_CONFIG_FILE > /dev/null
echo 'plugins.security.ssl.http.pemtrustedcas_filepath: root-ca.pem' | tee -a $OPENSEARCH_CONFIG_FILE > /dev/null
echo 'plugins.security.allow_default_init_securityindex: false' | tee -a $OPENSEARCH_CONFIG_FILE > /dev/null
echo -e 'plugins.security.authcz.admin_dn:\n  - CN=admin,OU=Archive,O=perfSONAR' | tee -a $OPENSEARCH_CONFIG_FILE > /dev/null
echo -e 'plugins.security.nodes_dn:\n  - CN=localhost,OU=Archive,O=perfSONAR' | tee -a $OPENSEARCH_CONFIG_FILE > /dev/null
echo 'plugins.security.audit.type: internal_opensearch' | tee -a $OPENSEARCH_CONFIG_FILE > /dev/null
echo 'plugins.security.enable_snapshot_restore_privilege: true' | tee -a $OPENSEARCH_CONFIG_FILE > /dev/null
echo 'plugins.security.check_snapshot_restore_write_privileges: true' | tee -a $OPENSEARCH_CONFIG_FILE > /dev/null
echo 'plugins.security.restapi.roles_enabled: ["all_access", "security_rest_api_access"]' | tee -a $OPENSEARCH_CONFIG_FILE > /dev/null
echo 'plugins.security.allow_unsafe_democertificates: false' | tee -a $OPENSEARCH_CONFIG_FILE > /dev/null
echo 'plugins.security.ssl.transport.enforce_hostname_verification: false' | tee -a $OPENSEARCH_CONFIG_FILE > /dev/null
echo 'discovery.type: single-node' | tee -a $OPENSEARCH_CONFIG_FILE > /dev/null
echo -e '\n######## End OpenSearch Security PerfSONAR Configuration ########' | tee -a $OPENSEARCH_CONFIG_FILE > /dev/null

## Specify initial and maximum JVM heap sizes.

HALF_MEM=$(free --mega | awk '$1 == "Mem:" { half=int(($2/2)+0.5); print (half > 8192) ? 8192 : half }')
sed -i "s/^-Xms.*/-Xms${HALF_MEM}m/g" $JVM_FILE
sed -i "s/^-Xmx.*/-Xmx${HALF_MEM}m/g" $JVM_FILE

# Give execute permission to opensearch hash script
chmod +x ${OPENSEARCH_SECURITY_PLUGIN}/tools/hash.sh

# Generate default users random passwords, write them to tmp file and, if it works, move to permanent file
echo "[Generating opensearch passwords]"
if [ -e "$PASSWORD_FILE" ]; then
    echo "$PASSWORD_FILE already exists, so not generating new passwords"
else
    mkdir -p $PASSWORD_DIR
    TEMPFILE=$(mktemp)
    egrep -v '^[[:blank:]]' "${OPENSEARCH_SECURITY_CONFIG}/internal_users.yml" | egrep "\:$" | egrep -v '^\_' | sed 's\:\\g' | while read user; do
        PASS=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 20)
        echo "$user $PASS" >> $TEMPFILE
        HASHED_PASS=$(OPENSEARCH_JAVA_HOME=/usr/share/opensearch/jdk ${OPENSEARCH_SECURITY_PLUGIN}/tools/hash.sh -p $PASS | tail -n 1 | sed -e 's/[&\\/]/\\&/g')
        if [[ $OS == "redhat" ]]; then
            sed -i -e '/^'$user'\:$/,/[^hash.*$]/s/\(hash\: \).*$/\1"'$HASHED_PASS'"/' "${OPENSEARCH_SECURITY_CONFIG}/internal_users.yml"
        elif [[ $OS == "debian" ]]; then
            sed -i -e '/^'$user'\:$/,/[^hash.*$]/      s/\(hash\: \).*$/\1"'$HASHED_PASS'"/' "${OPENSEARCH_SECURITY_CONFIG}/internal_users.yml"
        fi
    done
    mv $TEMPFILE $PASSWORD_FILE
    chmod 600 $PASSWORD_FILE
fi

# Get password for admin user
ADMIN_PASS=$(grep -w "admin" $PASSWORD_FILE | head -n 1 | awk '{print $2}')
if [ $? -ne 0 ]; then
    echo "Failed to parse password"
    exit 1
elif [ -z "$ADMIN_PASS" ]; then
    echo "Unable to find admin password in $PASSWORD_FILE. Exiting."
    exit 1
fi

# Create file with admin login - overwrite it if already exists (is this file necessary?)
echo "admin $ADMIN_PASS" > $ADMIN_LOGIN_FILE
chmod 600 $ADMIN_LOGIN_FILE
echo "[DONE]"
echo ""

# Create perfsonar user for logstash auth in proxy layer
if [ -f "$LOGSTASH_PROXY_LOGIN_FILE" ] ; then
    rm "$LOGSTASH_PROXY_LOGIN_FILE"
fi
PROXY_PASS=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 20)
htpasswd -bc $LOGSTASH_PROXY_LOGIN_FILE $LOGSTASH_PROXY_USER $PROXY_PASS
LOGIN_BASE64=$(echo -n "$LOGSTASH_PROXY_USER:$PROXY_PASS" | base64 -i)
echo "\"Authorization\":\"Basic $LOGIN_BASE64\"" | tee $PROXY_AUTH_JSON > /dev/null

# new users: pscheduler_logstash, pscheduler_reader and pscheduler_writer
# 1. Create users, generate passwords and save them to file 
echo "[Creating pscheduler users]"
grep "pscheduler" $OPENSEARCH_SECURITY_CONFIG/internal_users.yml > /dev/null
if [ $? -eq 0 ]; then
    echo "User already created"
else
    # pscheduler_logstash
    echo "[Creating $LOGSTASH_USER user]"
    PASS=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 20)
    HASHED_PASS=$(OPENSEARCH_JAVA_HOME=/usr/share/opensearch/jdk ${OPENSEARCH_SECURITY_PLUGIN}/tools/hash.sh -p $PASS | tail -n 1)
    echo "$LOGSTASH_USER $PASS" | tee -a $PASSWORD_FILE  > /dev/null
    echo | tee -a $OPENSEARCH_SECURITY_CONFIG/internal_users.yml > /dev/null
    echo "$LOGSTASH_USER:" | tee -a $OPENSEARCH_SECURITY_CONFIG/internal_users.yml > /dev/null
    echo '  hash: "'$HASHED_PASS'"' | tee -a $OPENSEARCH_SECURITY_CONFIG/internal_users.yml > /dev/null
    echo '  reserved: true' | tee -a $OPENSEARCH_SECURITY_CONFIG/internal_users.yml > /dev/null
    echo '  description: "pscheduler logstash user"' | tee -a $OPENSEARCH_SECURITY_CONFIG/internal_users.yml > /dev/null

    # pscheduler_reader
    echo "[Creating pscheduler_reader user]"
    PASS=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 20)
    HASHED_PASS=$(OPENSEARCH_JAVA_HOME=/usr/share/opensearch/jdk ${OPENSEARCH_SECURITY_PLUGIN}/tools/hash.sh -p $PASS | tail -n 1)
    echo "pscheduler_reader $PASS" | tee -a $PASSWORD_FILE  > /dev/null
    echo | tee -a $OPENSEARCH_SECURITY_CONFIG/internal_users.yml > /dev/null
    echo 'pscheduler_reader:' | tee -a $OPENSEARCH_SECURITY_CONFIG/internal_users.yml > /dev/null
    echo '  hash: "'$HASHED_PASS'"' | tee -a $OPENSEARCH_SECURITY_CONFIG/internal_users.yml > /dev/null
    echo '  reserved: true' | tee -a $OPENSEARCH_SECURITY_CONFIG/internal_users.yml > /dev/null
    echo '  description: "pscheduler reader user"' | tee -a $OPENSEARCH_SECURITY_CONFIG/internal_users.yml > /dev/null

    # pscheduler_writer
    echo "[Creating pscheduler_writer user]"
    PASS=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 20)
    HASHED_PASS=$(OPENSEARCH_JAVA_HOME=/usr/share/opensearch/jdk ${OPENSEARCH_SECURITY_PLUGIN}/tools/hash.sh -p $PASS | tail -n 1)
    echo "pscheduler_writer $PASS" | tee -a $PASSWORD_FILE  > /dev/null
    echo | tee -a $OPENSEARCH_SECURITY_CONFIG/internal_users.yml > /dev/null
    echo 'pscheduler_writer:' | tee -a $OPENSEARCH_SECURITY_CONFIG/internal_users.yml > /dev/null
    echo '  hash: "'$HASHED_PASS'"' | tee -a $OPENSEARCH_SECURITY_CONFIG/internal_users.yml > /dev/null
    echo '  reserved: true' | tee -a $OPENSEARCH_SECURITY_CONFIG/internal_users.yml > /dev/null
    echo '  description: "pscheduler writer user"' | tee -a $OPENSEARCH_SECURITY_CONFIG/internal_users.yml > /dev/null

    # Enable anonymous user
    sed -i 's/\(anonymous_auth_enabled:\).*/\1 true/g' $OPENSEARCH_SECURITY_CONFIG/config.yml
fi
echo "[DONE]"
echo ""

# 2. Create roles
echo "[Creating pscheduler roles]"
grep "pscheduler" $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
if [ $? -eq 0 ]; then
    echo "Role already created"
else
    # pscheduler_logstash
    echo "[Creating $LOGSTASH_USER role]"
    echo | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "$LOGSTASH_USER:" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "  cluster_permissions:" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "    - 'cluster_monitor'" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "    - 'cluster_manage_index_templates'" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "  index_permissions:" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "    - index_patterns:" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "      - 'pscheduler_*'" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "      allowed_actions:" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "      - 'write'" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "      - 'read'" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "      - 'delete'" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "      - 'create_index'" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "      - 'manage'" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "      - 'indices:admin/template/delete'" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "      - 'indices:admin/template/get'" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "      - 'indices:admin/template/put'" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null

    # pscheduler_reader => read-only access to the pscheduler indices
    echo "[Creating pscheduler_reader role]"
    echo | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "pscheduler_reader:" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "  reserved: true" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "  index_permissions:" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "    - index_patterns:" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "      - 'pscheduler*'" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "      allowed_actions:" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "      - 'read'" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "      - 'indices:admin/mappings/get'" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null

    # pscheduler_writer => write-only access to the pscheduler indices
    echo "[Creating pscheduler_writer role]"
    echo | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "pscheduler_writer:" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "  reserved: true" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "  index_permissions:" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "    - index_patterns:" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "      - 'pscheduler*'" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "      allowed_actions:" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "      - 'write'" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null

    # anonymous_reader => read-only access to the pscheduler indices
    echo "[Creating opendistro_security_anonymous role]"
    echo | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "opendistro_security_anonymous:" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "  reserved: true" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "  cluster_permissions:" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
    echo "    - 'cluster_monitor'" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles.yml > /dev/null
fi
echo "[DONE]"
echo ""

# 3. Map users to roles
echo "[Mapping pscheduler users to pscheduler roles]"
grep "pscheduler" $OPENSEARCH_SECURITY_CONFIG/roles_mapping.yml > /dev/null
if [ $? -eq 0 ]; then
    echo "Map already created"
else
    # pscheduler_logstash
    echo "[Mapping $LOGSTASH_USER user to $LOGSTASH_USER role]"
    echo | tee -a $OPENSEARCH_SECURITY_CONFIG/roles_mapping.yml > /dev/null
    echo "$LOGSTASH_USER:" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles_mapping.yml > /dev/null
    echo '  reserved: true' | tee -a $OPENSEARCH_SECURITY_CONFIG/roles_mapping.yml > /dev/null
    echo '  users:' | tee -a $OPENSEARCH_SECURITY_CONFIG/roles_mapping.yml > /dev/null
    echo "  - \"$LOGSTASH_USER\"" | tee -a $OPENSEARCH_SECURITY_CONFIG/roles_mapping.yml > /dev/null

    # pscheduler_reader
    echo "[Mapping pscheduler_reader user to pscheduler_reader role]"
    echo | tee -a $OPENSEARCH_SECURITY_CONFIG/roles_mapping.yml > /dev/null
    echo 'pscheduler_reader:' | tee -a $OPENSEARCH_SECURITY_CONFIG/roles_mapping.yml > /dev/null
    echo '  reserved: true' | tee -a $OPENSEARCH_SECURITY_CONFIG/roles_mapping.yml > /dev/null
    echo '  users:' | tee -a $OPENSEARCH_SECURITY_CONFIG/roles_mapping.yml > /dev/null
    echo '  - "pscheduler_reader"' | tee -a $OPENSEARCH_SECURITY_CONFIG/roles_mapping.yml > /dev/null
    # maps pscheduler_reader role with the anonymous user backend role
    echo '  backend_roles:' | tee -a $OPENSEARCH_SECURITY_CONFIG/roles_mapping.yml > /dev/null
    echo '  - "opendistro_security_anonymous_backendrole"' | tee -a $OPENSEARCH_SECURITY_CONFIG/roles_mapping.yml > /dev/null

    # pscheduler_writer
    echo "[Mapping pscheduler_writer user to pscheduler_writer role]"
    echo | tee -a $OPENSEARCH_SECURITY_CONFIG/roles_mapping.yml > /dev/null
    echo 'pscheduler_writer:' | tee -a $OPENSEARCH_SECURITY_CONFIG/roles_mapping.yml > /dev/null
    echo '  reserved: true' | tee -a $OPENSEARCH_SECURITY_CONFIG/roles_mapping.yml > /dev/null
    echo '  users:' | tee -a $OPENSEARCH_SECURITY_CONFIG/roles_mapping.yml > /dev/null
    echo '  - "pscheduler_writer"' | tee -a $OPENSEARCH_SECURITY_CONFIG/roles_mapping.yml > /dev/null

    # anonymous
    echo "[Mapping anonymous user to anonymous user backend role]"
    echo | tee -a $OPENSEARCH_SECURITY_CONFIG/roles_mapping.yml > /dev/null
    echo 'opendistro_security_anonymous:' | tee -a $OPENSEARCH_SECURITY_CONFIG/roles_mapping.yml > /dev/null
    echo '  reserved: true' | tee -a $OPENSEARCH_SECURITY_CONFIG/roles_mapping.yml > /dev/null
    echo '  backend_roles:' | tee -a $OPENSEARCH_SECURITY_CONFIG/roles_mapping.yml > /dev/null
    echo '  - "opendistro_security_anonymous_backendrole"' | tee -a $OPENSEARCH_SECURITY_CONFIG/roles_mapping.yml > /dev/null
fi
echo "[DONE]"
echo ""

# 5. Configure logstash to use pscheduler_logstash user/password
echo "[Configure logstash]"
LOGSTASH_PASS=$(grep $LOGSTASH_USER $PASSWORD_FILE | head -n 1 | awk '{print $2}')
grep "opensearch" $LOGSTASH_SYSCONFIG > /dev/null
if [ $? -eq 0 ]; then
    sed -i 's/\(opensearch_output_password=\).*/\1'$LOGSTASH_PASS'/g' $LOGSTASH_SYSCONFIG   
else
    echo '## Logstash environment variables.' | tee -a $LOGSTASH_SYSCONFIG  > /dev/null
    echo 'log_level=info' | tee -a $LOGSTASH_SYSCONFIG  > /dev/null
    echo 'opensearch_output_host=https://localhost:9200' | tee -a $LOGSTASH_SYSCONFIG  > /dev/null
    echo 'opensearch_output_user=pscheduler_logstash' | tee -a $LOGSTASH_SYSCONFIG  > /dev/null
    echo 'opensearch_output_password='$LOGSTASH_PASS | tee -a $LOGSTASH_SYSCONFIG  > /dev/null
    echo 'XPACK_MONITORING_ENABLED=False' | tee -a $LOGSTASH_SYSCONFIG  > /dev/null
fi
echo "[DONE]"
echo ""
