# /bin/sh

decrypt() {
    if [ -z "$1" ] || [ -z "$2" ]; then
        echo ""
        return
    fi
    echo "$1" | openssl enc -aes-256-cbc -A -d -a -S $CE_HEX_CODE -K "$2" -iv $CE_IV -pbkdf2 -iter 10000
}

CE_SETUP_ID=$(echo "$CE_SETUP_ID" | tr -d '"')
# Generate processed key
PROCESSED_KEY=$(echo -n $CE_SETUP_ID | openssl dgst -sha256 -hex | awk '{print $2}')
# Export values
for VAR in "MAINTENANCE_PASSWORD" "RABBITMQ_DEFAULT_PASS" "MONGO_INITDB_ROOT_PASSWORD" "MONGODB_PASSWORD" "MAINTENANCE_PASSWORD_ESCAPED" "CE_SSL_CERTIFICATE_PASSWORD"; do
    export "$VAR"="$(decrypt "${!VAR}" "${PROCESSED_KEY}")"
done

if [ -n "${HA_IP_LIST:-}" ]; then

    mongo_host_list=""
    rabbitmq_node_conn_string=""
    IFS=',' read -r -a host_array <<< "$HA_IP_LIST"

    for hostname in "${host_array[@]}"; do
        mongo_host_list+="$hostname:27017,"
        rabbitmq_node_conn_string+="amqps://user:${MAINTENANCE_PASSWORD_ESCAPED}@${hostname};"
    done

    mongo_host_list="${mongo_host_list%,}"
    rabbitmq_node_conn_string="${rabbitmq_node_conn_string%,}"

    export MONGO_CONNECTION_STRING="mongodb://cteadmin:${MAINTENANCE_PASSWORD_ESCAPED}@${mongo_host_list}/cte?replicaSet=mongo_replica_set&tls=true&tlsCertificateKeyFile=/opt/certs/mongodb_rabbitmq_certs/tls_cert_key.pem&tlsCAFile=/opt/certs/mongodb_rabbitmq_certs/tls_cert_ca.crt&tlsAllowInvalidHostnames=true"
    export RABBITMQ_CONNECTION_STRING="$rabbitmq_node_conn_string"
else
    export MONGO_CONNECTION_STRING="mongodb://cteadmin:${MAINTENANCE_PASSWORD_ESCAPED}@mongodb-primary:27017/cte?tls=true&tlsCertificateKeyFile=/opt/certs/mongodb_rabbitmq_certs/tls_cert_key.pem&tlsCAFile=/opt/certs/mongodb_rabbitmq_certs/tls_cert_ca.crt&tlsAllowInvalidHostnames=true"
    export RABBITMQ_CONNECTION_STRING="amqps://user:${MAINTENANCE_PASSWORD_ESCAPED}@rabbitmq-stats"

fi
