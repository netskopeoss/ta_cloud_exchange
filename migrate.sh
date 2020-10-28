#!/bin/bash

set -e
MONGO_DIR="./data/mongo-data"

if [ ! -d "$MONGO_DIR" ]; then
    echo "Stopping running containers"
    docker stop core ui mongodb
    echo "Extracting databse from existing container"
    docker cp mongodb:/data/db "./data"
    mv "./data/db" $MONGO_DIR
    echo "Removing previous containers"
    docker rm -f core ui mongodb
    echo "Pulling latest images"
    docker-compose pull
    docker-compose up -d
    echo "Migrating database schema"
    docker cp database-migrate.py core:/opt
    docker exec -ti core python /opt/database-migrate.py
else
    echo "$MONGO_DIR already exists"
    echo "Make sure it does not contain any data, delete it and run the script again"
fi

