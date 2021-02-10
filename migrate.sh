#!/bin/bash
#
# Prerequisites for migration:
#  - Previous version of core, ui, and mongodb containers should be running
#  - Current working directory should be the one with the docker-compose.yml
#  - Mongo mount path specified in the docker-compose.yml should be a
#    non-existent directory.
#
# Executing the script:
#  > chmod +x migrate.sh
#  > ./migrate.sh
#
# Notes:
#  - After migration, all the Netskope plugins would default to poll interval
#    of 60 minutes. Update this manually from UI if necessary.

set -e
MOUNT_PATH=`grep "/data/db:z" docker-compose.yml`
MONGO_DIR=`docker exec -ti core python -c 'import sys; print(sys.argv[1].strip().split(":")[0][1:].strip(), end="")' "${MOUNT_PATH}"`

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
    echo "$MONGO_DIR already exists; updating core and ui containers"
    echo "Stopping running containers"
    docker stop core ui
    echo "Removing previous containers"
    docker rm -f core ui
    docker-compose pull core ui
    docker-compose up -d
    echo "Migrating database schema"
    docker cp database-migrate.py core:/opt
    docker exec -ti core python /opt/database-migrate.py
    echo "Containers updated successfully"
fi
