#!/bin/bash

###############################################################################
# Copyright 2021 Netskope, Inc.
# Redistribution and use in source and binary forms, with or without modification, 
# are permitted provided that the following conditions are met:
# 1: Redistributions of source code must retain the above copyright notice, this 
# list of conditions and the following disclaimer.
# 2: Redistributions in binary form must reproduce the above copyright notice, 
# this list of conditions and the following disclaimer in the documentation and/or
# other materials provided with the distribution.
# Neither the name of the copyright holder nor the names of its contributors may
# be used to endorse or promote products derived from this software without specific
# prior written permission.
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, 
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT 
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR 
# PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
# POSSIBILITY OF SUCH DAMAGE
###############################################################################

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
