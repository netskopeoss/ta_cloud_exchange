#!/bin/sh
mongo -- "$MONGO_INITDB_DATABASE" <<EOF
    var user = '$MONGODB_USERNAME';
    var passwd = '$MONGODB_PASSWORD';
    var dbName = '$MONGO_INITDB_DATABASE';
    db.createUser({user: user, pwd: passwd, roles: [ { role: "dbOwner", db: dbName, } ]});
EOF