# Netskope Cloud Exchange Docker Compose

There are three sections of this readme.
1: New install
2: Migrate from previous Cloud Threat Exchange
3: Upgrades

If this is a new install:
  docker-compose up -d
  https://<your ip>


If you are upgrading from Cloud Threat Exchange to Cloud Exchange!

Deploy new repo into a new folder
- IE: Old Folder netskope/ta_cloud_threat_exchange
- IE: New Folder netskope/ta_cloud_exchange

Optional: 
  If you have custom SSL Certificates, copy them to the ./data/ssl_certs directory

Make the migration script executable
  chmod +x migrate.sh

Execute the migration script
  ./migrate.sh

  Once this script has completed, you should get the following message on console:
  - Successfully migrated database to version 1.3.0

Validate your instance of Cloud Exchange is functional.
Clean up your old instance of Cloud Threat Exchange 
  IE: rm -rf netskope/ta_cloud_threat_exchange

What this script does.

This script is used to export the Mongo Database from the Container to the 
local directory export of ./data/mongo_data 
This export will prevent the rest of Cloud Exchange through future upgrades. 

After the export of the data, the script will pull the new copies of the docker
images and relaunch Cloud Exchange with the Threat Module enabled. 


UPGRADING Cloud Exchange:

Issue migrate script as mentioned above:
    If you get this message:
      ./data/mongo-data already exists

Issue:
    docker-compose pull && docker-compose stop && docker-compose up -d
