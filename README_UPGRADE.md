# Upgrade Instructions from Cloud Exchange 2/3 to Cloud Exchange 3.1.5 or greater

1. Enter existing Cloud Exchange Directory
  - `cd netskope/ta_cloud_exchange`

2. Shutdown existing Cloud Exchange 2 instance
  - `docker-compose stop`

3. Remove existing container definitions NOTE: this does NOT remove your data
  - `docker-compose rm`
  - Yes you want to delete

4. Make backup of your Cloud Exchange database
  - `cd ..`
  - `mv ta_cloud_exchange ta_cloud_exchange_2_backup`

5. Install New version of Cloud Exchange 3
  - `cp ta_cloud_exchange_3.zip netskope/`
  - `unzip ta_cloud_exchange_3.zip`

6. Copy Data from Cloud Exchange Backup made in Step 4 to Cloud Exchange 3
  - `sudo cp -R ta_cloud_exchange_2_backup/data/mongo-data/* data/mongo-data/data/db/`

7. Execute the setup script
  - `sudo ./setup`

8. Launch Cloud Exchange 3
  - `sudo ./start`
