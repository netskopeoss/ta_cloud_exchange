Install Instructions for Cloud Exchange 3
=========================================

        1: Copy ta_cloud_exchange_3.zip to host system
           

        2: Create Directory for Cloud Exchange
                mkdir netskope

        3: Copy Cloud Exchange to Netskope Directory
                cp ta_cloud_exchange_3.zip netskope

        4: unzip Cloud Exchange
                cd netskope
                unzip ta_cloud_exchange_3.zip

        5: Set Database Directory permissions
                sudo chown -R 1001:1001 data/mongo-data
                sudo chmod 775 data/custom_plugins

        6: Launch Cloud Exchange 3
                docker-compose up -d

