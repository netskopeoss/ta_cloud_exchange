# Quick Start Install Documentation!
Full documentation can be found here: [Netskope Cloud Exchange](https://docs.netskope.com/en/netskope-cloud-exchange.html)
## Prerequisites

 - Currently, CE is not supported on macOS.
 - Linux System capable of supporting docker.io release of docker, and docker-compose
 - Python 3
 - Zip (For the diagnose script)
 - Minimum Requirements Below:
 	- 2 vCPU
 	- 4 GB of Memory
	- 20 GB of storage
 - Please see the full documentation for scale numbers.

## Install Procedure
 
 1. Clone repository to volume with requisite 20 GB of storage<br>
	a. `mkdir netskope`<br>
	b. `cd netskope`<br>
	c. `git clone https://github.com/netskopeoss/ta_cloud_exchange`<br> 
	Note: To use the beta branch use. `git clone -b beta https://github.com/netskopeoss/ta_cloud_exchange`<br>
 2. Execute the setup script:<br>
	a.`cd ta_cloud_exchange`<br>
	b.`sudo ./setup`<br>
 4. Launch Cloud Exchange 3<br>
 	a. `sudo ./start`<br>
 5. Open Browser to `http(s)://<host ip address>`<br>
	 
Note: If you want to add your SSL certificate, you can add them to the `ta_cloud_exchange/data/ssl_certs` directory. The name of the certificate file should be `cte_cert.crt` and `cte_cert_key.key`<br>

## Troubleshooting

1. If you issue sudo ./start and you are presented with a help screen.
 
   - Please download a newer version of docker-compose from:
   [https://docs.docker.com/compose/install/](https://www.digitalocean.com/community/tutorials/how-to-install-docker-compose-on-ubuntu-18-04)

2. If bad gateway is received when you try to login:

   - Check if  step 2 was done correctly:
   `ls -lash data`
   ```
   4.0K drwxrwxr-x 6 ubuntu ubuntu 4.0K Sep  9 08:53
   4.0K drwxrwxr-x 3 ubuntu ubuntu 4.0K Nov  1 18:47 
   4.0K drwxrwxr-x 3 ubuntu ubuntu 4.0K Sep 29 12:31 custom_plugins
   4.0K drwxrwxr-x 3 1001 1001 4.0K Sep 29 12:37 mongo-data
   4.0K drwxrwxr-x 2 ubuntu ubuntu 4.0K Sep  9 08:53 rabbitmq
   4.0K drwxrwxr-x 2 ubuntu ubuntu 4.0K Sep 10 14:49 ssl_certs
   ```
   Note the mask on line with custom_plugins - mask should be 775<br> 
   Note ownership of mongo-data - should represent 1001:1001

3. If you get `SyntaxError: invalid syntax` while running `sudo ./setup`
   - Try to run `sudo python3 setup`

 
