# Quick Start Install Documentation!
Full documentation can be found here: [Netskope Cloud Exchange](https://docs.netskope.com/en/netskope-cloud-exchange.html)
## Prerequisites
 - Linux System capable of supporting docker.io release of docker, and docker-compose
 - Python 3
 - Zip (For the diagnose script)
 - Miniumum Requirements Below:
 	- 2 vCPU
 	- 4 GB of Memory
	- 20 GB of storage
 - Please see full documentation for scale numbers.

 ## Install Procedure
 
 1. Clone repository to volume with requisite 20 GB of storage<br>
	a. `mkdir netskope`<br>
	b. `cd netsokpe`<br>
	c. `git clone https://github.com/netskopeoss/ta_cloud_exchange`<br>   
 2. Execute the setup script:<br>
	a. `sudo ./setup`<br>
 4. Launch Cloud Exchange 3<br>
 	a. `sudo ./start`<br>
 5. Open Browser to `http(s)://<host ip address>`<br>
	 

 ## Troubleshooting
If bad gateway is received when you try to login:
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

 
