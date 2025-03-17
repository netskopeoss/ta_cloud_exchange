# Quick Start Install Documentation!

Full documentation can be found here: [Netskope Cloud Exchange](https://docs.netskope.com/en/netskope-help/integrations-439794/netskope-cloud-exchange/)

## Prerequisites

- Currently, CE is not supported on macOS.
- Linux System capable of supporting docker.io release of docker, and docker compose
- Python 3.8.x
- Zip (For the diagnose script)
- Minimum Requirements:
  - 8 vCPU (only x86 architecture with AVX is supported)
  - 16 GB of Memory
  - 80 GB of storage
- Please see the full [documentation](https://docs.netskope.com/en/netskope-help/integrations-439794/netskope-cloud-exchange/about-cloud-exchange/cloud-exchange-system-requirements) for scale numbers.
- Use latest docker version (https://docs.docker.com/engine/install/centos/)
- Use latest docker compose version (https://docs.docker.com/compose/install)

## Install Procedure for standalone deployment

1.  Clone repository to volume with requisite 20 GB of storage<br>
    a. `mkdir netskope`<br>
    b. `cd netskope`<br>
    c. `git clone https://github.com/netskopeoss/ta_cloud_exchange`<br>
    Note: To use the beta branch use. `git clone -b beta https://github.com/netskopeoss/ta_cloud_exchange`<br>
2.  Execute the setup script:<br>
    a. `sudo ./setup`<br>
3.  Launch Cloud Exchange<br>
    a. `sudo ./start`<br>
4.  Open Browser to `http(s)://<host ip address>`<br>

Note: If you want to add your SSL certificate, you can add them to the `ta_cloud_exchange/data/ssl_certs` directory. The name of the certificate file should be `cte_cert.crt` and `cte_cert_key.key`<br>

## Install Procedure for CE as a VM deployment

- Download the latest version of OVA from this [link](https://cloud-exchange-store-beta.s3.us-east-1.amazonaws.com/cloudexchange/ova/cloud-exchange-5.1.1-20250313.ova).

## Troubleshooting

1. If you issue sudo ./start and you are presented with a help screen.

   - Please download a newer version of docker compose from:
     https://docs.docker.com/compose/install

2. If bad gateway is received when you try to login:

   - Check if step 2 was done correctly:
     `ls -lash data`

   ```
   0 drwxrwxrwx. 2 devuser devuser   22 Apr 27  2023 ca_certs
   0 drwxr--r--. 3 devuser devuser   60 Apr 25  2023 custom_plugins
   0 drwxrwxr-x. 2 999      999      27 Apr 25  2023 database-init
   0 drwxr--r--. 3 999      999      18 May 22 13:18 mongo-data
   0 drwxr--r--. 3 devuser devuser   37 Nov  3 19:10 rabbitmq
   0 drwxrw-rw-. 2 devuser devuser  106 Apr 25  2023 ssl_certs
   ```

   - Note the mask on line with custom_plugins - mask should be 775
   - Note ownership of mongo-data - should represent 999:999
   - Note ownership of database-init - should represent 999:999
   - Note ownership of rabbitmq - should represent 1001:1001

3. If you get `SyntaxError: invalid syntax` while running `sudo ./setup`
   - Try to run `sudo python3 setup`

For more informations, please refer [Troubleshooting and FAQs](https://docs.netskope.com/en/netskope-help/integrations-439794/netskope-cloud-exchange/cloud-exchange-troubleshooting/) Guide.
