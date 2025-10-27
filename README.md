# Quick Start Install Documentation!

Full documentation can be found here: [Netskope Cloud Exchange](https://docs.netskope.com/en/netskope-help/integrations-439794/netskope-cloud-exchange/)

## Prerequisites

- Currently, CE is not supported on macOS.
- Python ~ Version mentioned in below documentation
- Docker/Podman along with Docker compose/podman-compose
- Zip (For the diagnose script and for upgrade/migration process)
- Please see the full [documentation](https://docs.netskope.com/en/netskope-help/integrations-439794/netskope-cloud-exchange/about-cloud-exchange/cloud-exchange-system-requirements) for scale numbers.

## Install Procedure for standalone deployment in Ubuntu/RHEL VM

1.  Clone repository to volume with requisite 20 GB of storage<br>
    a. `mkdir netskope`<br>
    b. `cd netskope`<br>
    c. `git clone https://github.com/netskopeoss/ta_cloud_exchange`<br>
    Note: To use the beta branch use. `git clone -b beta https://github.com/netskopeoss/ta_cloud_exchange`<br>
2. Checkout the Desired Version.
  Before proceeding, checkout the desired version of the repository. For example, to checkout version 6.0.0:<br>
    a. `git checkout v6.0.0`<br>
3.  Execute the setup script:<br>
    a. `sudo ./setup`<br>
4.  Launch Cloud Exchange<br>
    a. `sudo ./start`<br>
5.  Open Browser to `http(s)://<host ip address>`<br>

Note: If you want to add your SSL certificate, you can add them to the `ta_cloud_exchange/data/ssl_certs` directory. The name of the certificate file should be `cte_cert.crt` and `cte_cert_key.key`<br>

## Install Procedure for CE as a VM deployment

- Download the latest version of OVA from this [link](https://cloud-exchange-store.s3.us-east-1.amazonaws.com/cloudexchange/ova/cloud-exchange-6.0.0-20251124.ova).

## Upgrade Cloud Exchange

- Upgrade Cloud Exchange Deployment to latest version follow the steps mentioned in [Upgrade documentation](https://docs.netskope.com/en/netskope-help/integrations-439794/netskope-cloud-exchange/upgrade-cloud-exchange).

## Migrate Cloud Exchange

- Migrate Cloud Exchange Deployment to latest version follow the steps mentioned in [Migration documentation](https://docs.netskope.com/en/netskope-help/integrations-439794/netskope-cloud-exchange/migrate-cloud-exchange).

## Troubleshooting

- Please refer [Troubleshooting and FAQs](https://docs.netskope.com/en/netskope-help/integrations-439794/netskope-cloud-exchange/cloud-exchange-troubleshooting/) Guide.
