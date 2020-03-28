This is a simple UDP Proxy for DNS requests.
It intercepts and responds to CAA request (with a static value) and ACME requests reading the content from a file. All the other requests will be forwarded to Burp Collaborator.

I wrote this to obtain valid Let's Encrypt certificates DNS requests for a Burp Collaborator server. Since Burp Collaborator DNS is not configurable and cannot be used to serve ACME and CAA responses (and changing the DNS configuration every 3 months is a PITA), the proxy will intercept the requests from Let's encrypt and serve the correct responses.

## Requirements
The project requires python3 and scapy.
To install the requirements:
`pip install -r requirements.txt`


## Configuration
To make the proxy work in conjunction with BurpCollaborator you will have to perform some steps:
* move collaborator DNS on a port different from the 53, for example 55353
* configure the proxy to forward the normal traffic to Burp Collaborator
* set the correct output file in `authentication.sh`
* configure the `certbot` to use the authentication script `authentication.sh`

### BurpCollaborato
You must edit the the configuration of BurpCollaborator to move the proxy to another port.

```JSON
{
  ....
  "dns": {
  	...
    "ports" : 55353
  }
} 

```

## The proxy
The configuration is in JSON format, every value in the configuration file will override the ones passed in the command line. Every command line argument can be specified in the dictionary as a couple key, value.
Below is an example of configuration file:
```JSON
{
	"destination": "127.0.0.1",
	"destination_port": 55353,
	"ip": "0.0.0.0",
	"port": 53,
	"domain": "somedomain.com",
	"acme_file": "/tmp/acme-challenge",
	"verbose": false,
	"uid_name": "nobody",
	"gid_name": "nobody"
}
```

You can start it manually or setup a system service to start it at boot time.


## authentication.sh
The script is used to cleanly write the acme challenge to a file. The output file must be the same `acme_file` read from the proxy.
The authentication file is literally one line of code (two if you use a variable :) )
```bash
#!/bin/bash
CHALLENGE_PATH="/tmp/acme-challenge"
# write the challenge to a file. This must be the sameone read from the proxy
echo "$CERTBOT_VALIDATION" >> $CHALLENGE_PATH
```

## Certbot
You can run `certbot` manually or add create a cronjob.
```bash
certbot-auto certonly -d somedomain.com -d '*.somedomain.com'  --server https://acme-v02.api.letsencrypt.org/directory --manual --agree-tos --no-eff-email --manual-public-ip-logging-ok --preferred-challenges dns-01 --manual-auth-hook  <path_to_autentication.sh> -m info@somedomain.com -q
```
