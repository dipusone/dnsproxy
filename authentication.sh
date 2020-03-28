#!/bin/bash
# Autenticator for the certbot
CHALLENGE_PATH="/tmp/acme-challenge"

# write the challenge to a file. This must be the sameone read from the proxy
echo "$CERTBOT_VALIDATION" >> $CHALLENGE_PATH
