#!/bin/bash

# Generate RSA private key
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048

# Extract public key
openssl rsa -pubout -in private_key.pem -out public_key.pem

echo "Keys generated: private_key.pem, public_key.pem"
echo "To use them, set the following environment variables:"
echo "export JWT_PRIVATE_KEY=\"\$(cat private_key.pem)\""
echo "export JWT_PUBLIC_KEY=\"\$(cat public_key.pem)\""
