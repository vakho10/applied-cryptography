openssl genrsa -out alice_private.key 2048
openssl req -new -x509 -key alice_private.key -out alice_cert.pem -days 365 -subj "/CN=Alice"

openssl genrsa -out bob_private.key 2048
openssl req -new -x509 -key bob_private.key -out bob_cert.pem -days 365 -subj "/CN=Bob"