# Generate temporary local keys
openssl req -x509 -newkey rsa:4096 -nodes -sha256 -days 3650 -keyout local.key.pem -out local.cert.pem -subj '/C=US/ST=Texas/L=San Marcos/O=Texas State University/CN=*.txstate.edu' -reqexts SAN -config <(cat /etc/ssl/openssl.cnf <(printf '[SAN]\nsubjectAltName=DNS:mediaflow-dev.its.txstate.edu,DNS:mediaflow1.its.txstate.edu,DNS:mediaflow-qa1.its.qual.txstate.edu\n'))

