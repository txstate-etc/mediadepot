# Example of how to generate temporary local keys with SANs
openssl req -x509 -newkey rsa:4096 -nodes -sha256 -days 3650 -keyout local.key.pem -out local.cert.pem -subj '/C=US/ST=Texas/L=San Marcos/O=Texas State University/CN=mediadepot-dev.its.txstate.edu' -reqexts SAN -config <(cat /etc/ssl/openssl.cnf <(printf '[SAN]\nsubjectAltName=DNS:mediadepot-dev2.its.txstate.edu,DNS:mediadepot-dev2.its.txstate.edu\n'))

