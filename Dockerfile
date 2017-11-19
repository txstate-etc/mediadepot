FROM clux/muslrust AS builder

COPY . /root/
WORKDIR /root/
RUN update-ca-certificates \
  && cargo test \
  && cargo build --release --target x86_64-unknown-linux-musl

FROM scratch AS deploy
COPY --from=builder /etc/ssl/certs /etc/ssl/certs/
COPY --from=builder /root/target/x86_64-unknown-linux-musl/release/mediadepot /bin/ 
WORKDIR /var/lib/www/
CMD ["/bin/mediadepot"]
