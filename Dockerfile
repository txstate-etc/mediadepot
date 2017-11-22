FROM clux/muslrust AS builder

COPY . /root/
WORKDIR /root/
RUN update-ca-certificates \
  && cargo test \
  && cargo build --release --target x86_64-unknown-linux-musl \
  && groupadd -r -g 48 mdepot \
  && groupadd -r -g 797 tls_read \
  && groupadd -g 7402 vcms \
  && useradd -r -u 48 -g 48 -G 797,7402 -c 'Media Depot Service' -d /var/lib/www mdepot \
  && mkdir -p /rootfs/etc/ssl /rootfs/bin/ /rootfs/var/lib/www \
  && cp /etc/passwd /rootfs/etc/ \
  && cp /etc/group /rootfs/etc/ \
  && cp -r /etc/ssl/certs /rootfs/etc/ssl/ \
  && cp /root/target/x86_64-unknown-linux-musl/release/mediadepot /rootfs/bin/

FROM scratch AS final
COPY --from=builder /rootfs/  /
USER mdepot
WORKDIR /var/lib/www/
CMD ["/bin/mediadepot"]
