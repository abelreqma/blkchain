FROM alpine:3.23.6@sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0 AS toolbuild
ARG TARGETARCH
COPY build-packages-${TARGETARCH}.lock /packages.lock
RUN set -eu; mkdir /packages; cd /packages; \
    while read -r digest url; do \
      name="${url##*/}"; wget -q -O "$name" "$url"; \
      printf '%s  %s\n' "$digest" "$name" | sha256sum -c -; \
    done < /packages.lock; \
    apk add --no-network /packages/*.apk; \
    rm -rf /packages /packages.lock
RUN set -eu; mkdir /src; cd /src; \
    wget -q -O curl.tar.gz https://curl.se/download/curl-8.22.0.tar.gz; \
    printf '%s  %s\n' d54dd598bf05927a726deb38df31c6a255ba83ff1de57c5d1464dac3ed8f44a1 curl.tar.gz | sha256sum -c -; \
    wget -q -O ike-scan.tar.gz https://codeload.github.com/royhills/ike-scan/tar.gz/c74c01fd22d9a3aae3d8ba9a0bd2eb1a2146ac6f; \
    printf '%s  %s\n' 1c55e6a53178be5f6c4c1af39a524e39a13e7bd860b3c77da5a6bd4f974e5f93 ike-scan.tar.gz | sha256sum -c -; \
    tar -xzf curl.tar.gz; tar -xzf ike-scan.tar.gz; \
    cmake -S curl-8.22.0 -B curl-build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/opt/curl -DBUILD_SHARED_LIBS=OFF -DCURL_USE_OPENSSL=OFF -DCURL_USE_GNUTLS=ON -DUSE_NGTCP2=ON -DUSE_NGHTTP2=ON -DCURL_USE_LIBPSL=OFF; \
    cmake --build curl-build --parallel 2; \
    cmake --install curl-build; \
    cd ike-scan-c74c01fd22d9a3aae3d8ba9a0bd2eb1a2146ac6f; \
    autoreconf --install; \
    ./configure --prefix=/opt/ike --with-openssl CFLAGS='-O2 -std=gnu11'; \
    make -j2; make install

FROM alpine:3.23.6@sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0
ARG TARGETARCH
COPY packages-${TARGETARCH}.lock /packages.lock
RUN set -eu; mkdir /packages; cd /packages; \
    while read -r digest url; do \
      name="${url##*/}"; wget -q -O "$name" "$url"; \
      printf '%s  %s\n' "$digest" "$name" | sha256sum -c -; \
    done < /packages.lock; \
    apk add --no-network /packages/*.apk; \
    rm -rf /packages /packages.lock; \
    mkdir /work; chown 1000:1000 /work; \
    addgroup -g 1000 worker; \
    adduser -D -H -u 1000 -G worker -h /work -s /sbin/nologin worker; \
    id -u worker >/dev/null; \
    find / -xdev -type f -perm /6000 -exec chmod ug-s {} ';'; \
    setuid="$(find / -xdev -type f -perm /6000)"; \
    [ -z "$setuid" ] || { echo "setuid or setgid files remain: $setuid" >&2; exit 1; }; \
    caps="$(getcap -r / 2>/dev/null)"; \
    [ -z "$caps" ] || { echo "file capabilities remain: $caps" >&2; exit 1; }
COPY --from=toolbuild /opt/curl/bin/curl /usr/bin/curl
COPY --from=toolbuild /opt/ike/bin/ike-scan /usr/bin/ike-scan
COPY --from=toolbuild /opt/ike/share/ /opt/ike/share/
RUN set -eu; \
    setuid="$(find / -xdev -type f -perm /6000)"; \
    [ -z "$setuid" ] || { echo "setuid or setgid files remain: $setuid" >&2; exit 1; }; \
    caps="$(getcap -r / 2>/dev/null)"; \
    [ -z "$caps" ] || { echo "file capabilities remain: $caps" >&2; exit 1; }; \
    curl -V > /tmp/curl-version; grep -q HTTP3 /tmp/curl-version; \
    ike-scan --version > /tmp/ike-version 2>&1; grep -q 'ike-scan 1.9.6' /tmp/ike-version; \
    rm /tmp/curl-version /tmp/ike-version
ENV PATH=/usr/bin:/bin:/usr/sbin:/sbin HOME=/work LANG=C
WORKDIR /work
USER 1000:1000
