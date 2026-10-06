FROM alpine@sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0
ARG TARGETARCH
COPY packages-${TARGETARCH}.lock /packages.lock
RUN set -eu; mkdir /packages; cd /packages; \
    while read -r digest url; do \
      name="${url##*/}"; wget -q -O "$name" "$url"; \
      printf '%s  %s\n' "$digest" "$name" | sha256sum -c -; \
    done < /packages.lock; \
    apk add --no-network /packages/*.apk; \
    rm -rf /packages /packages.lock; \
    find / -xdev -type f -perm /6000 -exec chmod ug-s {} ';'; \
    setuid="$(find / -xdev -type f -perm /6000)"; \
    [ -z "$setuid" ] || { echo "setuid or setgid files remain: $setuid" >&2; exit 1; }; \
    caps="$(getcap -r / 2>/dev/null)"; \
    [ -z "$caps" ] || { echo "file capabilities remain: $caps" >&2; exit 1; }; \
    mkdir /work; chown 1000:1000 /work
ENV PATH=/usr/bin:/bin:/usr/sbin:/sbin HOME=/work LANG=C
WORKDIR /work
USER 1000:1000
