# Copyright © 2021 Irina Nikolaeva, Ivan Gankevich
# SPDX-License-Identifier: Unlicense

FROM nginx:latest as build

RUN apt-get update && \
    apt-get install -y git ninja-build meson g++ && \
    git clone --branch master https://github.com/igankevich/chainsaw && \
	cd chainsaw && \
	meson -Dbuildtype=release build && \
	ninja -C build && \
	ninja -C build install && \
	cd .. && \
	rm -rf chainsaw

RUN chainsaw-blacklist / && \
    (chainsaw-whitelist timeout 5s /usr/sbin/nginx -g 'daemon off;' || true) && \
    echo /usr/sbin/nginx >> whitelist && \
    echo /var/run >> whitelist && \
    chainsaw-diff && \
    chainsaw-cut --confirm diff

FROM scratch
COPY --from=build / /

ENTRYPOINT ["/usr/sbin/nginx", "-g", "daemon off;"]
