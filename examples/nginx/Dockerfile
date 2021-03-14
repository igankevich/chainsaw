FROM nginx:latest as build
RUN apt-get update && \
    apt-get install git python3-pip -y && \
    yes | pip3 install ninja meson && \
    git clone --branch 0.2.3 https://github.com/igankevich/chainsaw && \
	cd chainsaw && \
	meson -Dbuildtype=release build && \
	ninja -C build && \
	ninja -C build install && \
	yes | pip3 uninstall ninja meson && \
	yes | apt purge python3-pip git && \ 
	yes | apt autoremove && \
	cd .. && \
	rm -rf chainsaw
RUN chainsaw-blacklist / && \
    (chainsaw-whitelist timeout 5s /usr/sbin/nginx -g 'daemon off;' || true) && \
    echo /usr/bin/timeout >> whitelist && \
    echo /usr/sbin/nginx >> whitelist && \
    echo /var/run >> whitelist && \
    echo /lib/x86_64-linux-gnu/ld-2.28.so >> whitelist && \
    echo /lib64/ld-linux-x86-64.so.2 >> whitelist && \
    chainsaw-diff && \
    chainsaw-cut --confirm diff && \
    (timeout 5s /usr/sbin/nginx -g 'daemon off;' || true)
    #echo "DIFF" && cat diff && \

FROM scratch
COPY --from=build / /

ENTRYPOINT ["/usr/sbin/nginx", "-g", "daemon off;"]
