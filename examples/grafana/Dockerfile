FROM grafana/grafana as build
USER root
RUN cd / && \
    apk update && \
    apk add --no-cache git py3-pip && \
    apk add python3-dev gcc g++ libc-dev cmake make linux-headers && \
    pip3 install ninja meson && \
    git clone --branch 0.2.3 https://github.com/igankevich/chainsaw && \
	cd chainsaw && \
	meson -Dbuildtype=release build && \
	ninja -C build && \
	ninja -C build install && \
	yes | pip3 uninstall ninja meson && \
	yes | apk del py3-pip git python3-dev && \
	cd .. && \
	rm -rf chainsaw && \
    cp run.sh /usr/share/grafana
RUN cd / && \
    chainsaw-blacklist / && \
    (chainsaw-whitelist timeout 5s /run.sh || true) && \
    echo $GF_PATHS_HOME >> whitelist && \
    find $GF_PATHS_HOME/public -type f >> whitelist && \
    echo $GF_PATHS_CONFIG >> whitelist && \
    echo $GF_PATHS_DATA >> whitelist && \
    echo $GF_PATHS_LOGS >> whitelist && \
    echo $GF_PATHS_PLUGINS >> whitelist && \
    echo $GF_PATHS_PROVISIONING >> whitelist && \
    echo /usr/bin/timeout >> whitelist && \
    echo /usr/share/grafana/public >> whitelist && \
    echo /lib/ld-musl-x86_64.so.1 >> whitelist && \
    echo /lib64/ld-linux-x86-64.so.2 >> whitelist && \
    echo /etc/hostname >> whitelist && \
    chainsaw-diff && \
    chainsaw-cut --confirm diff

FROM scratch
COPY --from=build / /

ENTRYPOINT [ "/usr/share/grafana/bin/grafana-server", "--homepath=/usr/share/grafana", "--config=/etc/grafana/grafana.ini", "--packaging=docker", "$@", "cfg:default.log.mode=console", "cfg:default.paths.data=/var/lib/grafana", "cfg:default.paths.logs=/var/log/grafana", "cfg:default.paths.plugins=/var/lib/grafana/plugins", "cfg:default.paths.provisioning=/etc/grafana/provisioning" ]