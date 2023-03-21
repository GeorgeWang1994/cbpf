FROM centos:7

WORKDIR /app/
RUN  curl https://k8s-bpf-probes-public.oss-cn-hangzhou.aliyuncs.com/kindling-falcolib-probe-v0.3.0.tar.gz -o kindling-falcolib-probe.tar.gz --progress
COPY libso/libkindling.so /lib64/
RUN ldconfig

COPY probe-loader /usr/bin/probe-loader
RUN chmod +x  /usr/bin/probe-loader
COPY collector/config/config.yml /etc/collector/
COPY collector /usr/bin/collector
COPY start.sh /app/

CMD ["sh", "start.sh"]
