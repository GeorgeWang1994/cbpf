FROM golang:1.19 AS build

RUN apt update -y && apt install -y libelf-dev

COPY collector /app/

COPY probe/build/libevent.so /lib64/

RUN ldconfig

WORKDIR /app/

RUN cd /app/ && go mod tidy && go build -o collector cmd/main.go

# docker build -t eventprobe:latest .
FROM centos:7

WORKDIR /app/
# libscap 和 libsinsp 是 Falco 项目中的两个重要用户空间库，用于处理获取自内核模块和 eBPF 探针的 syscall 事件数据。
# 具体而言，libscap 库直接与驱动程序进行通信，并从环形缓冲区（由驱动程序放置）读取 syscall 事件，然后将其发送到 libsinsp 进一步处理。同时，libscap 还实现了操作系统状态收集，并支持对 scap 文件的读写。
# libsinsp 库则在收到 libscap 发送的事件后，可以通过规则引擎对事件进行筛选和评估，并丰富事件的机器状态。此外，libsinsp 还能够管理输出结果。
RUN  curl https://k8s-bpf-probes-public.oss-cn-hangzhou.aliyuncs.com/kindling-falcolib-probe-v0.3.0.tar.gz -o kindling-falcolib-probe.tar.gz --progress

COPY probe/build/libevent.so /lib64/

RUN ldconfig

WORKDIR /app/

COPY probe-loader /usr/bin/probe-loader

RUN chmod +x  /usr/bin/probe-loader

COPY collector/config/config.yaml /app/

COPY --from=build /app/collector /app/

COPY start.sh /app/

CMD ["sh", "start.sh"]
