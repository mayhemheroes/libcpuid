FROM --platform=linux/amd64 ubuntu:20.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y automake pkg-config libtool build-essential

COPY . /repo
WORKDIR /repo
RUN autoreconf -if
RUN ./configure
RUN make -j8

FROM ubuntu:20.04 as package
COPY --from=builder /repo/cpuid_tool/.libs/cpuid_tool /
COPY --from=builder /repo/libcpuid/.libs /lib
ENV LD_LIBRARY_PATH=/lib
