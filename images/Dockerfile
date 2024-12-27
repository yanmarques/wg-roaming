FROM docker.io/golang:1.23.4-alpine3.21 AS builder

WORKDIR /build/
COPY . /build/
RUN go build -ldflags "-s -w"

FROM docker.io/alpine:3.21

RUN mkdir /opt/bin/
COPY --from=builder /build/wg-roaming /opt/bin/

ENTRYPOINT "/opt/bin/wg-roaming"
