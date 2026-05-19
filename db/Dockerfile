FROM --platform=$BUILDPLATFORM golang:1.26.3-trixie AS gosu-builder

ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
ARG GOSU_VERSION=1.19

RUN set -eux; \
    goArm=''; \
    case "${TARGETARCH}${TARGETVARIANT}" in \
        amd64) goArch='amd64' ;; \
        arm64) goArch='arm64' ;; \
        386) goArch='386' ;; \
        armv5) goArch='arm'; goArm='5' ;; \
        armv6) goArch='arm'; goArm='6' ;; \
        armv7) goArch='arm'; goArm='7' ;; \
        ppc64le) goArch='ppc64le' ;; \
        riscv64) goArch='riscv64' ;; \
        s390x) goArch='s390x' ;; \
        *) echo "unsupported architecture: ${TARGETARCH}${TARGETVARIANT}"; exit 1 ;; \
    esac; \
    GOOS="${TARGETOS:-linux}" GOARCH="$goArch" GOARM="$goArm" CGO_ENABLED=0 GOBIN=/out \
        go install -trimpath -ldflags="-s -w" "github.com/tianon/gosu@${GOSU_VERSION}"; \
    go version -m /out/gosu

FROM postgres:15.17-trixie


RUN apt-get update && \
    apt-get upgrade -y && \
    rm -rf /var/lib/apt/lists/*

COPY --from=gosu-builder /out/gosu /usr/local/bin/gosu

RUN set -eux; \
    chmod +x /usr/local/bin/gosu; \
    gosu --version; \
    gosu nobody true

COPY init.sql /docker-entrypoint-initdb.d/

ENV POSTGRES_DB=docdb
ENV POSTGRES_USER=postgres
ENV POSTGRES_PASSWORD=postgres