# syntax=docker/dockerfile:1.7
FROM mcr.microsoft.com/dotnet/aspnet:11.0 AS base

# Supply the public development CA root as a BuildKit secret when building a
# dev image. The public root is installed in the final image trust store; the
# secret mount keeps it out of the build context and intermediate build layer.
RUN --mount=type=secret,id=development-ca-root,required=false \
    if [ -f /run/secrets/development-ca-root ]; then \
      install -m 0644 /run/secrets/development-ca-root /usr/local/share/ca-certificates/transactionprocessing-development-ca.crt && \
      update-ca-certificates; \
    fi

WORKDIR /home/txnproc/
COPY ["/config", "config"]
COPY ["/syncfusion/QtBinariesLinux", "syncfusion/QtBinariesLinux"]
