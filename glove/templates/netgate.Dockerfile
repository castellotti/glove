# glove netgate — instrumented forwarder + telemetry collector
# (docs/planning/network-observability.md). Stdlib-only Python; the build
# context is staged by glove (glove/observe.py: build_netgate) and holds just
# this file and the `netgate` package.
FROM python:3.12-alpine

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt

COPY netgate /opt/netgate

# Compose always runs this as the operator's non-root uid:gid, cap_drop ALL,
# no-new-privileges, read-only rootfs. `nobody` is only the fallback.
USER 65534:65534
ENTRYPOINT ["python", "-m", "netgate"]
CMD ["--help"]
