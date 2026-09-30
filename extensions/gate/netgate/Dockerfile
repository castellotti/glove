# glove netgate — instrumented forwarder + telemetry collector (the `gate`
# extension's image; build context: this package). Stdlib-only Python.
FROM docker.io/library/python:3.12.14-alpine@sha256:4c47124a8391cb7a9f571164147d154777cf012a4ece5f86097130d7a4478111

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt

COPY . /opt/netgate

# Compose always runs this as the operator's non-root uid:gid, cap_drop ALL,
# no-new-privileges, read-only rootfs. `nobody` is only the fallback.
USER 65534:65534
ENTRYPOINT ["python", "-m", "netgate"]
CMD ["--help"]
