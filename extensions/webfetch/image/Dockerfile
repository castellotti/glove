# glove `webfetch` MCP sidecar: webfetch_mcp.py (fetch_url through the
# session's egress proxy) served as streamable HTTP on :8000. Dependencies are
# installed from the committed, hash-pinned requirements.txt (`uv pip compile
# requirements.in --universal --python-version 3.12 --generate-hashes -o
# requirements.txt`). glove runs it as the session uid, cap-less, with a
# read-only rootfs, on the extension's internal network: its peers are one
# harness forwarder and the egress proxy (or, with observe, a gate in front of it).
FROM docker.io/library/python:3.12-slim@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
COPY requirements.txt /opt/glove/webfetch/requirements.txt
RUN pip install --require-hashes --only-binary=:all: -r /opt/glove/webfetch/requirements.txt
COPY webfetch_mcp.py /opt/glove/webfetch/webfetch_mcp.py
CMD ["python3", "/opt/glove/webfetch/webfetch_mcp.py"]
