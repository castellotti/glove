# glove `llm` key sidecar: llm_auth.py (stdlib only) holds the session's LLM
# key and injects it into the harness's requests (see its docstring). glove
# runs it as the session uid, cap-less, with a read-only rootfs, on the
# extension's internal network only: its peers are the harness's `llm`
# forwarder and the `llm-upstream` forwarder.
FROM docker.io/library/python:3.12-slim@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY llm_auth.py /opt/glove/llm/llm_auth.py
CMD ["python3", "/opt/glove/llm/llm_auth.py"]
