#!/bin/sh
# kstore, baked in by glove's `rag` extension (the package lives in /opt/glove/rag).
PYTHONPATH="/opt/glove/rag${PYTHONPATH:+:$PYTHONPATH}" exec python3 -m kstore "$@"
