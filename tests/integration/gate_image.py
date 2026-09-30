"""Build the gate extension's netgate image for a runtime and print its tag.

    uv run python tests/integration/gate_image.py docker|podman
"""

import subprocess
import sys

from glove.extensions import Active, discover, image_tag

m = discover()["gate"]
tag = image_tag(Active(m, {}), "netgate")
if subprocess.run([sys.argv[1], "image", "inspect", tag], capture_output=True).returncode != 0:
    subprocess.run([sys.argv[1], "build", "-q", "-t", tag, str(m.path / "netgate")], check=True,
                   stdout=subprocess.DEVNULL)
print(tag)
