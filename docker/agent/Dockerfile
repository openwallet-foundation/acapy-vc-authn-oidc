FROM ghcr.io/openwallet-foundation/acapy-agent:py3.12-1.4.0 AS base

# Install webvh plugin from acapy-plugins repository
# Using the same approach as Traction
USER root

# Install webvh plugin directly from GitHub
# Using commit before Python 3.13 upgrade (Dec 15, 2025)
# This is the last version compatible with Python 3.12 and ACA-Py 1.3.2
RUN pip install git+https://github.com/openwallet-foundation/acapy-plugins@7a1a7c644ed4525d8eaf182a88c179ca5453a6f6#subdirectory=webvh

# Switch back to default aries user
USER aries

ENTRYPOINT ["/bin/bash", "-c", "aca-py \"$@\"", "--"]
CMD ["start"]
