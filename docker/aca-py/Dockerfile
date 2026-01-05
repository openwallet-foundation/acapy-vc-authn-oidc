FROM ghcr.io/openwallet-foundation/acapy-agent:py3.13-1.3.2 AS base

# Install webvh plugin from acapy-plugins repository
# Using the same approach as Traction
USER root

# Install webvh plugin directly from GitHub
# Note: Using version compatible with ACA-Py 1.3.2
RUN pip install git+https://github.com/openwallet-foundation/acapy-plugins@main#subdirectory=webvh

# Switch back to default aries user
USER aries

ENTRYPOINT ["/bin/bash", "-c", "aca-py \"$@\"", "--"]
CMD ["start"]
