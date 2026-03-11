FROM ghcr.io/openwallet-foundation/acapy-agent:py3.13-1.5.1 AS base

# Install webvh plugin from acapy-plugins repository
USER root

RUN pip install git+https://github.com/openwallet-foundation/acapy-plugins@1.5.1#subdirectory=webvh

# Switch back to default aries user
USER aries

ENTRYPOINT ["/bin/bash", "-c", "aca-py \"$@\"", "--"]
CMD ["start"]
