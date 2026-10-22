FROM registry.access.redhat.com/ubi10/ubi:10.2 AS builder

# Install the builder dependencies
RUN dnf -y install \
    --setopt=install_weak_deps=false \
    --setopt=tsflags=nodocs \
    --setopt=deltarpm=0 \
    --allowerasing \
    python3.12-pip \
    python3.12-devel \
    git \
    gcc \
    make \
    krb5-devel \
    && dnf clean all \
    && mkdir -p /export/wheels

# Copy the project source code
COPY . /src/
WORKDIR /src

# Generate the wheels
RUN pip3.12 wheel --wheel-dir=/export/wheels '.[kerberos]'


# Build the final image using task-runner which includes oras and other Tekton tooling
FROM quay.io/konflux-ci/task-runner:1.5.0

LABEL \
    name="slan-cuan" \
    maintainer="Lightwell Developers" \
    licence="Apache-2.0"

# Copy the wheels from the builder stage
COPY --from=builder /export/ /

USER 0

ARG RH_IT_CERT
ARG KUBECTL_VERSION=1.27.2

# Install dependencies
RUN echo "${RH_IT_CERT}" | base64 -d > /etc/pki/ca-trust/source/anchors/Current-IT-Root-CAs.pem \
    && update-ca-trust \
    && microdnf install -y \
        python3.12-pip \
        jq \
        krb5-workstation \
    && curl -L https://dl.k8s.io/release/v${KUBECTL_VERSION}/bin/linux/amd64/kubectl -o /usr/bin/kubectl \
    && chmod +x /usr/bin/kubectl \
    # for CVEs in base image
    && microdnf update -y \
    && microdnf clean all \
    && pip3.12 install --no-cache-dir --no-deps /wheels/*.whl \
    && rm -rf /wheels

# Internal-request helpers from release-service-utils (direct signing)
COPY vendor/release-service-utils/scripts/python/helpers/ /opt/release-service-utils/helpers/
ENV PYTHONPATH="/opt/release-service-utils/helpers"

# Set the internal certificates
ENV REQUESTS_CA_BUNDLE=/etc/pki/tls/certs/ca-bundle.crt
ENV SSL_CERT_FILE=/etc/pki/tls/certs/ca-bundle.crt

# Embed Tekton Task definitions
COPY tekton/tasks/ /tekton/tasks/

# npm-to-Pulp release scripts
COPY scripts/npm/ /usr/local/bin/

# Run the CLI
ENTRYPOINT ["slan-cuan", "--verbose" ]
