ARG PYTHON_IMAGE=python:3.14.3-slim-trixie@sha256:5e59aae31ff0e87511226be8e2b94d78c58f05216efda3b07dbbed938ec8583b

FROM ${PYTHON_IMAGE} AS build-stage

WORKDIR /app

COPY . /app/

RUN pip install --upgrade pip && \
    pip install .

FROM ${PYTHON_IMAGE} AS prod-stage

COPY --from=build-stage /usr/local /usr/local

# git keeps the CVE List.
RUN apt-get update && \
    apt-get install --yes --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

# Runs as an unprivileged user, by UID so Kubernetes' runAsNonRoot can check it. The feeds' copies
# go in DATA_DIR (/data), a volume.
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin advisory-map
USER 10001

EXPOSE 8080
ENTRYPOINT ["advisory-map"]
