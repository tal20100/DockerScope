FROM python:3.12-slim AS builder

WORKDIR /build
COPY pyproject.toml README.md ./
COPY dockerscope/ dockerscope/

RUN pip install --no-cache-dir build && \
    python -m build --wheel

FROM python:3.12-slim

WORKDIR /app
COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && \
    rm /tmp/*.whl

ENTRYPOINT ["dockerscope"]
