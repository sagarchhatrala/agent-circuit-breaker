FROM python:3.12-slim
COPY dist/*.whl /tmp/wheels/
RUN python -m pip install --no-cache-dir --no-index /tmp/wheels/*.whl
USER 10001:10001
WORKDIR /tmp
ENTRYPOINT ["python", "-I"]
