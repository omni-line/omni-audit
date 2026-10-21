FROM python:3.12-slim
# pip install --extra-index-url in a comment is ignored
RUN pip install --extra-index-url https://download.pytorch.org/whl/cu121 torch
RUN uv pip install --extra-index-url https://pypi.acme.corp/simple acme-sdk
ENV UV_INDEX_STRATEGY=unsafe-best-match
