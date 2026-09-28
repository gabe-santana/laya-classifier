FROM python:3.12-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 LAYA_DEVICE=cpu

# The CPU build of PyTorch keeps the image a fraction of the CUDA one.
RUN pip install torch --index-url https://download.pytorch.org/whl/cpu

COPY pyproject.toml README.md ./
COPY src ./src
COPY config ./config
COPY samples ./samples
RUN pip install .

ENV LAYA_SCREENER_CONFIG=/app/config/screener.json LAYA_SCREENER_SAMPLES=/app/samples
EXPOSE 8000
CMD ["laya-screener", "serve", "--host", "0.0.0.0", "--port", "8000"]
