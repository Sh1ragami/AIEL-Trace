FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1

# Qt WebEngine and X11 runtime deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    libx11-xcb1 libxkbcommon-x11-0 libglu1-mesa libnss3 libxcomposite1 \
    libxcursor1 libxdamage1 libxi6 libxtst6 libdrm2 libgbm1 libasound2 \
    libxrandr2 libxrender1 libxfixes3 libfontconfig1 libfreetype6 \
    libjpeg62-turbo libpng16-16 libglib2.0-0 libegl1 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md /app/
COPY mbsd_tool /app/mbsd_tool

RUN pip install --upgrade pip && pip install .

# Display forwarding
ENV DISPLAY=:0 \
    QT_X11_NO_MITSHM=1 \
    QTWEBENGINE_DISABLE_SANDBOX=1

CMD ["python", "-m", "mbsd_tool"]
