FROM node:20-alpine

RUN apk add --no-cache bash coreutils

WORKDIR /app

# Copy all POC files
COPY package-vulnerable.json package-patched.json ./
COPY poc-*.mjs run-all.sh ./

RUN chmod +x run-all.sh

# Install vulnerable deps
RUN mkdir -p /app/vulnerable && \
    cp package-vulnerable.json /app/vulnerable/package.json && \
    cd /app/vulnerable && npm install --ignore-scripts 2>/dev/null

# Install patched deps
RUN mkdir -p /app/patched && \
    cp package-patched.json /app/patched/package.json && \
    cd /app/patched && npm install --ignore-scripts 2>/dev/null

CMD ["bash", "run-all.sh"]
