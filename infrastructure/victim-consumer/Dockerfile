FROM node:18-alpine

WORKDIR /app

# Install bash and curl for verification and telemetry inspection
RUN apk add --no-cache bash curl

# Copy project definition and npm config
COPY package.json .npmrc /app/

# Keep container running for interactive demo and automated testing
CMD ["tail", "-f", "/dev/null"]
