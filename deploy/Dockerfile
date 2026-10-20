FROM node:22-alpine AS build
WORKDIR /app
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run lint && npm run typecheck && npm test && npm run build

FROM caddy:2-alpine
COPY deploy/Caddyfile /etc/caddy/Caddyfile
COPY --from=build /app/dist /srv
EXPOSE 80 443 443/udp

# Validate Caddyfile syntax without contacting a live public domain. Runtime
# configuration overrides this non-routable placeholder with WEBGUARD_DOMAIN.
ENV WEBGUARD_DOMAIN=validation.example.com
RUN caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
