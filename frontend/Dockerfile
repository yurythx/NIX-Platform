# syntax=docker/dockerfile:1

# ---- deps ----
FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

# ---- builder ----
FROM node:22-alpine AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
# NEXT_PUBLIC_* vars are inlined into the client bundle at build time, not
# read at container startup — they MUST come in as build args, not just
# runtime `environment:` in docker-compose.yml.
ARG NEXT_PUBLIC_API_URL
ARG NEXT_PUBLIC_WS_URL
ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL} \
    NEXT_PUBLIC_WS_URL=${NEXT_PUBLIC_WS_URL}
# Auth/config env is only READ at request time by server code, so build
# placeholders are enough to satisfy the fail-fast checks in lib/auth —
# the real values come from docker-compose's runtime `environment:`.
ENV KEYCLOAK_ISSUER_URL=https://build-placeholder.invalid/realms/build \
    KEYCLOAK_FRONTEND_CLIENT_ID=build-placeholder \
    KEYCLOAK_FRONTEND_CLIENT_SECRET=build-placeholder \
    NEXTAUTH_SECRET=build-placeholder-please-override-at-runtime
# Next.js "standalone" output produces a minimal self-contained server.
RUN npm run build

# ---- runtime ----
FROM node:22-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
RUN addgroup -S nix && adduser -S nix -G nix

COPY --from=builder --chown=nix:nix /app/public ./public
COPY --from=builder --chown=nix:nix /app/.next/standalone ./
COPY --from=builder --chown=nix:nix /app/.next/static ./.next/static

USER nix
EXPOSE 3000
ENV PORT=3000
ENTRYPOINT ["node", "server.js"]
