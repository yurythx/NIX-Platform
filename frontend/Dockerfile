# syntax=docker/dockerfile:1

# ---- deps ----
FROM node:20-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

# ---- builder ----
FROM node:20-alpine AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
# Next.js "standalone" output produces a minimal self-contained server.
RUN npm run build

# ---- runtime ----
FROM node:20-alpine AS runtime
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
