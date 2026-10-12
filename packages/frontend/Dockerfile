# Build Stage
FROM node:20-alpine AS builder

WORKDIR /app

# Copy root manifests and workspace configs
COPY package.json package-lock.json* ./
COPY packages/frontend/package.json ./packages/frontend/

# Install dependencies
RUN npm install

# Copy frontend source
COPY packages/frontend ./packages/frontend

# Build Next.js application
ENV NEXT_TELEMETRY_DISABLED=1
RUN cd packages/frontend && npm run build

# Production Runner Stage
FROM node:20-alpine AS runner

WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3001

RUN apk add --no-cache wget

# Copy built artifacts
COPY --from=builder /app/packages/frontend/public ./packages/frontend/public
COPY --from=builder /app/packages/frontend/.next/standalone ./
COPY --from=builder /app/packages/frontend/.next/static ./packages/frontend/.next/static

EXPOSE 3001

USER node

CMD ["node", "packages/frontend/server.js"]
