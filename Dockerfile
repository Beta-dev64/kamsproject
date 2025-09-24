# syntax=docker/dockerfile:1

# ---- Base dependencies stage ----
FROM node:20-alpine AS deps
WORKDIR /app

# Install OS deps (if needed later)
RUN apk add --no-cache bash

# Copy lockfile and package.json
COPY package.json yarn.lock ./

# Install deps (including dev for build)
RUN yarn install --frozen-lockfile

# ---- Build stage ----
FROM node:20-alpine AS builder
WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY package.json yarn.lock tsconfig.json ./
COPY src ./src

# Build TypeScript
RUN yarn build

# ---- Production runtime stage ----
FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production

# Create non-root user
RUN addgroup -S nodejs && adduser -S nodeusr -G nodejs

# Only install production dependencies
COPY package.json yarn.lock ./
RUN yarn install --frozen-lockfile --production && yarn cache clean

# Copy built files
COPY --from=builder /app/dist ./dist

# Expose port (Render provides $PORT)
ENV PORT=8080
EXPOSE 8080

# Drop privileges
USER nodeusr

# Start the server
CMD ["node", "dist/index.js"]
