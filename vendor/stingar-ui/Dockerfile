# Stage 1: Building the code
#FROM node:latest AS builder
# node:25.9.0-trixie-slim: Debian 13 (trixie) base.
# trixie is required (not bookworm) to actually fix:
#   CVE-2026-0861  glibc memalign  (only fixed in glibc 2.41-12+deb13u2; bookworm has no backport)
#   CVE-2025-6297  dpkg-deb        (only fixed in dpkg 1.22.22; Debian declined a bookworm backport)
FROM node:25.9.0-trixie-slim AS builder

# Accept version as build argument. No default: builds must pass
# --build-arg VERSION=v<X.Y[.Z]>. See
# Roadmap/plans/VERSIONING_OVERHAUL_PLAN.md (phase 1).
ARG VERSION
RUN test -n "${VERSION}" \
    || (echo "FATAL: --build-arg VERSION=v<X.Y[.Z]> is required (was empty)" >&2 && exit 1)

WORKDIR /app

# Apply latest Debian security updates to address base-image CVEs.
# Covers (at least):
#   CVE-2026-0861  -- glibc memalign integer overflow  (libc6 >= 2.41-12+deb13u2 on trixie)
#   CVE-2025-6297  -- dpkg-deb temp-file leak           (dpkg  >= 1.22.22         on trixie)
RUN apt-get update && \
    apt-get upgrade -y --no-install-recommends && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Update npm to latest version to address security vulnerabilities
RUN npm install -g npm@latest

# Install dependencies
COPY package*.json ./
RUN npm install --legacy-peer-deps 

# Copy the source code
COPY . .

# Rewrite package.json "version" field directly from the build arg.
# package.json uses the stripped form (e.g. 2.3); STINGAR_VERSION env
# var carries the canonical v-prefixed form (e.g. v2.3). start-server.js
# prefers the env var and re-adds the 'v' if it falls back to this file.
RUN VERSION_NUM="$(printf '%s' "${VERSION}" | sed -E 's/^v//')" \
    && node -e "const fs=require('fs');const p=require('./package.json');p.version='${VERSION_NUM}';fs.writeFileSync('package.json',JSON.stringify(p,null,2)+'\n');" \
    && node -e "console.log('package.json version =>',require('./package.json').version)"

# Clean any existing build artifacts to ensure fresh build
RUN rm -rf .next

# Enable threat-feeds nav during pre-render so the sidebar includes it (v2.4)
ARG THREAT_FEEDS_ENABLED=true
ENV THREAT_FEEDS_ENABLED=$THREAT_FEEDS_ENABLED

# Build the Next.js app with standalone output
RUN echo "Building with THREAT_FEEDS_ENABLED=${THREAT_FEEDS_ENABLED}" \
    && npm run build

# Stage 2: Run the built app
#FROM node:latest
# node:25.9.0-trixie-slim: see stage-1 comment for CVE rationale.
FROM node:25.9.0-trixie-slim

# Accept version as build argument. No default: builds must pass
# --build-arg VERSION=v<X.Y[.Z]>. See
# Roadmap/plans/VERSIONING_OVERHAUL_PLAN.md (phase 1).
ARG VERSION
RUN test -n "${VERSION}" \
    || (echo "FATAL: --build-arg VERSION=v<X.Y[.Z]> is required (was empty)" >&2 && exit 1)

# Baked into the runtime so start-server.js, the self-version
# endpoint, and any consumer can read it without external lookups.
ENV STINGAR_VERSION="${VERSION}"

# Same flag as builder: sidebar reads this at request time (layout is force-dynamic).
ARG THREAT_FEEDS_ENABLED=false
ENV THREAT_FEEDS_ENABLED=$THREAT_FEEDS_ENABLED

# Set version label (mirrors STINGAR_VERSION; used by image-inspectors).
LABEL version="${VERSION}"
LABEL org.opencontainers.image.version="${VERSION}"

WORKDIR /app

# Apply latest Debian security updates to address base-image CVEs.
# Same coverage as the builder stage; repeated here because the runtime
# stage is a fresh node:25.4-slim layer (multi-stage builds do not inherit
# apt state across FROM directives).
#   CVE-2026-0861  -- glibc memalign integer overflow  (libc6 >= 2.41-12+deb13u2 on trixie)
#   CVE-2025-6297  -- dpkg-deb temp-file leak           (dpkg  >= 1.22.22         on trixie)
RUN apt-get update && \
    apt-get upgrade -y --no-install-recommends && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Update npm to latest version to address security vulnerabilities
RUN npm install -g npm@latest

# Create and use a non-root user
RUN groupadd -r -g 1001 appuser && \
    useradd -r -u 1001 -g appuser appuser

# Copy the standalone output from the builder stage
# The standalone output includes only production dependencies
COPY --from=builder --chown=appuser:appuser /app/.next/standalone ./
COPY --from=builder --chown=appuser:appuser /app/.next/static ./.next/static
COPY --from=builder --chown=appuser:appuser /app/public ./public
# Copy the startup script and package.json (for version reading) from the builder stage
COPY --from=builder --chown=appuser:appuser /app/start-server.js ./
COPY --from=builder --chown=appuser:appuser /app/package.json ./package.json

USER appuser

# Expose the port Next.js runs on
EXPOSE 3000

# Set the NODE_ENV to production
ENV NODE_ENV=production
ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

# Run the production server with banner
CMD ["node", "start-server.js"]
