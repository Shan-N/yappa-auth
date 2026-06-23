FROM node:20-alpine

RUN apk add --no-cache tini

RUN addgroup -S yappa && adduser -S yappa -G yappa

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY src ./src

RUN chown -R yappa:yappa /app

USER yappa

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3001/health || exit 1

EXPOSE 3001

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "src/index.js"]
