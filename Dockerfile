FROM node:24-alpine

ENV NODE_ENV=production \
    PORT=3000 \
    HOST=0.0.0.0

WORKDIR /app
COPY --chown=1000:1000 secure-app/ /app/

USER 1000:1000
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:3000/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]

CMD ["node", "--disable-proto=throw", "--frozen-intrinsics", "server.mjs"]
