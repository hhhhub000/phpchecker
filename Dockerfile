# Cloud Run 用イメージ（依存パッケージなしのため npm install は不要）
FROM node:22-slim

ENV NODE_ENV=production \
    PORT=8080 \
    TRUST_PROXY=1

WORKDIR /app
COPY package.json server.js ./
COPY lib ./lib
COPY public ./public

USER node
EXPOSE 8080
CMD ["node", "server.js"]
