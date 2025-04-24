FROM oven/bun:latest

WORKDIR /app

COPY package.json .
COPY bun.lockb .

RUN bun install --production

COPY . .

ENV PORT=3000
ENV JWT_SECRET=your-secret-key
ENV LOG_LEVEL=info

EXPOSE 3000

CMD ["bun", "src/server.ts"]
