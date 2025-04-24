FROM oven/bun:latest

WORKDIR /app

# Копіюємо тільки package.json спочатку
COPY package.json .

# Копіюємо bun.lockb, якщо він існує (використовуємо умовне копіювання)
COPY bun.lockb* ./ 2>/dev/null || true

RUN bun install --production

# Копіюємо решту файлів
COPY . .

ENV PORT=3000
ENV JWT_SECRET=your-secret-key
ENV LOG_LEVEL=info

EXPOSE 3000

CMD ["bun", "src/server.ts"]
