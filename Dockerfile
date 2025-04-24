FROM oven/bun:latest

WORKDIR /app

# Копіюємо тільки package.json спочатку
COPY package.json .
# Видаляємо спробу копіювання bun.lockb, він буде створений при bun install

RUN bun install --production

# Копіюємо решту файлів
COPY . .

# Створюємо директорію для даних
RUN mkdir -p data

# Замість жорсткого кодування значень, ми використовуємо ARG з можливістю передачі під час збірки
# і встановлюємо значення за замовчуванням
ARG PORT=3000
ENV PORT=${PORT}

# Інші змінні оточення з можливістю перевизначення
ARG JWT_SECRET=default-jwt-secret-please-change
ENV JWT_SECRET=${JWT_SECRET}

ARG LOG_LEVEL=info
ENV LOG_LEVEL=${LOG_LEVEL}

ARG ALLOWED_TOKENS=
ENV ALLOWED_TOKENS=${ALLOWED_TOKENS}

# Відкриваємо порт, який вказаний у змінній оточення
EXPOSE ${PORT}

CMD ["bun", "src/server.ts"]
