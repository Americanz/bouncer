import os
import json

# Використовуємо поточну директорію
project_name = ""  # Порожнє значення для поточного каталогу

# Базова структура директорій
directories = [
    f"{project_name}src",
    f"{project_name}src/validators",
    f"{project_name}src/utils",
    f"{project_name}tests",
]

# Створення директорій
for directory in directories:
    os.makedirs(directory, exist_ok=True)
    print(f"Створено директорію: {directory}")

# Файли та їх вміст
files = {
    # Головний файл сервера
    f"{project_name}src/server.ts": """import { serve } from "bun";
import { validateJwt } from "./validators/jwt";
import { logger } from "./utils/logger";
import { config } from "./config";

serve({
  port: config.port,
  async fetch(req: Request) {
    logger.info(`Отримано запит: ${req.method} ${new URL(req.url).pathname}`);

    // Перевіряємо, чи запит іде на потрібний ендпоінт
    const url = new URL(req.url);
    if (url.pathname !== "/validate") {
      return new Response("Not Found", { status: 404 });
    }

    // Отримуємо токен з заголовка Authorization
    const authHeader = req.headers.get("authorization");

    if (!authHeader) {
      logger.warn("Відсутній токен авторизації");
      return new Response("Відсутній токен авторизації", { status: 401 });
    }

    try {
      // Валідуємо JWT токен
      const result = await validateJwt(authHeader);

      if (result.valid) {
        // Створюємо успішну відповідь з інформацією про користувача
        const response = new Response("OK", { status: 200 });

        // Додаємо інформацію про користувача в заголовки
        if (result.payload) {
          if (result.payload.username) {
            response.headers.set("X-User", result.payload.username);
          }
          if (result.payload.role) {
            response.headers.set("X-User-Role", result.payload.role);
          }
        }

        logger.info("Токен успішно валідовано");
        return response;
      } else {
        logger.warn(`Помилка валідації: ${result.error}`);
        return new Response(result.error || "Недійсний токен", { status: 403 });
      }
    } catch (err) {
      logger.error(`Помилка під час обробки запиту: ${err}`);
      return new Response("Внутрішня помилка сервера", { status: 500 });
    }
  }
});

logger.info(`Auth сервіс запущено на порту ${config.port}`);
""",

    # Конфігурація додатку
    f"{project_name}src/config.ts": """// Конфігурація додатку
export const config = {
  port: parseInt(process.env.PORT || "3000"),
  jwtSecret: process.env.JWT_SECRET || "your-secret-key",
  allowedTokens: (process.env.ALLOWED_TOKENS || "").split(",").filter(Boolean),
  logLevel: process.env.LOG_LEVEL || "info",
};
""",

    # JWT валідатор
    f"{project_name}src/validators/jwt.ts": """import { verify } from "bun:jwt";
import { config } from "../config";
import { logger } from "../utils/logger";

interface ValidationResult {
  valid: boolean;
  error?: string;
  payload?: any;
}

export async function validateJwt(authHeader: string): Promise<ValidationResult> {
  // Витягуємо токен з формату "Bearer [token]"
  const [bearer, token] = authHeader.split(" ");

  if (bearer !== "Bearer" || !token) {
    return { valid: false, error: "Неправильний формат токена" };
  }

  // Якщо налаштовано список дозволених токенів, перевіряємо по ньому
  if (config.allowedTokens.length > 0 && !config.allowedTokens.includes(token)) {
    return { valid: false, error: "Токен не в списку дозволених" };
  }

  try {
    // Верифікуємо JWT за допомогою вбудованої в Bun функції
    const decoded = await verify(token, config.jwtSecret);
    logger.debug(`Декодований токен: ${JSON.stringify(decoded)}`);

    return { valid: true, payload: decoded };
  } catch (err) {
    logger.warn(`Помилка валідації токена: ${err}`);
    return { valid: false, error: "Недійсний токен" };
  }
}
""",

    # Basic Auth валідатор (опціонально)
    f"{project_name}src/validators/basic.ts": """import { config } from "../config";
import { logger } from "../utils/logger";

interface ValidationResult {
  valid: boolean;
  error?: string;
  username?: string;
}

export function validateBasicAuth(authHeader: string): ValidationResult {
  // Витягуємо credentials з формату "Basic [base64]"
  const [basic, encoded] = authHeader.split(" ");

  if (basic !== "Basic" || !encoded) {
    return { valid: false, error: "Неправильний формат Basic Auth" };
  }

  try {
    // Декодуємо Base64
    const decoded = atob(encoded);
    const [username, password] = decoded.split(":");

    if (!username || !password) {
      return { valid: false, error: "Неправильний формат логін:пароль" };
    }

    // Тут можна додати логіку перевірки логіну і паролю
    // Наприклад, порівняння з списком користувачів або зовнішня перевірка
    logger.debug(`Спроба авторизації користувача: ${username}`);

    return { valid: true, username };
  } catch (err) {
    logger.warn(`Помилка декодування Basic Auth: ${err}`);
    return { valid: false, error: "Помилка декодування" };
  }
}
""",

    # API Key валідатор (опціонально)
    f"{project_name}src/validators/apikey.ts": """import { config } from "../config";
import { logger } from "../utils/logger";

interface ValidationResult {
  valid: boolean;
  error?: string;
  apiKey?: string;
}

export function validateApiKey(authHeader: string): ValidationResult {
  // Витягуємо API Key з формату "ApiKey [key]"
  const [prefix, apiKey] = authHeader.split(" ");

  if (prefix !== "ApiKey" || !apiKey) {
    return { valid: false, error: "Неправильний формат API Key" };
  }

  // Якщо налаштовано список дозволених ключів, перевіряємо по ньому
  if (config.allowedTokens.length > 0 && !config.allowedTokens.includes(apiKey)) {
    return { valid: false, error: "API Key не в списку дозволених" };
  }

  logger.debug(`Валідовано API Key: ${apiKey.substring(0, 4)}...`);

  return { valid: true, apiKey };
}
""",

    # Логгер
    f"{project_name}src/utils/logger.ts": """const LOG_LEVELS = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

class Logger {
  private level: number;

  constructor(level: string = "info") {
    this.level = LOG_LEVELS[level.toLowerCase()] || LOG_LEVELS.info;
  }

  debug(message: string): void {
    if (this.level <= LOG_LEVELS.debug) {
      console.debug(`[DEBUG] ${new Date().toISOString()} - ${message}`);
    }
  }

  info(message: string): void {
    if (this.level <= LOG_LEVELS.info) {
      console.info(`[INFO] ${new Date().toISOString()} - ${message}`);
    }
  }

  warn(message: string): void {
    if (this.level <= LOG_LEVELS.warn) {
      console.warn(`[WARN] ${new Date().toISOString()} - ${message}`);
    }
  }

  error(message: string): void {
    if (this.level <= LOG_LEVELS.error) {
      console.error(`[ERROR] ${new Date().toISOString()} - ${message}`);
    }
  }
}

import { config } from "../config";
export const logger = new Logger(config.logLevel);
""",

    # Утиліти для обробки помилок
    f"{project_name}src/utils/errors.ts": """export class AuthError extends Error {
  status: number;

  constructor(message: string, status: number = 401) {
    super(message);
    this.name = "AuthError";
    this.status = status;
  }
}

export function handleError(error: unknown): Response {
  if (error instanceof AuthError) {
    return new Response(error.message, { status: error.status });
  }

  if (error instanceof Error) {
    return new Response(error.message, { status: 500 });
  }

  return new Response("Невідома помилка", { status: 500 });
}
""",

    # Тест для JWT валідації
    f"{project_name}tests/jwt.test.ts": """import { expect, test, describe } from "bun:test";
import { validateJwt } from "../src/validators/jwt";

describe("JWT Validator", () => {
  test("повинен відхилити неправильний формат", async () => {
    const result = await validateJwt("InvalidFormat");
    expect(result.valid).toBe(false);
    expect(result.error).toContain("Неправильний формат");
  });

  test("повинен відхилити невірний токен", async () => {
    const result = await validateJwt("Bearer invalid.token.here");
    expect(result.valid).toBe(false);
  });

  // Тут можна додати більше тестів з валідними токенами
});
""",

    # Тест для сервера
    f"{project_name}tests/server.test.ts": """import { expect, test, describe } from "bun:test";

describe("Server Endpoints", () => {
  test("повинен повернути 401 без токена", async () => {
    const response = await fetch("http://localhost:3000/validate");
    expect(response.status).toBe(401);
  });

  test("повинен повернути 403 з невірним токеном", async () => {
    const response = await fetch("http://localhost:3000/validate", {
      headers: {
        Authorization: "Bearer invalid.token.here"
      }
    });
    expect(response.status).toBe(403);
  });

  // Тут можна додати тести з валідними токенами
});
""",

    # Dockerfile
    f"{project_name}Dockerfile": """FROM oven/bun:latest

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
""",

    # docker-compose.yml
    f"{project_name}docker-compose.yml": """version: '3'

services:
  auth-service:
    build: .
    container_name: bouncer
    restart: unless-stopped
    environment:
      - PORT=3000
      - JWT_SECRET=your-secure-jwt-secret-key
      - ALLOWED_TOKENS=token1,token2,token3
      - LOG_LEVEL=info
    ports:
      - "3000:3000"
    # networks:
    #   - proxy_network

# Розкоментуйте, якщо потрібно підключити до існуючої мережі
# networks:
#   proxy_network:
#     external: true
#     name: traefik_proxy  # Замініть на назву вашої мережі
""",

    # .env.example
    f"{project_name}.env.example": """# Порт, на якому буде працювати сервіс
PORT=3000

# Секретний ключ для JWT валідації
JWT_SECRET=your-secure-jwt-secret-key

# Список дозволених токенів, розділених комами (опціонально)
ALLOWED_TOKENS=token1,token2,token3

# Рівень логування (debug, info, warn, error)
LOG_LEVEL=info
""",

    # .gitignore
    f"{project_name}.gitignore": """# Залежності
node_modules/
/bun.lockb

# Скомпільовані файли
dist/
build/

# Логи
logs/
*.log
npm-debug.log*

# Змінні середовища
.env
.env.local
.env.development
.env.test
.env.production

# Системні файли
.DS_Store
Thumbs.db
""",

    # package.json
    f"{project_name}package.json": """{
  "name": "bouncer",
  "version": "1.0.0",
  "description": "JWT Authentication Service for API Protection",
  "main": "src/server.ts",
  "scripts": {
    "start": "bun src/server.ts",
    "dev": "bun --watch src/server.ts",
    "test": "bun test",
    "build": "bun build src/server.ts --outdir ./dist"
  },
  "keywords": [
    "auth",
    "jwt",
    "bun",
    "authentication",
    "api"
  ],
  "author": "",
  "license": "MIT",
  "devDependencies": {
    "bun-types": "latest"
  },
  "dependencies": {}
}
""",

    # tsconfig.json
    f"{project_name}tsconfig.json": """{
  "compilerOptions": {
    "target": "esnext",
    "module": "esnext",
    "moduleResolution": "node",
    "types": ["bun-types"],
    "esModuleInterop": true,
    "strict": true,
    "skipLibCheck": true,
    "outDir": "dist"
  },
  "include": ["src/**/*"]
}
""",

    # README.md
    f"{project_name}README.md": """# Bouncer

Легкий та швидкий сервіс авторизації на Bun для захисту API за допомогою JWT токенів.

## Особливості

- Швидка валідація JWT токенів
- Підтримка Basic Auth та API Key (опціонально)
- Низьке споживання ресурсів
- Docker-ready для легкого розгортання
- Повна підтримка TypeScript

## Вимоги

- [Bun](https://bun.sh/) 1.0.0 або вище
- Docker (опціонально)

## Встановлення

```bash
# Клонуйте репозиторій
git clone https://github.com/your-username/bouncer.git
cd bouncer

# Встановіть залежності
bun install

# Скопіюйте приклад .env файлу та налаштуйте його
cp .env.example .env
```
"""
}

# Створюємо файли з вмістом
for file_path, content in files.items():
    # Створюємо директорії для файлу, якщо вони не існують
    dir_name = os.path.dirname(file_path)
    if dir_name and not os.path.exists(dir_name):
        os.makedirs(dir_name, exist_ok=True)
    
    # Записуємо вміст у файл
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"Створено файл: {file_path}")

print("\nПроект 'Bouncer' успішно створено!")
print("Легкий та швидкий сервіс авторизації на Bun для захисту API за допомогою JWT токенів.")
