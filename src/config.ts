// Завантажуємо змінні оточення з .env файлу
import { resolve } from "path";

// Спробуємо завантажити змінні оточення з .env файлу
try {
  const { loadEnv } = require("bun");
  loadEnv({ path: resolve(process.cwd(), ".env") });
} catch (err) {
  console.warn("Не вдалося завантажити змінні оточення з .env файлу:", err);
}

// Конфігурація додатку
export const config = {
  port: parseInt(process.env.PORT || "3000"),
  jwtSecret: process.env.JWT_SECRET || "your-secret-key",
  allowedTokens: (process.env.ALLOWED_TOKENS || "").split(",").filter(Boolean),
  logLevel: process.env.LOG_LEVEL || "info",
};
