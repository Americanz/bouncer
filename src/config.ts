// Завантажуємо змінні оточення з .env файлу
import { resolve } from "path";
import fs from "fs";

// Функція для завантаження змінних оточення з .env файлу
function loadEnvFile(filePath: string) {
  try {
    if (fs.existsSync(filePath)) {
      const content = fs.readFileSync(filePath, "utf8");
      const lines = content.split("\n");

      for (const line of lines) {
        // Пропускаємо порожні рядки та коментарі
        const trimmedLine = line.trim();
        if (!trimmedLine || trimmedLine.startsWith("#")) continue;

        // Розбиваємо на ключ та значення
        const [key, ...valueParts] = trimmedLine.split("=");
        if (key && valueParts.length > 0) {
          const value = valueParts.join("=").trim();
          // Встановлюємо змінну оточення, якщо її ще немає
          if (!process.env[key.trim()]) {
            process.env[key.trim()] = value;
          }
        }
      }

      console.log(`Завантажено змінні оточення з ${filePath}`);
    }
  } catch (err) {
    console.warn(`Не вдалося завантажити змінні оточення з ${filePath}:`, err);
  }
}

// Завантажуємо змінні оточення з .env файлу
loadEnvFile(resolve(process.cwd(), ".env"));

// Конфігурація додатку
export const config = {
  port: parseInt(process.env.PORT || "3000"),
  jwtSecret: process.env.JWT_SECRET || "your-secret-key",
  allowedTokens: (process.env.ALLOWED_TOKENS || "").split(",").filter(Boolean),
  logLevel: process.env.LOG_LEVEL || "info",
};
