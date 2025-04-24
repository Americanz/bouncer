import fs from "fs";
import path from "path";
import { logger } from "./logger";

// Шлях до JSON файлу, який буде використовуватися як база токенів
const TOKEN_DB_PATH = path.join(process.cwd(), "data", "tokens.json");

// Структура для зберігання інформації про токен
interface TokenEntry {
  token: string;
  username: string;
  role: string;
  issuedAt: number;
  expiresAt: number;
  isActive: boolean;
}

class TokenDatabase {
  private tokens: TokenEntry[] = [];

  constructor() {
    this.loadTokens();
  }

  // Завантаження токенів з файлу
  private loadTokens() {
    try {
      if (fs.existsSync(TOKEN_DB_PATH)) {
        const data = fs.readFileSync(TOKEN_DB_PATH, "utf-8");
        this.tokens = JSON.parse(data);
        logger.info(`Завантажено ${this.tokens.length} токенів з бази`);
      } else {
        logger.info("Файл бази токенів не знайдено. Створюємо нову базу.");
        this.saveTokens(); // Створюємо порожню базу
      }
    } catch (err) {
      logger.error(`Помилка завантаження бази токенів: ${err}`);
      this.tokens = [];
    }
  }

  // Збереження токенів у файл
  private saveTokens() {
    try {
      fs.writeFileSync(TOKEN_DB_PATH, JSON.stringify(this.tokens, null, 2));
      logger.info(`Збережено ${this.tokens.length} токенів у базу`);
    } catch (err) {
      logger.error(`Помилка збереження бази токенів: ${err}`);
    }
  }

  // Додавання нового токена
  addToken(token: string, username: string, role: string, expiresIn: number): boolean {
    const now = Date.now();
    const newToken: TokenEntry = {
      token,
      username,
      role,
      issuedAt: now,
      expiresAt: now + expiresIn * 1000, // Переводимо секунди в мілісекунди
      isActive: true
    };

    this.tokens.push(newToken);
    this.saveTokens();
    return true;
  }

  // Перевірка чи токен в базі та чи він активний
  isTokenValid(token: string): boolean {
    const entry = this.tokens.find(t => t.token === token);

    if (!entry) {
      return false;
    }

    // Перевіряємо чи токен активний і не протермінований
    const now = Date.now();
    return entry.isActive && entry.expiresAt > now;
  }

  // Деактивація токена (відкликання)
  revokeToken(token: string): boolean {
    const entry = this.tokens.find(t => t.token === token);

    if (!entry) {
      return false;
    }

    entry.isActive = false;
    this.saveTokens();
    return true;
  }

  // Отримання інформації по токену
  getTokenInfo(token: string): TokenEntry | null {
    return this.tokens.find(t => t.token === token) || null;
  }

  // Очистка протермінованих токенів
  cleanupExpiredTokens(): number {
    const now = Date.now();
    const originalCount = this.tokens.length;

    this.tokens = this.tokens.filter(t => t.expiresAt > now);

    if (originalCount !== this.tokens.length) {
      this.saveTokens();
    }

    return originalCount - this.tokens.length;
  }
}

// Експортуємо єдиний екземпляр класу для використання в додатку
export const tokenDb = new TokenDatabase();
