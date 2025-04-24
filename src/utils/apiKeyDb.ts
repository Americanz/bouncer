import fs from "fs";
import path from "path";
import { logger } from "./logger";
import crypto from "crypto";

// Шлях до JSON файлу, який буде використовуватися як база API ключів
const API_KEYS_DB_PATH = path.join(process.cwd(), "data", "apikeys.json");

// Структура для зберігання інформації про API ключ
interface ApiKeyEntry {
  apiKey: string;
  username: string;
  description: string;
  created: number;
  expiresAt?: number; // Опціонально, якщо ключ має термін дії
  isActive: boolean;
}

class ApiKeyDatabase {
  private apiKeys: ApiKeyEntry[] = [];

  constructor() {
    this.loadApiKeys();
  }

  // Завантаження API ключів з файлу
  private loadApiKeys() {
    try {
      if (fs.existsSync(API_KEYS_DB_PATH)) {
        const data = fs.readFileSync(API_KEYS_DB_PATH, "utf-8");
        this.apiKeys = JSON.parse(data);
        logger.info(`Завантажено ${this.apiKeys.length} API ключів з бази`);
      } else {
        logger.info("Файл бази API ключів не знайдено. Створюємо нову базу.");
        this.saveApiKeys(); // Створюємо порожню базу
      }
    } catch (err) {
      logger.error(`Помилка завантаження бази API ключів: ${err}`);
      this.apiKeys = [];
    }
  }

  // Збереження API ключів у файл
  private saveApiKeys() {
    try {
      fs.writeFileSync(API_KEYS_DB_PATH, JSON.stringify(this.apiKeys, null, 2));
      logger.info(`Збережено ${this.apiKeys.length} API ключів у базу`);
    } catch (err) {
      logger.error(`Помилка збереження бази API ключів: ${err}`);
    }
  }

  // Генерація нового API ключа
  private generateApiKey(length: number = 32): string {
    // Генеруємо випадковий буфер вказаної довжини
    return crypto.randomBytes(length).toString('hex');
  }

  // Додавання нового API ключа
  addApiKey(username: string, description: string, expiresInDays?: number): string {
    // Генеруємо новий API ключ
    const apiKey = this.generateApiKey();
    
    const now = Date.now();
    const newApiKey: ApiKeyEntry = {
      apiKey,
      username,
      description,
      created: now,
      isActive: true
    };

    // Якщо вказано термін дії, додаємо його
    if (expiresInDays) {
      const expiresAt = now + (expiresInDays * 24 * 60 * 60 * 1000); // Конвертуємо дні в мілісекунди
      newApiKey.expiresAt = expiresAt;
    }

    this.apiKeys.push(newApiKey);
    this.saveApiKeys();
    logger.info(`Створено новий API ключ для користувача: ${username}`);
    
    return apiKey;
  }

  // Перевірка чи API ключ в базі та чи він активний
  isApiKeyValid(apiKey: string): boolean {
    const entry = this.apiKeys.find(k => k.apiKey === apiKey);
    
    if (!entry) {
      return false;
    }

    // Перевіряємо чи ключ активний і не протермінований
    const now = Date.now();
    const isActive = entry.isActive;
    const isNotExpired = !entry.expiresAt || entry.expiresAt > now;
    
    return isActive && isNotExpired;
  }

  // Деактивація API ключа
  revokeApiKey(apiKey: string): boolean {
    const entry = this.apiKeys.find(k => k.apiKey === apiKey);
    
    if (!entry) {
      return false;
    }

    entry.isActive = false;
    this.saveApiKeys();
    logger.info(`Деактивовано API ключ для користувача: ${entry.username}`);
    return true;
  }

  // Отримання інформації по API ключу
  getApiKeyInfo(apiKey: string): ApiKeyEntry | null {
    return this.apiKeys.find(k => k.apiKey === apiKey) || null;
  }

  // Отримання всіх API ключів користувача
  getApiKeysByUser(username: string): ApiKeyEntry[] {
    return this.apiKeys.filter(k => k.username === username);
  }

  // Очистка протермінованих API ключів
  cleanupExpiredApiKeys(): number {
    const now = Date.now();
    const originalCount = this.apiKeys.length;
    
    // Видаляємо протерміновані ключі
    this.apiKeys = this.apiKeys.filter(k => !k.expiresAt || k.expiresAt > now);
    
    if (originalCount !== this.apiKeys.length) {
      this.saveApiKeys();
    }
    
    return originalCount - this.apiKeys.length;
  }
}

// Експортуємо єдиний екземпляр класу для використання в додатку
export const apiKeyDb = new ApiKeyDatabase();