import { config } from "../config";
import { logger } from "../utils/logger";
import { apiKeyDb } from "../utils/apiKeyDb";

interface ValidationResult {
  valid: boolean;
  error?: string;
  errorDetail?: string;
  apiKey?: string;
  payload?: any;
}

export function validateApiKey(authHeader: string): ValidationResult {
  // Перевіряємо, чи заголовок існує
  if (!authHeader) {
    logger.warn("Пустий заголовок API Key");
    return {
      valid: false,
      error: "Відсутній заголовок API Key",
      errorDetail: "X-API-Key header is missing",
    };
  }

  let apiKey: string;

  // Перевіряємо формат заголовка - підтримуємо як "ApiKey [key]", так і просто ключ
  if (authHeader.startsWith("ApiKey ")) {
    // Формат "ApiKey [key]"
    const [prefix, key] = authHeader.split(" ");

    if (!key || key.trim() === "") {
      logger.warn("API Key порожній");
      return {
        valid: false,
        error: "Порожній API Key",
        errorDetail: "API Key is empty",
      };
    }

    apiKey = key;
  } else {
    // Простий формат, де весь заголовок є ключем
    apiKey = authHeader;
  }

  logger.debug(`Отримано API Key для валідації: ${apiKey.substring(0, 4)}...`);

  // Спочатку перевіряємо ключ у нашій базі даних
  if (apiKeyDb.isApiKeyValid(apiKey)) {
    // Отримуємо інформацію про ключ
    const keyInfo = apiKeyDb.getApiKeyInfo(apiKey);

    if (keyInfo) {
      return {
        valid: true,
        apiKey,
        payload: {
          username: keyInfo.username,
          created: new Date(keyInfo.created).toISOString(),
          expiresAt: keyInfo.expiresAt
            ? new Date(keyInfo.expiresAt).toISOString()
            : undefined,
          description: keyInfo.description,
        },
      };
    }

    return { valid: true, apiKey };
  }

  // Якщо ключ не знайдено в базі, перевіряємо список дозволених токенів з конфігурації
  if (
    config.allowedTokens.length > 0 &&
    config.allowedTokens.includes(apiKey)
  ) {
    return { valid: true, apiKey };
  }

  logger.warn(`Недійсний API Key: ${apiKey.substring(0, 4)}...`);
  return {
    valid: false,
    error: "API Key не в списку дозволених",
    errorDetail: "API Key is not valid or has been revoked",
  };
}
