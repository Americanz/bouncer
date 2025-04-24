import { config } from "../config";
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
