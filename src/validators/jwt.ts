import jwt from "jsonwebtoken";
import { config } from "../config";
import { logger } from "../utils/logger";
import { tokenDb } from "../utils/tokenDb";

interface ValidationResult {
  valid: boolean;
  error?: string;
  payload?: any;
}

export async function validateJwt(
  authHeader: string
): Promise<ValidationResult> {
  // Витягуємо токен з формату "Bearer [token]"
  const [bearer, token] = authHeader.split(" ");

  if (bearer !== "Bearer" || !token) {
    return { valid: false, error: "Неправильний формат токена" };
  }

  // Перевіряємо токен у нашій базі даних токенів
  if (!tokenDb.isTokenValid(token)) {
    // Якщо токен не знайдено в базі, перевіряємо список дозволених токенів з конфігурації
    if (
      config.allowedTokens.length > 0 &&
      !config.allowedTokens.includes(token)
    ) {
      return { valid: false, error: "Токен не в списку дозволених" };
    }
  }

  try {
    // Верифікуємо JWT за допомогою jsonwebtoken
    const decoded = jwt.verify(token, config.jwtSecret);
    logger.debug(`Декодований токен: ${JSON.stringify(decoded)}`);

    // Отримуємо додаткову інформацію про токен з бази даних
    const tokenInfo = tokenDb.getTokenInfo(token);
    if (tokenInfo) {
      // Додаємо інформацію з бази даних до payload
      Object.assign(decoded, {
        issuedAt: new Date(tokenInfo.issuedAt).toISOString(),
        expiresAt: new Date(tokenInfo.expiresAt).toISOString(),
      });
    }

    return { valid: true, payload: decoded };
  } catch (err) {
    logger.warn(`Помилка валідації токена: ${err}`);
    return { valid: false, error: "Недійсний токен" };
  }
}
