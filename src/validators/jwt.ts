import jwt from "jsonwebtoken";
import { config } from "../config";
import { logger } from "../utils/logger";
import { tokenDb } from "../utils/tokenDb";

interface ValidationResult {
  valid: boolean;
  error?: string;
  errorDetail?: string;
  payload?: any;
}

export async function validateJwt(
  authHeader: string
): Promise<ValidationResult> {
  // Перевіряємо, чи заголовок існує
  if (!authHeader) {
    logger.warn("Пустий заголовок авторизації");
    return {
      valid: false,
      error: "Відсутній заголовок авторизації",
      errorDetail: "Authorization header is missing",
    };
  }

  // Витягуємо токен з формату "Bearer [token]"
  const parts = authHeader.split(" ");
  if (parts.length !== 2) {
    logger.warn(`Неправильний формат заголовка авторизації: ${authHeader}`);
    return {
      valid: false,
      error: "Неправильний формат токена",
      errorDetail: "Authorization header format should be 'Bearer [token]'",
    };
  }

  const [bearer, token] = parts;

  if (bearer !== "Bearer") {
    logger.warn(`Невідомий тип авторизації: ${bearer}`);
    return {
      valid: false,
      error: "Неправильний тип авторизації",
      errorDetail: "Only Bearer authentication is supported",
    };
  }

  if (!token || token.trim() === "") {
    logger.warn("Токен порожній");
    return {
      valid: false,
      error: "Порожній токен",
      errorDetail: "Token is empty",
    };
  }

  logger.debug(`Отримано токен для валідації: ${token.substring(0, 10)}...`);

  // Перевіряємо токен у нашій базі даних токенів
  if (!tokenDb.isTokenValid(token)) {
    // Якщо токен не знайдено в базі, перевіряємо список дозволених токенів з конфігурації
    if (
      config.allowedTokens.length > 0 &&
      !config.allowedTokens.includes(token)
    ) {
      logger.warn("Токен не знайдено в списку дозволених");
      return {
        valid: false,
        error: "Токен не в списку дозволених",
        errorDetail: "Token is not in the allowlist",
      };
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
    const error = err as Error;
    logger.warn(`Помилка валідації токена: ${error.name}: ${error.message}`);

    let errorDetail = "Invalid token";
    if (error.name === "JsonWebTokenError") {
      if (error.message === "jwt malformed") {
        errorDetail =
          "JWT має неправильний формат. Перевірте, чи правильно токен закодований.";
      } else if (error.message === "invalid signature") {
        errorDetail = "Невірний підпис JWT. Перевірте секретний ключ.";
      } else if (error.message === "jwt signature is required") {
        errorDetail = "JWT підпис відсутній.";
      }
    } else if (error.name === "TokenExpiredError") {
      errorDetail = "Термін дії токена закінчився.";
    } else if (error.name === "NotBeforeError") {
      errorDetail = "Токен ще не активний.";
    }

    return {
      valid: false,
      error: "Недійсний токен",
      errorDetail,
    };
  }
}
