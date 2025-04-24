import { config } from "../config";
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
