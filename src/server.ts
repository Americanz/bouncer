import { serve } from "bun";
import { validateJwt } from "./validators/jwt";
import { validateApiKey } from "./validators/apikey";
import { logger } from "./utils/logger";
import { config } from "./config";
import jwt from "jsonwebtoken";
import { tokenDb } from "./utils/tokenDb";
import { userDb } from "./utils/userDb";
import { apiKeyDb } from "./utils/apiKeyDb";

// Очистка застарілих токенів при старті сервера
const removedTokens = tokenDb.cleanupExpiredTokens();
if (removedTokens > 0) {
  logger.info(`Видалено ${removedTokens} застарілих токенів з бази`);
}

// Очистка застарілих API ключів при старті сервера
const removedApiKeys = apiKeyDb.cleanupExpiredApiKeys();
if (removedApiKeys > 0) {
  logger.info(`Видалено ${removedApiKeys} застарілих API ключів з бази`);
}

serve({
  port: config.port,
  async fetch(req: Request) {
    logger.info(`Отримано запит: ${req.method} ${new URL(req.url).pathname}`);

    // Отримуємо URL шлях
    const url = new URL(req.url);

    // Ендпоінт для видачі токенів
    if (url.pathname === "/token" && req.method === "POST") {
      try {
        // Отримуємо дані авторизації з body запиту
        const body = await req.json();
        const { username, password } = body;

        if (!username || !password) {
          logger.warn("Відсутні дані для авторизації");
          return new Response("Необхідно вказати username та password", {
            status: 400,
          });
        }

        // Перевіряємо користувача за допомогою бази даних користувачів
        const authResult = userDb.verifyCredentials(username, password);

        if (!authResult.valid || !authResult.user) {
          logger.warn(
            `Невдала спроба авторизації для користувача: ${username}`
          );
          return new Response("Невірні облікові дані", { status: 401 });
        }

        // Час життя токена в секундах (1 година)
        const expiresIn = 3600;

        // Створюємо JWT токен
        const token = jwt.sign(
          {
            username: authResult.user.username,
            role: authResult.user.role,
          },
          config.jwtSecret,
          { expiresIn: `${expiresIn}s` }
        );

        // Зберігаємо токен в базі даних
        tokenDb.addToken(
          token,
          authResult.user.username,
          authResult.user.role,
          expiresIn
        );

        logger.info(`Видано токен для користувача: ${username}`);
        return new Response(JSON.stringify({ token }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      } catch (err) {
        logger.error(`Помилка під час створення токена: ${err}`);
        return new Response("Помилка під час обробки запиту", { status: 500 });
      }
    }

    // Ендпоінт для видачі API ключів (потрібна JWT авторизація)
    if (url.pathname === "/apikey" && req.method === "POST") {
      // Отримуємо токен з заголовка Authorization
      const authHeader = req.headers.get("authorization");

      if (!authHeader) {
        return new Response("Відсутній токен авторизації", { status: 401 });
      }

      try {
        // Валідуємо JWT токен
        const result = await validateJwt(authHeader);

        if (!result.valid) {
          const errorBody = {
            error: result.error || "Недійсний токен",
            details: result.errorDetail || "Помилка авторизації"
          };
          
          return new Response(JSON.stringify(errorBody), {
            status: 403,
            headers: { "Content-Type": "application/json" }
          });
        }

        // Отримуємо дані для створення API ключа
        const body = await req.json();
        const { description, expiresInDays } = body;
        
        if (!description) {
          return new Response(JSON.stringify({ 
            error: "Необхідно вказати опис (description) для API ключа"
          }), { 
            status: 400,
            headers: { "Content-Type": "application/json" }
          });
        }
        
        // Створюємо новий API ключ
        const apiKey = apiKeyDb.addApiKey(
          result.payload.username,
          description,
          expiresInDays
        );
        
        logger.info(`Видано API ключ для користувача: ${result.payload.username}`);
        
        // Формуємо відповідь
        const response = {
          apiKey,
          username: result.payload.username,
          description,
          expiresInDays: expiresInDays || "never"
        };
        
        return new Response(JSON.stringify(response), { 
          status: 201,
          headers: { "Content-Type": "application/json" }
        });
      } catch (err) {
        logger.error(`Помилка під час створення API ключа: ${err}`);
        return new Response("Помилка під час обробки запиту", { status: 500 });
      }
    }

    // Ендпоінт для отримання списку власних API ключів
    if (url.pathname === "/apikeys" && req.method === "GET") {
      // Отримуємо токен з заголовка Authorization
      const authHeader = req.headers.get("authorization");

      if (!authHeader) {
        return new Response("Відсутній токен авторизації", { status: 401 });
      }

      try {
        // Валідуємо JWT токен
        const result = await validateJwt(authHeader);

        if (!result.valid) {
          const errorBody = {
            error: result.error || "Недійсний токен",
            details: result.errorDetail || "Помилка авторизації"
          };
          
          return new Response(JSON.stringify(errorBody), {
            status: 403,
            headers: { "Content-Type": "application/json" }
          });
        }

        // Отримуємо список API ключів користувача
        const apiKeys = apiKeyDb.getApiKeysByUser(result.payload.username);
        
        // Форматуємо відповідь без самих ключів (для безпеки)
        const formattedKeys = apiKeys.map(key => ({
          id: key.apiKey.substring(0, 8) + '...',
          description: key.description,
          created: new Date(key.created).toISOString(),
          expires: key.expiresAt ? new Date(key.expiresAt).toISOString() : null,
          active: key.isActive
        }));
        
        return new Response(JSON.stringify(formattedKeys), { 
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      } catch (err) {
        logger.error(`Помилка під час отримання списку API ключів: ${err}`);
        return new Response("Помилка під час обробки запиту", { status: 500 });
      }
    }

    // Ендпоінт для відкликання API ключа
    if (url.pathname === "/apikey/revoke" && req.method === "POST") {
      // Отримуємо токен з заголовка Authorization
      const authHeader = req.headers.get("authorization");

      if (!authHeader) {
        return new Response("Відсутній токен авторизації", { status: 401 });
      }

      try {
        // Валідуємо JWT токен
        const result = await validateJwt(authHeader);

        if (!result.valid) {
          const errorBody = {
            error: result.error || "Недійсний токен",
            details: result.errorDetail || "Помилка авторизації"
          };
          
          return new Response(JSON.stringify(errorBody), {
            status: 403,
            headers: { "Content-Type": "application/json" }
          });
        }

        // Отримуємо API ключ для відкликання
        const body = await req.json();
        const { apiKey } = body;
        
        if (!apiKey) {
          return new Response(JSON.stringify({ 
            error: "Необхідно вказати API ключ для відкликання"
          }), { 
            status: 400,
            headers: { "Content-Type": "application/json" }
          });
        }
        
        // Перевіряємо, чи належить ключ цьому користувачу
        const keyInfo = apiKeyDb.getApiKeyInfo(apiKey);
        
        if (!keyInfo) {
          return new Response(JSON.stringify({ 
            error: "API ключ не знайдено"
          }), { 
            status: 404,
            headers: { "Content-Type": "application/json" }
          });
        }
        
        // Перевіряємо, чи це адміністратор або власник ключа
        if (keyInfo.username !== result.payload.username && result.payload.role !== "admin") {
          return new Response(JSON.stringify({ 
            error: "Ви не маєте прав для відкликання цього API ключа"
          }), { 
            status: 403,
            headers: { "Content-Type": "application/json" }
          });
        }
        
        // Відкликаємо API ключ
        const revoked = apiKeyDb.revokeApiKey(apiKey);
        
        if (revoked) {
          logger.info(`API ключ успішно відкликано користувачем ${result.payload.username}`);
          return new Response(JSON.stringify({ 
            success: true,
            message: "API ключ успішно відкликано"
          }), { 
            status: 200,
            headers: { "Content-Type": "application/json" }
          });
        } else {
          return new Response(JSON.stringify({ 
            error: "Не вдалося відкликати API ключ"
          }), { 
            status: 500,
            headers: { "Content-Type": "application/json" }
          });
        }
      } catch (err) {
        logger.error(`Помилка під час відкликання API ключа: ${err}`);
        return new Response("Помилка під час обробки запиту", { status: 500 });
      }
    }

    // Ендпоінт для валідації API ключа
    if (url.pathname === "/validate/apikey") {
      // Отримуємо API ключ з заголовка X-API-Key
      const apiKeyHeader = req.headers.get("x-api-key");

      if (!apiKeyHeader) {
        logger.warn("Відсутній заголовок API Key");
        return new Response(JSON.stringify({ 
          error: "Відсутній заголовок API Key",
          details: "X-API-Key header is required" 
        }), { 
          status: 401,
          headers: { "Content-Type": "application/json" }
        });
      }

      try {
        // Валідуємо API ключ
        const result = validateApiKey(apiKeyHeader);

        if (result.valid) {
          // Створюємо успішну відповідь з інформацією про користувача
          const response = new Response("OK", { status: 200 });

          // Додаємо інформацію в заголовки
          if (result.payload) {
            if (result.payload.username) {
              response.headers.set("X-User", result.payload.username);
            }
            if (result.payload.description) {
              response.headers.set("X-API-Description", result.payload.description);
            }
          }

          logger.info("API ключ успішно валідовано");
          return response;
        } else {
          logger.warn(`Помилка валідації API ключа: ${result.error}`);
          
          const errorBody = {
            error: result.error || "Недійсний API ключ",
            details: result.errorDetail || "Помилка авторизації"
          };
          
          return new Response(JSON.stringify(errorBody), {
            status: 403,
            headers: { "Content-Type": "application/json" }
          });
        }
      } catch (err) {
        logger.error(`Помилка під час обробки запиту: ${err}`);
        return new Response("Внутрішня помилка сервера", { status: 500 });
      }
    }

    // Ендпоінт для управління користувачами (тільки для адмінів)
    if (url.pathname === "/users" && req.method === "GET") {
      // Отримуємо токен з заголовка Authorization
      const authHeader = req.headers.get("authorization");

      if (!authHeader) {
        return new Response("Відсутній токен авторизації", { status: 401 });
      }

      try {
        // Валідуємо JWT токен
        const result = await validateJwt(authHeader);

        if (!result.valid) {
          return new Response(result.error || "Недійсний токен", {
            status: 403,
          });
        }

        // Перевіряємо роль користувача
        if (result.payload.role !== "admin") {
          logger.warn(
            `Спроба доступу до користувачів без прав адміна: ${result.payload.username}`
          );
          return new Response("Доступ заборонено", { status: 403 });
        }

        // Отримуємо список усіх користувачів
        const users = userDb.getUsers();

        return new Response(JSON.stringify(users), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      } catch (err) {
        logger.error(`Помилка під час обробки запиту: ${err}`);
        return new Response("Внутрішня помилка сервера", { status: 500 });
      }
    }

    // Ендпоінт для створення користувача (тільки для адмінів)
    if (url.pathname === "/users" && req.method === "POST") {
      // Отримуємо токен з заголовка Authorization
      const authHeader = req.headers.get("authorization");

      if (!authHeader) {
        return new Response("Відсутній токен авторизації", { status: 401 });
      }

      try {
        // Валідуємо JWT токен
        const result = await validateJwt(authHeader);

        if (!result.valid) {
          return new Response(result.error || "Недійсний токен", {
            status: 403,
          });
        }

        // Перевіряємо роль користувача
        if (result.payload.role !== "admin") {
          logger.warn(
            `Спроба створення користувача без прав адміна: ${result.payload.username}`
          );
          return new Response("Доступ заборонено", { status: 403 });
        }

        // Отримуємо дані нового користувача
        const body = await req.json();
        const { username, password, role } = body;

        if (!username || !password || !role) {
          return new Response("Необхідно вказати username, password та role", {
            status: 400,
          });
        }

        // Створюємо нового користувача
        const created = userDb.addUser(username, password, role);

        if (!created) {
          return new Response("Користувач з таким іменем вже існує", {
            status: 409,
          });
        }

        logger.info(
          `Адмін ${result.payload.username} створив нового користувача: ${username}`
        );
        return new Response(JSON.stringify({ success: true, username }), {
          status: 201,
          headers: { "Content-Type": "application/json" },
        });
      } catch (err) {
        logger.error(`Помилка під час обробки запиту: ${err}`);
        return new Response("Внутрішня помилка сервера", { status: 500 });
      }
    }

    // Ендпоінт для відкликання токена
    if (url.pathname === "/revoke" && req.method === "POST") {
      try {
        // Отримуємо токен з body запиту
        const body = await req.json();
        const { token } = body;

        if (!token) {
          return new Response("Необхідно вказати токен", { status: 400 });
        }

        // Відкликаємо токен
        const revoked = tokenDb.revokeToken(token);

        if (revoked) {
          logger.info("Токен успішно відкликано");
          return new Response("Токен відкликано", { status: 200 });
        } else {
          logger.warn("Спроба відкликати неіснуючий токен");
          return new Response("Токен не знайдено", { status: 404 });
        }
      } catch (err) {
        logger.error(`Помилка під час відкликання токена: ${err}`);
        return new Response("Помилка під час обробки запиту", { status: 500 });
      }
    }

    // Перевіряємо, чи запит іде на endpoint валідації
    if (url.pathname === "/validate") {
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

          // Формуємо відповідь з детальною інформацією про помилку
          const errorBody = {
            error: result.error || "Недійсний токен",
            details: result.errorDetail || "Помилка авторизації",
          };

          return new Response(JSON.stringify(errorBody), {
            status: 403,
            headers: { "Content-Type": "application/json" },
          });
        }
      } catch (err) {
        logger.error(`Помилка під час обробки запиту: ${err}`);
        return new Response("Внутрішня помилка сервера", { status: 500 });
      }
    }

    // Якщо шлях не відповідає жодному з ендпоінтів
    return new Response("Not Found", { status: 404 });
  },
});

logger.info(`Auth сервіс запущено на порту ${config.port}`);
