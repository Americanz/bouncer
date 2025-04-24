import fs from "fs";
import path from "path";
import { logger } from "./logger";
import crypto from "crypto";

// Шлях до JSON файлу, який буде використовуватися як база користувачів
const USERS_DB_PATH = path.join(process.cwd(), "users.json");

// Структура для зберігання інформації про користувача
interface UserEntry {
  username: string;
  passwordHash: string;
  role: string;
  created: number;
  lastLogin?: number;
  enabled: boolean;
}

class UserDatabase {
  private users: UserEntry[] = [];

  constructor() {
    this.loadUsers();
  }

  // Завантаження користувачів з файлу
  private loadUsers() {
    try {
      if (fs.existsSync(USERS_DB_PATH)) {
        const data = fs.readFileSync(USERS_DB_PATH, "utf-8");
        this.users = JSON.parse(data);
        logger.info(`Завантажено ${this.users.length} користувачів з бази`);
      } else {
        logger.info("Файл бази користувачів не знайдено. Створюємо нову базу з базовими користувачами.");
        // Створюємо базових користувачів при першому запуску
        this.createDefaultUsers();
        this.saveUsers();
      }
    } catch (err) {
      logger.error(`Помилка завантаження бази користувачів: ${err}`);
      this.users = [];
      // Створюємо базових користувачів при помилці
      this.createDefaultUsers();
      this.saveUsers();
    }
  }

  // Створення базових користувачів при першому запуску
  private createDefaultUsers() {
    this.users = [
      {
        username: "admin",
        passwordHash: this.hashPassword("admin123"),
        role: "admin",
        created: Date.now(),
        enabled: true
      },
      {
        username: "user",
        passwordHash: this.hashPassword("user123"),
        role: "user",
        created: Date.now(),
        enabled: true
      }
    ];
    logger.info("Створено базових користувачів");
  }

  // Хешування паролю
  private hashPassword(password: string): string {
    return crypto.createHash('sha256').update(password).digest('hex');
  }

  // Збереження користувачів у файл
  private saveUsers() {
    try {
      fs.writeFileSync(USERS_DB_PATH, JSON.stringify(this.users, null, 2));
      logger.info(`Збережено ${this.users.length} користувачів у базу`);
    } catch (err) {
      logger.error(`Помилка збереження бази користувачів: ${err}`);
    }
  }

  // Додавання нового користувача
  addUser(username: string, password: string, role: string): boolean {
    // Перевіряємо, чи користувач вже існує
    if (this.users.some(u => u.username === username)) {
      logger.warn(`Спроба створити користувача з існуючим іменем: ${username}`);
      return false;
    }

    const newUser: UserEntry = {
      username,
      passwordHash: this.hashPassword(password),
      role,
      created: Date.now(),
      enabled: true
    };

    this.users.push(newUser);
    this.saveUsers();
    logger.info(`Створено нового користувача: ${username}`);
    return true;
  }

  // Перевірка облікових даних
  verifyCredentials(username: string, password: string): { valid: boolean; user?: { username: string; role: string } } {
    const user = this.users.find(u => u.username === username);
    
    if (!user) {
      return { valid: false };
    }

    if (!user.enabled) {
      logger.warn(`Спроба входу у відключений обліковий запис: ${username}`);
      return { valid: false };
    }

    const passwordHash = this.hashPassword(password);
    if (user.passwordHash !== passwordHash) {
      logger.warn(`Невірний пароль для користувача: ${username}`);
      return { valid: false };
    }

    // Оновлюємо час останнього входу
    user.lastLogin = Date.now();
    this.saveUsers();

    logger.info(`Успішна автентифікація користувача: ${username}`);
    return { 
      valid: true, 
      user: {
        username: user.username,
        role: user.role
      }
    };
  }

  // Деактивація користувача
  disableUser(username: string): boolean {
    const user = this.users.find(u => u.username === username);
    
    if (!user) {
      return false;
    }

    user.enabled = false;
    this.saveUsers();
    logger.info(`Деактивовано користувача: ${username}`);
    return true;
  }

  // Активація користувача
  enableUser(username: string): boolean {
    const user = this.users.find(u => u.username === username);
    
    if (!user) {
      return false;
    }

    user.enabled = true;
    this.saveUsers();
    logger.info(`Активовано користувача: ${username}`);
    return true;
  }

  // Зміна паролю
  changePassword(username: string, newPassword: string): boolean {
    const user = this.users.find(u => u.username === username);
    
    if (!user) {
      return false;
    }

    user.passwordHash = this.hashPassword(newPassword);
    this.saveUsers();
    logger.info(`Змінено пароль для користувача: ${username}`);
    return true;
  }

  // Отримання списку користувачів (без паролів)
  getUsers(): Array<{ username: string; role: string; created: number; lastLogin?: number; enabled: boolean }> {
    return this.users.map(u => ({
      username: u.username,
      role: u.role,
      created: u.created,
      lastLogin: u.lastLogin,
      enabled: u.enabled
    }));
  }
}

// Експортуємо єдиний екземпляр класу для використання в додатку
export const userDb = new UserDatabase();