// Конфігурація додатку
export const config = {
  port: parseInt(process.env.PORT || "3000"),
  jwtSecret: process.env.JWT_SECRET || "your-secret-key",
  allowedTokens: (process.env.ALLOWED_TOKENS || "").split(",").filter(Boolean),
  logLevel: process.env.LOG_LEVEL || "info",
};
