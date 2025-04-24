import { expect, test, describe } from "bun:test";
import { validateJwt } from "../src/validators/jwt";

describe("JWT Validator", () => {
  test("повинен відхилити неправильний формат", async () => {
    const result = await validateJwt("InvalidFormat");
    expect(result.valid).toBe(false);
    expect(result.error).toContain("Неправильний формат");
  });

  test("повинен відхилити невірний токен", async () => {
    const result = await validateJwt("Bearer invalid.token.here");
    expect(result.valid).toBe(false);
  });

  // Тут можна додати більше тестів з валідними токенами
});
