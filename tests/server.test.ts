import { expect, test, describe } from "bun:test";

describe("Server Endpoints", () => {
  test("повинен повернути 401 без токена", async () => {
    const response = await fetch("http://localhost:3000/validate");
    expect(response.status).toBe(401);
  });

  test("повинен повернути 403 з невірним токеном", async () => {
    const response = await fetch("http://localhost:3000/validate", {
      headers: {
        Authorization: "Bearer invalid.token.here"
      }
    });
    expect(response.status).toBe(403);
  });

  // Тут можна додати тести з валідними токенами
});
