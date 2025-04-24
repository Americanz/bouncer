export class AuthError extends Error {
  status: number;

  constructor(message: string, status: number = 401) {
    super(message);
    this.name = "AuthError";
    this.status = status;
  }
}

export function handleError(error: unknown): Response {
  if (error instanceof AuthError) {
    return new Response(error.message, { status: error.status });
  }

  if (error instanceof Error) {
    return new Response(error.message, { status: 500 });
  }

  return new Response("Невідома помилка", { status: 500 });
}
