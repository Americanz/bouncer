# Bouncer

Легкий та швидкий сервіс авторизації на Bun для захисту API за допомогою JWT токенів.

## Особливості

- Швидка валідація JWT токенів
- Підтримка Basic Auth та API Key (опціонально)
- Низьке споживання ресурсів
- Docker-ready для легкого розгортання
- Повна підтримка TypeScript

## Вимоги

- [Bun](https://bun.sh/) 1.0.0 або вище
- Docker (опціонально)

## Встановлення

```bash
# Клонуйте репозиторій
git clone https://github.com/your-username/bouncer.git
cd bouncer

# Встановіть залежності
bun install

# Скопіюйте приклад .env файлу та налаштуйте його
cp .env.example .env
```
