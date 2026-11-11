# 🎨 MoodBoard

Платформа для создания досок вдохновения (mood boards) с веб-интерфейсом и Telegram-ботом.

## 📋 О проекте

MoodBoard позволяет создавать доски, добавлять на них изображения и текстовые заметки, свободно размещать элементы по координатам, изменять размеры, слои и настройки оформления. Досками можно делиться с другими пользователями через код доски, а также работать совместно с соавторами.

### Возможности

- 📝 Создание досок с настраиваемым фоном, рамкой и размерами
- 🖼️ Добавление изображений и текстовых заметок
- 🎯 Свободное позиционирование элементов (X/Y, ширина/высота, z-index)
- 🔒 Публичные и приватные доски
- 👥 Ролевая модель: владелец и соавторы
- 🔑 Доступ к доске по коду в формате `XXX-XXX-XXX`
- 🤖 Telegram-бот для управления досками и регистрации
- 🌐 Web-интерфейс на Streamlit
- 🛡️ Защита от SQL-инъекций и валидация входных данных

## 🏗️ Архитектура

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  Telegram   │    │  Streamlit  │    │   FastAPI   │
│     Bot     │    │  Frontend   │    │     API     │
└──────┬──────┘    └──────┬──────┘    └──────┬──────┘
       │                  │                  │
       └──────────────────┴──────────────────┤
                                             │
                    ┌────────────────────────┼───────────────────────┐
                    │                        │                       │
              ┌─────▼─────┐          ┌───────▼───────┐        ┌──────▼──────┐
              │ PostgreSQL│          │     Redis     │        │  RQ Worker  │
              └───────────┘          └───────────────┘        └─────────────┘
```

## 🛠️ Технологии

- **Backend:** Python 3.12, FastAPI, SQLAlchemy, Alembic-style миграции
- **Frontend:** Streamlit
- **Bot:** python-telegram-bot 20.7
- **База данных:** PostgreSQL 15
- **Очереди:** Redis 7, RQ
- **Контейнеризация:** Docker, Docker Compose

## 📁 Структура проекта

```
MoodBoard/
├── api/                    # FastAPI backend
│   ├── main.py             # Точка входа, роуты
│   ├── database.py         # Подключение к PostgreSQL
│   ├── database_utils.py   # Утилиты безопасной работы с БД
│   ├── models.py           # SQLAlchemy модели
│   ├── migrations.py       # Миграции
│   ├── security_config.py  # Настройки безопасности
│   └── Dockerfile
├── bot/                    # Telegram-бот
│   ├── bot.py
│   └── Dockerfile
├── frontend/               # Streamlit-приложение
│   ├── app.py
│   └── Dockerfile
├── worker/                 # RQ worker
│   ├── worker.py
│   ├── tasks.py
│   └── Dockerfile
├── init.sql                # Инициализация БД
├── docker-compose.yml
├── .env.example
└── README.md
```

## 🔌 Основные эндпоинты API

### Аутентификация

| Метод | Путь | Описание |
|---|---|---|
| `POST` | `/api/auth/login` | Вход по логину и паролю |
| `GET` | `/api/auth/validate` | Проверка JWT токена |

### Пользователи

| Метод | Путь | Описание |
|---|---|---|
| `POST` | `/api/users/register` | Регистрация (вызывается ботом) |
| `GET` | `/api/users/{telegram_id}/status` | Статус пользователя |
| `GET` | `/api/users/{telegram_id}/boards` | Доски пользователя |
| `GET` | `/api/users/{telegram_id}/boards-with-roles` | Доски с ролями |
| `GET` | `/api/users/{telegram_id}/password` | Получить учётные данные |

### Доски

| Метод | Путь | Описание |
|---|---|---|
| `POST` | `/api/boards` | Создать доску |
| `GET` | `/api/boards/{board_id}` | Информация о доске |
| `GET` | `/api/boards/code/{board_code}` | Доска по коду |
| `GET` | `/api/boards/code/{board_code}/view` | Просмотр публичной доски по коду |
| `DELETE` | `/api/boards/{board_id}` | Удалить доску |
| `PUT` | `/api/boards/{board_id}/settings` | Обновить настройки |
| `GET` | `/api/boards/{board_id}/public-settings` | Публичные настройки |

### Контент

| Метод | Путь | Описание |
|---|---|---|
| `GET` | `/api/boards/{board_id}/content` | Контент доски |
| `POST` | `/api/boards/{board_id}/content` | Добавить элемент |
| `POST` | `/api/boards/{board_id}/content/upload` | Загрузить файл |
| `PUT` | `/api/boards/{board_id}/content/{id}/position` | Обновить позицию/размер |
| `PUT` | `/api/boards/{board_id}/content/{id}/layer` | Изменить слой |
| `DELETE` | `/api/boards/{board_id}/content/{id}` | Удалить элемент |

### Участники

| Метод | Путь | Описание |
|---|---|---|
| `GET` | `/api/boards/{board_id}/members` | Список участников |
| `POST` | `/api/boards/{board_id}/collaborators` | Добавить соавтора |
| `DELETE` | `/api/boards/{board_id}/collaborators/{user_id}` | Удалить соавтора |

Полная документация доступна на `/docs` (Swagger UI) и `/redoc`.

## 🤖 Команды Telegram-бота

| Команда | Описание |
|---|---|
| `/start` | Начать работу, регистрация |
| `/menu` | Главное меню |
| `/help` | Справка |
| `/status` | Статус системы |
| `/cancel` | Отменить действие |

## 🔒 Безопасность

- Пароли хранятся в виде хэшей `sha256_crypt`
- JWT-токены с ограниченным временем жизни
- Middleware блокирует запросы с признаками SQL-инъекций
- Валидация всех входных данных через Pydantic
- Ограничения на размер и типы загружаемых файлов
- CORS с явным списком разрешённых origin