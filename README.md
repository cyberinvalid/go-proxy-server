# HTTP Proxy with Request/Response Override

Мощный HTTP прокси-сервер с возможностью логирования, подмены ответов и гибкой настройки через переменные окружения.

## 🚀 Возможности

- ✅ **Проксирование HTTP/HTTPS запросов** с сохранением всех заголовков, параметров и тела
- ✅ **Подробное логирование** запросов и ответов с настраиваемой детализацией
- ✅ **Подмена ответов** по правилам с поддержкой счетчиков и условий
- ✅ **Автоматическая распаковка** gzip сжатых ответов
- ✅ **Умное форматирование JSON** для лучшей читаемости
- ✅ **Поддержка regex** для гибкого сопоставления URL
- ✅ **Статистика и мониторинг** через встроенный API
- ✅ **Горячая перезагрузка** конфигурации
- ✅ **Стриминговый режим** для эффективной передачи больших файлов и Server-Sent Events (SSE)

## 📦 Установка

```bash
# Клонирование репозитория
git clone <repository-url>
cd http-proxy

# Запуск
go run main.go
```

## 🔧 Быстрый старт

### Базовое использование

```bash
# Запуск с настройками по умолчанию
go run main.go

# Проксирование на другой сервер
PROXY_TARGET=https://api.example.com go run main.go

# Изменение порта
PROXY_PORT=8080 go run main.go

# Ограничение логирования body
BODY_LOG_MODE=truncate MAX_LOG_LENGTH=200 go run main.go
```

### Полный пример команды

```bash
PROXY_TARGET=https://test.yandex.net/ \
PROXY_PORT=3000 \
BODY_LOG_MODE=truncate \
MAX_LOG_LENGTH=100 \
OVERRIDE_CONFIG=my-rules.json \
go run main.go
```

## ⚙️ Переменные окружения

### Основные настройки

| Переменная | Значение по умолчанию | Описание |
|------------|----------------------|----------|
| `PROXY_TARGET` | `https://test.yandex.net` | Целевой сервер для проксирования |
| `PROXY_PORT` | `8080` | Порт локального прокси сервера |
| `OVERRIDE_CONFIG` | `overrides.json` | Путь к файлу конфигурации подмен |

### Настройки логирования

| Переменная | Значение по умолчанию | Описание |
|------------|----------------------|----------|
| `LOG_REQUEST_BODY` | `true` | Логировать ли тело входящих запросов |
| `LOG_RESPONSE_BODY` | `true` | Логировать ли тело ответов |
| `LOG_REQUEST_HEADERS` | `true` | Логировать ли заголовки запросов |
| `LOG_RESPONSE_HEADERS` | `true` | Логировать ли заголовки ответов |
| `BODY_LOG_MODE` | `json_full` | Режим логирования тела |
| `MAX_LOG_LENGTH` | `2000` | Максимальная длина для обрезания |
| `ENABLE_STREAMING` | `false` | Включить стриминговый режим |

### Режимы BODY_LOG_MODE

- **`none`** - не показывать body вообще
- **`full`** - показывать все body полностью (осторожно с большими файлами!)
- **`truncate`** - обрезать все body до `MAX_LOG_LENGTH` символов
- **`json_full`** - JSON показывать полностью с форматированием, остальное обрезать

### 🚀 Стриминговый режим

Для эффективной работы с большими файлами и потоковыми данными (например, Server-Sent Events) можно включить стриминговый режим:

```bash
# Включить стриминг
ENABLE_STREAMING=true go run main.go
```

**Особенности стримингового режима:**
- ✅ **Без буферизации** - данные передаются напрямую от сервера к клиенту
- ✅ **Поддержка SSE** - автоматическое обнаружение `text/event-stream` с правильными заголовками
- ✅ **Chunked encoding** - сохраняется `Transfer-Encoding` для потоковых данных
- ✅ **Эффективность памяти** - не загружает весь ответ в память
- ⚠️ **Ограниченное логирование** - тело запросов/ответов не логируется для экономии памяти

**Когда использовать:**
- Загрузка/скачивание больших файлов
- Server-Sent Events (SSE) потоки
- WebSocket соединения через HTTP CONNECT
- Потоковые API (например, OpenAI streaming)

## 📝 Конфигурация подмен (overrides.json)

При первом запуске автоматически создается файл `overrides.json` с примерами.

### Структура правила подмены

```json
{
  "overrides": [
    {
      "name": "Описательное имя правила",
      "method": "*",
      "url_pattern": "/api/users",
      "is_regex": false,
      "status_code": 200,
      "trigger_after": 3,
      "max_triggers": 5,
      "reset_after": 10,
      "headers": {
        "Content-Type": "application/json",
        "X-Custom": "mocked"
      },
      "body_file": "responses/users.json",
      "body_text": "{\"mock\": true}",
      "enabled": true
    }
  ]
}
```

### Параметры правила

| Поле | Тип | Описание |
|------|-----|----------|
| `name` | string | Название правила для логов |
| `method` | string | HTTP метод (`*` для любого, `GET`, `POST`, etc.) |
| `url_pattern` | string | Паттерн URL для сопоставления |
| `is_regex` | bool | Использовать ли regex для `url_pattern` |
| `status_code` | int | HTTP статус код ответа |
| `trigger_after` | int | После скольких запросов срабатывать (0 = сразу) |
| `max_triggers` | int | Максимум срабатываний (-1 = бесконечно) |
| `reset_after` | int | Сброс счетчиков через N запросов (0 = не сбрасывать) |
| `headers` | object | Заголовки ответа |
| `body_file` | string | Путь к файлу с телом ответа |
| `body_text` | string | Текст ответа (альтернатива файлу) |
| `enabled` | bool | Включено ли правило |

## 🎯 Примеры использования

### 1. Простая подмена ответа

```json
{
  "overrides": [
    {
      "name": "Mock user profile",
      "method": "GET",
      "url_pattern": "/api/user/profile",
      "is_regex": false,
      "status_code": 200,
      "trigger_after": 0,
      "max_triggers": -1,
      "headers": {
        "Content-Type": "application/json"
      },
      "body_text": "{\"id\": 123, \"name\": \"Test User\", \"email\": \"test@example.com\"}",
      "enabled": true
    }
  ]
}
```

### 2. Подмена после N запросов

```json
{
  "overrides": [
    {
      "name": "Simulate error after 5 requests",
      "method": "*",
      "url_pattern": "/api/submit",
      "trigger_after": 5,
      "max_triggers": 1,
      "status_code": 500,
      "headers": {
        "Content-Type": "application/json"
      },
      "body_text": "{\"error\": \"Server temporarily unavailable\"}",
      "enabled": true
    }
  ]
}
```

### 3. Regex паттерны

```json
{
  "overrides": [
    {
      "name": "Mock any user by ID",
      "method": "GET",
      "url_pattern": "/api/users/\\d+",
      "is_regex": true,
      "status_code": 200,
      "headers": {
        "Content-Type": "application/json"
      },
      "body_file": "responses/user.json",
      "enabled": true
    }
  ]
}
```

### 4. Циклическая подмена

```json
{
  "overrides": [
    {
      "name": "Periodic maintenance simulation",
      "method": "*",
      "url_pattern": "/api/health",
      "trigger_after": 10,
      "max_triggers": 3,
      "reset_after": 20,
      "status_code": 503,
      "headers": {
        "Content-Type": "application/json"
      },
      "body_text": "{\"status\": \"maintenance\"}",
      "enabled": true
    }
  ]
}
```

## 📊 Мониторинг и статистика

### Встроенный API статистики

```bash
# Просмотр статистики всех правил
curl http://localhost:8080/_proxy_stats
```

Ответ:
```json
{
  "overrides": [
    {
      "name": "Mock user profile",
      "enabled": true,
      "url_pattern": "/api/user/profile",
      "method": "GET",
      "trigger_after": 0,
      "max_triggers": -1,
      "reset_after": 0,
      "request_count": 15,
      "trigger_count": 15
    }
  ],
  "total_rules": 3,
  "active_rules": 2,
  "log_settings": {
    "show_request_body": true,
    "show_response_body": true,
    "body_log_mode": "json_full",
    "max_log_length": 2000
  }
}
```

## 📁 Структура файлов

```
├── main.go              # Основной файл приложения
├── overrides.json       # Конфигурация подмен (автосоздается)
├── responses/           # Директория с файлами ответов
│   ├── users.json
│   ├── error.json
│   └── bindings.json
└── README.md
```

## 🚦 Примеры команд запуска

### Разработка и тестирование

```bash
# Минимальное логирование
BODY_LOG_MODE=none go run main.go

# Только статус коды и заголовки
LOG_REQUEST_BODY=false LOG_RESPONSE_BODY=false go run main.go

# Подробное логирование JSON
BODY_LOG_MODE=json_full go run main.go

# Ограниченное логирование для продакшна
BODY_LOG_MODE=truncate MAX_LOG_LENGTH=100 go run main.go

# Стриминговый режим для больших файлов
ENABLE_STREAMING=true go run main.go
```

### Стриминговый режим

```bash
# Стриминг с минимальным логированием
ENABLE_STREAMING=true \
BODY_LOG_MODE=none \
go run main.go

# Стриминг для SSE с логированием заголовков
ENABLE_STREAMING=true \
LOG_REQUEST_BODY=false \
LOG_RESPONSE_BODY=false \
go run main.go

# Стриминг через upstream прокси
ENABLE_STREAMING=true \
UPSTREAM_PROXY=http://proxy.example.com:8080 \
go run main.go
```

### Специфичные сценарии

```bash
# Проксирование с подменой для тестирования API
PROXY_TARGET=https://api.prod.com \
PROXY_PORT=3000 \
OVERRIDE_CONFIG=test-overrides.json \
BODY_LOG_MODE=json_full \
go run main.go

# Минимальный прокси без подмен
OVERRIDE_CONFIG=/dev/null \
BODY_LOG_MODE=truncate \
MAX_LOG_LENGTH=50 \
go run main.go

# Стриминговый прокси для файлового сервера
PROXY_TARGET=https://files.example.com \
ENABLE_STREAMING=true \
BODY_LOG_MODE=none \
go run main.go
```

## 🔍 Логирование

### Пример логов при json_full режиме

```
🔄 POST /api/users -> https://test.yandex.net/api/users
📤 Request Body (JSON formatted):
{
  "name": "John Doe",
  "email": "john@example.com",
  "preferences": {
    "theme": "dark",
    "notifications": true
  }
}
📥 Response Status: 201 Created
📥 Response Content-Type: application/json
📥 Response Body (JSON formatted):
{
  "id": 12345,
  "name": "John Doe",
  "email": "john@example.com",
  "created_at": "2024-01-15T10:30:45Z",
  "preferences": {
    "theme": "dark",
    "notifications": true
  }
}
✅ Запрос завершен
```

### Пример с подменой

```
🔄 GET /api/bindings -> https://test.yandex.net/api/bindings
📊 Правило 'Yandex bindings': запрос 3 (нужно 4 для срабатывания)
📥 Response Status: 200 OK
📥 Response Content-Type: application/json
📥 Response Body (JSON formatted):
{
  "bindings": ["real", "data"]
}
✅ Запрос завершен

🔄 GET /api/bindings -> https://test.yandex.net/api/bindings
📊 Правило 'Yandex bindings': запрос 4, срабатывание 1
🎭 Применяем подмену: Yandex bindings
📂 Загружен ответ из файла: responses/bindings.json (156 bytes)
🎭 Отправлен подменный ответ:
   Status: 200
   Headers: map[Content-Type:application/json X-Custom:overridden]
   Body (JSON formatted):
{
  "status": "mocked",
  "bindings": ["mock1", "mock2", "mock3"]
}
✅ Подмена завершена
```

## 🛠️ Troubleshooting

### Проблемы с кодировкой

Если видите символы типа `�h�`:
```bash
# Включите детальную диагностику
BODY_LOG_MODE=full go run main.go
```

### Подмены не срабатывают

1. Проверьте статистику: `curl http://localhost:8080/_proxy_stats`
2. Убедитесь что `enabled: true`
3. Проверьте паттерн URL и метод
4. Посмотрите счетчики `request_count` и `trigger_count`

### Большие файлы в логах

```bash
# Ограничьте размер логирования
BODY_LOG_MODE=truncate MAX_LOG_LENGTH=200 go run main.go

# Или отключите body
BODY_LOG_MODE=none go run main.go
```

### Стриминговые соединения не работают

```bash
# Включите стриминговый режим
ENABLE_STREAMING=true go run main.go

# Проверьте, что Transfer-Encoding сохраняется
ENABLE_STREAMING=true LOG_RESPONSE_HEADERS=true go run main.go
```

## 🤝 Расширение функционала

### Добавление новых типов подмен

1. Расширьте структуру `ResponseOverride`
2. Обновите `findMatchingOverride()` для новой логики
3. Добавьте обработку в `handleOverride()`

### Добавление новых форматов логирования

1. Добавьте новый режим в `BODY_LOG_MODE`
2. Создайте функцию `logBodyNewMode()`
3. Добавьте обработку в `logBody()`

## 📄 Лицензия

MIT License

## 🆘 Поддержка

Если у вас есть вопросы или предложения:

1. Проверьте логи на наличие ошибок
2. Убедитесь в корректности конфигурации
3. Проверьте статистику через `/_proxy_stats`
4. Создайте issue с подробным описанием проблемы

## 📋 Примеры использования стриминга

### Server-Sent Events (SSE)

```bash
# Терминал 1: Запуск прокси в стриминговом режиме
ENABLE_STREAMING=true \
PROXY_TARGET=https://api.openai.com \
go run main.go

# Терминал 2: Тестирование SSE потока
curl -H "Accept: text/event-stream" \
     -H "Authorization: Bearer your-token" \
     http://localhost:8080/v1/chat/completions \
     -d '{"model":"gpt-3.5-turbo","messages":[{"role":"user","content":"Hello"}],"stream":true}'
```

### Загрузка больших файлов

```bash
# Стриминговая загрузка без буферизации
ENABLE_STREAMING=true \
PROXY_TARGET=https://download.example.com \
BODY_LOG_MODE=none \
go run main.go

# Тест загрузки большого файла
curl -o bigfile.zip http://localhost:8080/files/bigfile.zip
```

### WebSocket через CONNECT

```bash
# Поддержка WebSocket туннелирования
ENABLE_STREAMING=true \
PROXY_TARGET=wss://websocket.example.com \
go run main.go
```

---

**Полезные ссылки:**
- Статистика: `http://localhost:8080/_proxy_stats`
- Тестирование: `curl -v http://localhost:8080/api/test`
- Стриминговый тест: `curl -H "Accept: text/event-stream" http://localhost:8080/stream`
- Конфигурация: `overrides.json`