# WAF API — Описание внешних функций API

## Общая информация

API реализован в соответствии со спецификацией **OpenAPI v3** и описан в файле:

```
docs/api/swagger.yaml
```

## Аутентификация

Аутентификация выполняется с использованием Bearer-токена:
```
Authorization: Bearer <token>
```

Исключение:
* `/api/v1/waf-status/` — доступен без аутентификации.

---

## Основные группы методов API

### 1. WAF Engine

* `GET /api/v1/waf-status/`
* `POST /api/v1/waf-status/`

Назначение:

* Проверка, защищён ли домен;
* Получение IP для проксирования трафика.

---

### 2. Sites (Управление сайтами)

* `GET /api/v1/sites/` — список сайтов
* `POST /api/v1/sites/` — добавить сайт
* `GET /api/v1/sites/{site_id}/` — детали сайта
* `PATCH /api/v1/sites/{site_id}/` — обновление
* `DELETE /api/v1/sites/{site_id}/` — удаление

---

### 3. Rules (Правила WAF)

* `GET /api/v1/rules/` — список правил
* `POST /api/v1/rules/` — создание правила
* `GET /api/v1/rules/{rule_id}/` — получить правило
* `PATCH /api/v1/rules/{rule_id}/` — обновить правило
* `DELETE /api/v1/rules/{rule_id}/` — удалить правило
* `POST /api/v1/rules/{rule_id}/toggle/` — включить/выключить правило

---

### 4. Logs (Логи)

* `GET /api/v1/logs/` — получить логи
* `POST /api/v1/logs/export/` — экспорт в CSV (асинхронно)
* `GET /api/v1/logs/exports/` — список экспортов
* `DELETE /api/v1/logs/exports/{filename}/` — удалить экспорт

---

### 5. Tokens (Токены доступа)

* `GET /api/v1/tokens/`
* `POST /api/v1/tokens/`
* `PATCH /api/v1/tokens/{token_id}/`
* `DELETE /api/v1/tokens/{token_id}/`
* `POST /api/v1/tokens/{token_id}/block-ip/`
* `POST /api/v1/tokens/{token_id}/unblock-ip/`

---

### 6. Users (Пользователи)

* `GET /api/v1/users/`
* `GET /api/v1/users/{user_id}/`
* `PATCH /api/v1/users/{user_id}/`

---

### 7. Monitoring

* `GET /api/v1/monitoring/`

Метрики:

* CPU
* RAM
* Disk
* RPS
* статус базы данных

---

### 8. Security

* `GET /api/v1/banned-ips/` — список заблокированных IP

---

### 9. Admin

* `GET /api/v1/admin/messages/`
* `POST /api/v1/admin/messages/{msg_id}/read/`
* `GET /api/v1/admin/sessions/`
* `DELETE /api/v1/admin/sessions/{session_key}/`

---

### 10. Stats

* `GET /api/v1/stats/` — статистика атак и трафика

---

### Формат ответа

```json
{
  "requestId": "018f1a2b-3c4d-7e5f-8a9b-0c1d2e3f4a5e",
  "title": "Bad Request",
  "detail": "Запрос содержит некорректные данные. Проверьте тело запроса.",
  "timestamp": "2025-04-27T12:00:00Z"
}
```

### Поля

| Поле      | Описание                     |
| --------- | ---------------------------- |
| requestId | UUIDv7 идентификатор запроса |
| title     | краткое описание ошибки      |
| detail    | подробности и рекомендации   |
| timestamp | время в UTC                  |

---

## Поддерживаемые HTTP-коды

### 2xx — Успешные

* 200 OK
* 201 Created
* 202 Accepted

### 4xx — Ошибки клиента

* 400 Bad Request
* 401 Unauthorized
* 403 Forbidden
* 404 Not Found
* 405 Method Not Allowed
* 413 Payload Too Large
* 414 URI Too Long
* 415 Unsupported Media Type
* 418 I’m a teapot
* 429 Too Many Requests

### 5xx — Ошибки сервера

* 500 Internal Server Error
* 501 Not Implemented
* 502 Bad Gateway
* 503 Service Unavailable
* 504 Gateway Timeout
