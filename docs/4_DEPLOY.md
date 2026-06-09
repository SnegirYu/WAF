# Развертывание WAF

Документ описывает запуск текущей версии проекта `WAF` через Docker Compose.

Проект включает Django-панель управления, WAF engine, OpenResty/Nginx, PostgreSQL и тестовое приложение OWASP Juice Shop.

## 1. Состав системы

Сервисы описаны в `docker-compose.yml`.

| Сервис | Назначение | Внешний порт |
| --- | --- | --- |
| `db` | PostgreSQL 15, основная БД | `5432` |
| `web` | Django-приложение, админ-панель, API для Nginx | `8000` |
| `engine` | WAF proxy engine | `8080` |
| `nginx` | OpenResty/Nginx, основная входная точка | `80` |
| `juice-shop` | Тестовое приложение OWASP Juice Shop | `3000` |

Постоянные данные:

- `postgres_data` — данные PostgreSQL;
- `static_volume` — статические файлы Django после `collectstatic`.

## 2. Требования

Рекомендуемая среда:

- Ubuntu 22.04 LTS или Debian 12;
- Docker 24+;
- Docker Compose v2;
- `git`;
- свободные порты `80`, `3000`, `5432`, `8000`, `8080`.

Проверка:

```bash
docker --version
docker compose version
git --version
```

## 3. Получение проекта

```bash
git clone <URL_репозитория>
cd WAF
```

Если развертывается конкретная версия:

```bash
git checkout <tag-or-branch>
```

## 4. Первый запуск

Запустите сборку и контейнеры:

```bash
docker compose up -d --build
```

Сервис `web` при старте автоматически выполняет:

```bash
python manage.py migrate
python manage.py collectstatic --noinput
gunicorn waf_project.wsgi:application --bind 0.0.0.0:8000
```

Проверьте состояние контейнеров:

```bash
docker compose ps
```

Ожидаемый результат: сервисы `db`, `web`, `engine`, `nginx` и `juice-shop` находятся в состоянии `running` или `Up`.

## 5. Создание администратора

После первого запуска создайте суперпользователя Django:

```bash
docker compose exec web python manage.py createsuperuser
```

Панели управления:

- `http://<IP_сервера>/admin/` — стандартная Django admin;
- `http://<IP_сервера>/panel/` — панель администратора проекта;
- `http://<IP_сервера>/dashboard/` — пользовательская панель.

Для входа через GitHub OAuth добавьте Social Application в Django admin:

```text
/admin/ -> Social applications -> Add
```

Укажите `client id` и `secret key` GitHub OAuth-приложения.

## 6. Проверка после запуска

Проверка Nginx:

```bash
curl http://localhost/health
```

Ожидаемый ответ:

```text
OK
```

Основные адреса:

| Адрес | Назначение |
| --- | --- |
| `http://<IP_сервера>/health` | health-check Nginx |
| `http://<IP_сервера>/login/` | вход в приложение |
| `http://<IP_сервера>/dashboard/` | кабинет пользователя |
| `http://<IP_сервера>/panel/` | панель администратора |
| `http://<IP_сервера>:3000` | прямой доступ к Juice Shop |

Логи:

```bash
docker compose logs nginx --tail 100
docker compose logs web --tail 100
docker compose logs engine --tail 100
docker compose logs db --tail 100
```

Логи в реальном времени:

```bash
docker compose logs -f
```

## 7. Добавление защищаемого сайта

1. Войдите в приложение.
2. Откройте `dashboard/`.
3. Добавьте сайт:
   - `domain` — домен из HTTP-заголовка `Host`, например `example.com`;
   - `target_ip` — адрес приложения, куда WAF должен проксировать трафик;
   - `traffic_limit_mb` — месячный лимит трафика в МБ, `0` означает без лимита.
4. Правила WAF настраиваются в `panel/rules/`.

Важно: значение `domain` должно совпадать с доменом, по которому клиент обращается к Nginx.

## 8. Обновление

Перед обновлением желательно сделать резервную копию базы данных.

```bash
git pull origin main
docker compose pull
docker compose up -d --build
```

`docker compose pull` обновляет внешние образы `postgres`, `openresty` и `juice-shop`.

Сервисы `web` и `engine` в текущем `docker-compose.yml` собираются локально из `Dockerfile.web` и `Dockerfile.engine`, поэтому при обновлении нужен флаг `--build`.

После обновления:

```bash
docker compose ps
docker compose logs web --tail 100
docker compose logs engine --tail 100
```

## 9. Остановка и резервное копирование

Остановить контейнеры без удаления данных:

```bash
docker compose stop
```

Остановить и удалить контейнеры, сохранив volumes:

```bash
docker compose down
```

Не используйте без резервной копии:

```bash
docker compose down -v
```

Флаг `-v` удаляет volumes, включая `postgres_data`.

Дамп PostgreSQL:

```bash
docker compose exec db pg_dump -U waf_user -d waf_db > waf_db_backup.sql
```

Восстановление:

```bash
docker compose exec -T db psql -U waf_user -d waf_db < waf_db_backup.sql
```
