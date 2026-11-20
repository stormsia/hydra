[← Назад к Hydra README](../README.ru.md)

[English](README.md) • [Русский](README.ru.md) • [简体中文](README.zh.md)

# hydra_api

Модуль оркестрации, планирования проверок, персистентного хранения и REST API пула прокси-серверов Hydra. Координирует работу чекера (`hydra_checker`), взаимодействует с судьями (`hydra_judge`), управляет состояниями записей в СУБД libSQL (SQLite WAL).

## Структура файлов

```
hydra_api/
├── Cargo.toml                              # Манифест пакета Cargo и зависимости
├── .env.example                            # Шаблон переменных окружения
├── docs/API.md                             # Детальная спецификация схем и DTO REST API
├── README.md                               # Техническая документация модуля
├── migrations/
│   └── 001_initial.sql                     # SQL-миграция схем таблиц и B-Tree индексов
├── src/
│   ├── main.rs                             # Точка входа: запуск фоновых задач и HTTP-сервера
│   ├── lib.rs                              # Экспорт библиотеки и инициализация crypto provider
│   ├── app_state.rs                        # Разделяемое состояние приложения (AppState)
│   ├── config.rs                           # Парсинг и валидация конфигурации из окружения
│   ├── error.rs                            # Ошибки API и их маппинг в HTTP-статусы
│   ├── router.rs                           # Маршруты Axum, middleware авторизации, Swagger UI
│   ├── db/
│   │   ├── mod.rs                          # Реэкспорт функций доступа к базе данных
│   │   ├── init.rs                         # Инициализация libSQL, PRAGMA-настройки WAL, миграции
│   │   ├── proxies.rs                      # CRUD операции и выборка созревших прокси
│   │   ├── sources.rs                      # Учет источников прокси и статистика отдачи
│   │   └── proxy_sources.rs                # M2M-связи между прокси и источниками
│   ├── handlers/
│   │   ├── mod.rs                          # Реэкспорт HTTP-обработчиков
│   │   ├── proxies.rs                      # Хендлеры CRUD, импорта и отчетов о сбоях
│   │   ├── sources.rs                      # Хендлеры управления источниками
│   │   ├── stats.rs                        # Хендлеры метрик БД и in-memory телеметрии
│   │   └── judges.rs                       # Хендлеры статуса и проверок судей
│   ├── middleware/
│   │   ├── mod.rs                          # Реэкспорт middleware
│   │   └── auth.rs                         # Проверка заголовка авторизации X-API-Key
│   ├── models/
│   │   ├── mod.rs                          # Реэкспорт структур данных
│   │   ├── api.rs                          # DTO запросов/ответов API и схемы utoipa
│   │   └── db.rs                           # Модели строк базы данных (ProxyRow, SourceRow)
│   └── services/
│       ├── mod.rs                          # Реэкспорт фоновых сервисов
│       ├── scheduler.rs                    # Планировщик регулярного речека созревших прокси
│       ├── batch_writer.rs                 # MPSC-буфер пакетной транзакционной записи в БД
│       ├── geoip.rs                        # Lock-free GeoIP/ASN резолвер (MaxMind + ArcSwap)
│       ├── geoip_updater.rs                # Фоновое обновление mmdb файлов по ETag из CDN
│       ├── maintenance.rs                  # Очистка устаревших записей и оптимизация WAL/PRAGMA
│       └── parser.rs                       # Парсинг строковых форматов прокси и отсев Bogon IP
└── tests/
    ├── api_integration_tests.rs            # Интеграционные тесты эндпоинтов REST API
    ├── db_tests.rs                         # Интеграционные тесты SQL-запросов и миграций
    ├── models_and_parser_tests.rs          # Тесты парсера прокси и сериализации моделей
    └── scheduler_and_batch_writer_tests.rs # Тесты логики очередей планировщика и батчинга
```

## Основные подсистемы

- **Роутер (Axum 0.8):** Прием HTTP-запросов, проверка авторизации `X-API-Key`, раздача OpenAPI/Swagger UI и маршрутизация на хендлеры.
- **Планировщик (Scheduler):** Ежесекундная выборка созревших прокси (`next_check_at <= now`) и диспетчеризация в пул чекера с учетом таймаутов.
- **Batch Writer:** Неблокирующий MPSC-буфер для группировки результатов проверок и сброса в БД единой транзакцией каждые 100 мс.
- **GeoIP:** Lock-free обогащение IP метаданными страны и ASN (MaxMind DB через `ArcSwap`) с автообновлением по ETag из CDN.
- **База данных (libSQL):** Локальное хранилище в режиме WAL с таблицами `WITHOUT ROWID` и 8 B-Tree индексами для быстрого поиска и фильтрации.

## Переменные окружения

Все параметры считываются из окружения или файла `.env`. Все эндпоинты требуют заголовок `X-API-Key: <API_KEY>`.

| Переменная | Тип | Дефолт | Назначение |
| :--- | :--- | :--- | :--- |
| `LISTEN_ADDR` | String | `0.0.0.0:3000` | Сетевой адрес и порт API |
| `API_KEY` | String | — *(обязательно)* | Ключ авторизации заголовка X-API-Key |
| `DB_PATH` | String | `./data/hydra.db` | Путь к файлу базы данных |
| `EMBED_JUDGE` | bool | `false` | Запуск встроенного сервера Judge |
| `EMBED_JUDGE_PORT` | u16 | `8080` | Порт встроенного сервера Judge |
| `CHECKER_CONCURRENCY` | usize | `5000` | Лимит параллельных проверок чекера |
| `CHECKER_REAL_IP` | String | — | Внешний IP детекта анонимности |
| `JUDGE_HTTP_URL` | String | `http://127.0.0.1:8080` | URL эхо-сервера HTTP проверок |
| `JUDGE_HTTPS_URL` | String | `http://127.0.0.1:8080` | URL эхо-сервера HTTPS проверок |
| `JUDGE_SECRET_TOKEN` | String | `hydra_secret_token` | Статический токен верификации судьи |
| `JUDGE_SECRET_KEY` | String | — | HMAC-ключ суточной ротации токенов |
| `ENABLE_BUILTIN_JUDGE` | bool | `auto` | Включение встроенного судьи в пул проверок (true при EMBED_JUDGE/кастомном URL, иначе false) |
| `ENABLE_THIRD_PARTY_JUDGES` | bool | `true` | Включение пула сторонних судей |
| `JUDGE_HEALTH_CHECK_INTERVAL_SECS` | u64 | `30` | Интервал проверки доступности судей |
| `JUDGE_SELECTION_STRATEGY` | String | `lowest_latency` | Стратегия выбора рабочего судьи |
| `ADDITIONAL_JUDGES` | String | — | Дополнительные адреса сторонних судей |
| `GEOIP_AUTO_UPDATE` | bool | `true` | Автообновление баз из CDN |
| `GEOIP_COUNTRY_PATH` | String | `./geo/GeoLite2-Country.mmdb` | Путь к базе стран MaxMind |
| `GEOIP_ASN_PATH` | String | `./geo/GeoLite2-ASN.mmdb` | Путь к базе ASN MaxMind |
| `GEOIP_RELOAD_SECS` | u64 | `3600` | Интервал перечитки баз с диска |
| `GEOIP_UPDATE_INTERVAL_SECS` | u64 | `86400` | Интервал проверки обновлений CDN |
| `GEOIP_COUNTRY_URL` | String | `https://cdn.jsdelivr.net/...` | URL загрузки базы стран |
| `GEOIP_ASN_URL` | String | `https://cdn.jsdelivr.net/...` | URL загрузки базы ASN |
| `SCHEDULER_BATCH_SIZE` | usize | `10000` | Размер пачки задач планировщика |
| `BATCH_FLUSH_INTERVAL_MS` | u64 | `100` | Интервал пакетного сброса в БД |
| `DEAD_PROXY_RETENTION_DAYS` | u32 | `30` | Срок хранения мертвых прокси (дни) |
| `DB_MAINTENANCE_INTERVAL_SECS` | u64 | `3600` | Интервал фонового обслуживания БД |
| `RUST_LOG` | String | `info,hydra_api=debug` | Уровень детализации системных логов |

## Эндпоинты API

| Метод | Путь | Назначение |
| :--- | :--- | :--- |
| `POST` | `/api/v1/proxies/import` | Пакетный импорт сырых прокси в очередь `cold_queue` |
| `GET` | `/api/v1/proxies` | Выборка прокси с фильтрацией (страна, протокол, анонимность) |
| `GET` | `/api/v1/proxies/{id}` | Получение детальной информации о прокси по ID |
| `PATCH` | `/api/v1/proxies/{id}` | Частичное обновление параметров и политики проверки прокси |
| `DELETE` | `/api/v1/proxies/{id}` | Полное удаление прокси из базы данных |
| `POST` | `/api/v1/proxies/report-fail` | Отчет клиента о сбое для перевода в `cooldown` |
| `GET` | `/api/v1/sources` | Список источников и статистика их выхода (yield) |
| `GET` | `/api/v1/sources/{name}` | Детальная статистика конкретного источника по имени |
| `DELETE` | `/api/v1/sources/{name}` | Удаление источника и связанных с ним записей |
| `GET` | `/api/v1/judges` | Состояние, статус доступности и RTT судей |
| `POST` | `/api/v1/judges/health-check` | Принудительный запуск проверки доступности судей |
| `GET` | `/api/v1/stats` | Глобальная статистика пула и метрики базы данных |
| `GET` | `/api/v1/stats/engine` | In-memory телеметрия производительности чекера |
| `GET` | `/swagger-ui` | Интерактивная веб-документация Swagger UI |
| `GET` | `/api-docs/openapi.json` | Спецификация OpenAPI 3.0 в формате JSON |

Подробные схемы запросов, DTO и примеры ответов приведены в [../docs/API.ru.md](../docs/API.ru.md).

## Сборка и запуск

### 1. Настройка окружения

Linux / macOS:
```bash
cp .env.example .env
sed -i 's/API_KEY=.*/API_KEY=your_secure_key/' .env
```

Windows (PowerShell):
```powershell
Copy-Item .env.example .env
(Get-Content .env) -replace 'API_KEY=.*', 'API_KEY=your_secure_key' | Set-Content .env
```

### 2. Сборка и запуск

Linux / Windows:
```bash
# Запуск в режиме разработки
cargo run -p hydra_api

# Запуск в оптимизированном release-режиме
cargo run --release -p hydra_api

# Компиляция бинарного файла
cargo build --release -p hydra_api
```

### 3. Тестирование

```bash
cargo test -p hydra_api
```
