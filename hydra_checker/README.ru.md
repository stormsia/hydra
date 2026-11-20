[← Назад к Hydra README](../README.ru.md)

[English](README.md) • [Русский](README.ru.md) • [简体中文](README.zh.md)

# Hydra Checker

Высокопроизводительное асинхронное ядро валидации и классификации прокси-серверов на Rust (Tokio). Обеспечивает превентивную L4-фильтрацию, каскадный автодетект протоколов (SOCKS4/5, HTTP CONNECT, Plain HTTP), сквозную проверку через пул судей (Judge Pool) и классификацию анонимности без утечек файловых дескрипторов.

## Структура файлов и директорий

```text
hydra_checker/
├── .env.example              # Шаблон конфигурационных переменных окружения
├── Cargo.toml                # Манифест пакета и зависимости
├── Cargo.lock                # Зафиксированные версии зависимостей
├── README.md                 # Техническая документация модуля
├── examples/
│   └── stress_bench.rs       # Стресс-тест и бенчмарк пропускной способности
├── src/
│   ├── judge/
│   │   ├── anonymity.rs      # Классификация уровня анонимности прокси
│   │   ├── endpoint.rs       # Структура эндпоинта и метаданные судьи
│   │   ├── health.rs         # Фоновый мониторинг доступности судей
│   │   ├── mod.rs            # Экспорт подсистемы взаимодействия с судьями
│   │   ├── pool.rs           # Пул судей, балансировка и failover
│   │   └── probe.rs          # L7-опрос судьи и валидация ответа
│   ├── pipeline/
│   │   ├── handshake.rs      # Протокольное рукопожатие и каскадный автодетект
│   │   ├── l4_probe.rs       # Проверка доступности L4 TCP-порта
│   │   ├── l7_judge.rs       # Сквозной L7-запрос через туннель
│   │   └── mod.rs            # Оркестрация фаз конвейера проверки
│   ├── pool/
│   │   ├── mod.rs            # Модуль пула параллельных воркеров
│   │   └── worker_pool.rs    # Ограничение конкурентности через семафор Tokio
│   ├── protocols/
│   │   ├── http_connect.rs   # Туннелирование методом HTTP CONNECT
│   │   ├── http_plain.rs     # Прямой форвардинг Plain HTTP
│   │   ├── mod.rs            # Трейты и структуры прокси-протоколов
│   │   ├── socks4.rs         # Протоколы SOCKS4 и SOCKS4a
│   │   └── socks5.rs         # Протокол SOCKS5 с поддержкой auth
│   ├── transport/
│   │   ├── mock.rs           # Мок-диалер для бессетевого тестирования
│   │   ├── mod.rs            # Абстракция сетевого транспорта (Dialer)
│   │   ├── tcp.rs            # TCP-диалер с SO_LINGER=0 и TCP_NODELAY
│   │   └── tls.rs            # TLS-коннектор и буфер PrefixedStream
│   ├── config.rs             # Конфигурация чекера и парсинг ENV
│   ├── engine.rs             # Главный фасад выполнения проверок
│   ├── error.rs              # Типизированные коды ошибок (ErrorReason)
│   ├── lib.rs                # Корневой модуль и публичный API
│   ├── models.rs             # Структуры целей, результатов и метрик
│   ├── net_filter.rs         # Защита от SSRF и Bogon-фильтрация
│   └── token.rs              # Ротация суточных HMAC-SHA256 токенов
└── tests/
    ├── anonymity_tests.rs    # Тесты детекции уровня анонимности
    ├── judge_pool_tests.rs   # Тесты пула судей и failover
    ├── mock_pipeline_tests.rs# Сквозные тесты конвейера на моках
    ├── net_filter_tests.rs   # Тесты Bogon-фильтра и DNS-rebind
    ├── tls_tunnel_tests.rs   # Тесты TLS-туннелей через прокси
    └── token_rotation_tests.rs # Тесты ротации HMAC-токенов
```

## Конвейер сетевой проверки

1. **L4 (TCP Connect)**: SYN-подключение с `SO_LINGER=0`, отсечение Bogon/SSRF и замер TCP RTT.
2. **Handshake**: Согласование протокола (SOCKS5, SOCKS4, HTTP CONNECT) или каскадный автодетект.
3. **TLS / Judge**: Установка TLS-сессии через туннель, отправка HTTP-запроса судье и валидация токена.
4. **Анонимность**: Анализ сетевых заголовков и сопоставление IP для определения уровня (Elite, Anonymous, Transparent). Если `CHECKER_REAL_IP` не задан, исходящий публичный IP автоматически определяется консенсусом судей (мажоритарное голосование большинства здоровых судей с фильтрацией bogon/localhost адресов).

## Конфигурация ENV

| Переменная | Тип | Дефолт | Назначение |
|---|---|---|---|
| `JUDGE_HTTP_URL` | String (URL) | `http://127.0.0.1:8080` | URL судьи для Plain HTTP |
| `JUDGE_HTTPS_URL` | String (URL) | `http://127.0.0.1:8080` | URL судьи для туннелей |
| `JUDGE_SECRET_TOKEN` | String | `hydra_secret_token` | Статический проверочный токен ответа |
| `JUDGE_SECRET_KEY` | Hex String | — | Ключ динамической HMAC-ротации токена |
| `CHECKER_CONCURRENCY` | usize | `5000` | Лимит параллельно выполняемых проверок |
| `CHECKER_CONNECT_TIMEOUT_MS` | u64 | `3000` | Таймаут установки TCP-соединения |
| `CHECKER_HANDSHAKE_TIMEOUT_MS` | u64 | `4000` | Таймаут протокольного рукопожатия туннеля |
| `CHECKER_READ_WRITE_TIMEOUT_MS` | u64 | `5000` | Таймаут обмена данными судьи |
| `CHECKER_MAX_READ_BYTES` | usize | `8192` | Максимальный размер тела ответа |
| `CHECKER_LOCAL_BIND_IP` | IpAddr | — | Привязка сокетов к интерфейсу |
| `CHECKER_REAL_IP` | IpAddr | *(авто: консенсус)* | Собственный публичный IP адрес для классификации анонимности (по умолчанию динамический автодетект через консенсус судей; явное значение переопределяет) |
| `ENABLE_BUILTIN_JUDGE` | bool | `true` | Включение встроенного/основного судьи в пул |
| `ENABLE_THIRD_PARTY_JUDGES` | bool | `true` | Использование пула сторонних судей |
| `JUDGE_SELECTION_STRATEGY` | String | `lowest_latency` | Стратегия балансировки пула судей |
| `ADDITIONAL_JUDGES` | String | — | Список дополнительных эхо-серверов судей |
| `RUST_LOG` | String | `info` | Уровень детализации системного логирования |

## Команды CLI

### Сборка
```bash
cargo build -p hydra_checker --release
```

### Тестирование
```bash
# Все тесты модуля
cargo test -p hydra_checker

# Запуск конкретного набора тестов
cargo test -p hydra_checker --test mock_pipeline_tests
```

### Линтинг и форматирование
```bash
cargo fmt --check
cargo clippy -p hydra_checker --all-targets -- -D warnings
```

### Бенчмарк
```bash
cargo run -p hydra_checker --example stress_bench --release
```
