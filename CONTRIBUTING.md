# Руководство контрибьютора (Contributing to Hydra)

Спасибо за интерес к проекту **Hydra**! Мы приветствуем сообщения об ошибках, предложения по оптимизации, улучшение документации и Pull Request'ы.

---

## 🛠️ Окружение разработки (Development Setup)

Hydra написана на языке Rust (редакция 2024) и представляет собой Cargo-воркспейс из трех модулей:
- `hydra_api` — REST API сервер, планировщик и хранилище libSQL (SQLite WAL).
- `hydra_checker` — асинхронное ядро сетевой проверки и классификации прокси.
- `hydra_judge` — легковесный авторизованный эхо-сервер для оценки анонимности.

### Требования
- **Rust >= 1.85** (с поддержкой редакции Rust 2024)
- **Cargo** (стандартный пакетный менеджер)
- **SQLite / libSQL** (собирается встроенно, внешняя СУБД не требуется)

### Сборка и тестирование

1. Клонируйте репозиторий:
   ```bash
   git clone https://github.com/stormsia/hydra.git
   cd hydra
   ```

2. Создайте файл конфигурации окружения:
   ```bash
   cp .env.example .env
   ```

3. Соберите весь воркспейс:
   ```bash
   cargo build --workspace
   ```

4. Запустите тесты всего проекта:
   ```bash
   cargo test --workspace
   ```

5. Или тесты конкретного модуля при изолированной разработке:
   ```bash
   cargo test -p hydra_checker
   cargo test -p hydra_judge
   cargo test -p hydra_api
   ```

6. Проверьте форматирование и линтер перед отправкой:
   ```bash
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets -- -D warnings
   ```

---

## 📋 Правила оформления Pull Request

1. **Именование веток**: используйте префиксы назначения:
   - `feat/feature-name` — новая функциональность
   - `fix/bug-description` — исправление ошибки
   - `perf/optimization` — оптимизация производительности
   - `docs/doc-update` — изменения в документации
2. **Сообщения коммитов**: придерживайтесь формата [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat(checker): add support for protocol X`
   - `fix(api): correct pagination offset handling`
   - `docs(readme): update architecture diagram`
3. **Покрытие тестами**: любая новая функциональность или исправление бага должны сопровождаться модульными или интеграционными тестами в директории `tests/`.
4. **Документация**: при добавлении параметров ENV или роутов API обязательно обновляйте `.env.example`, `API.md` и соответствующие файлы `README.md`.

---

## 🔒 Безопасность (Security Vulnerabilities)

Если вы обнаружили уязвимость безопасности в Hydra, пожалуйста, **не создавайте публичные issues**. Сообщайте о них через функцию приватных отчетов безопасности на GitHub (Security Advisories).
