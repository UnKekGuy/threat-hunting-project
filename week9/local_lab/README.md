# Week 9: локальная лаборатория threat hunting

Источник задания: https://github.com/UnKekGuy/threat-hunting-project/tree/0260464cd692874ce7772a7ffd50a58849448e85/week9

Этот стенд воспроизводит неделю 9 на записанных Windows-логах OTRF. Команды атак из журналов не выполняются. Оригинальные Python-скрипты репозитория сохранены только как исходники; для импорта используется отдельный локальный `run_week9.py`.

## Интеграция с Atomic Red Team

`atomic_week9.py` читает настоящий закреплённый снимок YAML из официального redcanaryco/atomic-red-team. В каталоге 28 тестов из T1053.005, T1543.003 и T1569.002. Для исходных детекций выбраны два конкретных GUID:

- `e895677d-4f06-49ab-91b6-ae3742d0a2ba`: Scheduled Task Executing Base64 Encoded Commands From Registry (две детекции задачи).
- `2382dee2-a75f-49aa-9378-f52df6ed3fb1`: Execute a Command as a Service (одна детекция установки службы).

Снимок закреплён на `a0e3f9bc69fed2fd711bd1f1aa87a40c33482fe6`, проверяются Git blob SHA, GUID, название, техника, платформа и совместимость default-action строк с условиями детекций. Все 20 проверок пройдены: 11 unit и 9 read-only ES|QL expression checks. Эти проверки не запускали команды Atomic и не добавляли синтетические события в индекс.

```sh
python3 atomic_week9.py verify
python3 atomic_week9.py catalog
python3 atomic_week9.py run
WEEK9_TEST_ES=1 python3 -m unittest discover -s tests -v
python3 checks/verify_safety.py
```

Можно читать уже имеющийся checkout официального Atomic вместо встроенного снимка: `python3 atomic_week9.py verify --atomic-root /path/to/atomic-red-team`. Метаданные должны соответствовать указанному pinned commit; изменённые файлы отклоняются. `sync` загружает только эти три YAML с проверкой хешей, не выполняя код.

Отчёт: `output/atomic-coverage.json` и `output/atomic-coverage.txt`. Он разделяет подтверждённые метаданные, проверенные условия детекций и результат поиска на OTRF. Везде сохранены `execution_mode: recorded-equivalent` и `atomic_execution_verified: false`. Имена событий OTRF не подменяются именами Atomic.

Подробный гайд к защите: `docs/DEFENSE_GUIDE.md` и проверенные документы в `docs/`.

## Подготовка на новой машине

Нужны Python 3, PyYAML 6.0.2 и rootless Podman. Устанавливайте зависимости через официальные пакетные источники в отдельную Python-среду; `requirements.txt` фиксирует Python-зависимость. Сначала скачайте данные и официальный образ, затем запустите стенд:

```sh
python3 prepare_data.py
podman pull docker.elastic.co/elasticsearch/elasticsearch@sha256:13b4a40bb095774f5fda635e45fd5677cc6a26565e42b24997b0c72b88e75984
bash start-lab.sh
python3 atomic_week9.py run
```

Архивы и JSON-данные намеренно не входят в Git; загрузчик проверяет хеши и допускает повторный запуск. Для повторной демонстрации на текущем ноутбуке данные и образ уже готовы.

## Запуск и проверка

```sh
cd /home/lapis/threat-hunting-project-week9-atomic/week9/local_lab
bash start-lab.sh
python3 run_week9.py
```

Локальный API Elasticsearch: http://127.0.0.1:9201

- Контейнер: `threat-hunting-week9-es`.
- Образ: официальный Elasticsearch 9.5.5, закреплённый по digest в `start-lab.sh`.
- Индекс: `winlogs`.
- Данные: отдельный том Podman `threat-hunting-week9-es-data`.
- Ограничения: 3 ГБ RAM, 2 CPU; Java heap 1 ГБ.
- Вход по паролю отключён по согласованию. Порт доступен только на этом ноутбуке; не меняйте привязку на `0.0.0.0` и не храните здесь личные данные.
- Автозапуск при загрузке компьютера не включён.

Остановка без удаления данных:

```sh
podman stop threat-hunting-week9-es
```

## Результаты

Проверено 11 ноября 2026: Elasticsearch 9.5.5 запущен, кластер green, загружены все 78 868 событий. Три исходных запроса дали 1 / 2 / 1 совпадения, на семи фоновых наборах совпадений нет. Ограничение памяти и привязка только к localhost проверены. Подробности: `output/verification.json`.

Полные результаты реального запуска сохраняются в `output/results.txt` и `output/results.json`. До появления этих файлов выполнение запросов в Elasticsearch не считается проверенным.

Данные: 9 наборов OTRF, всего 78 868 событий. Семь фоновых наборов из week7 добавлены для воспроизведения проверки ложных срабатываний. Хеши и число событий каждого набора находятся в `output/data-manifest.json`.

Ожидаемый результат трёх исходных ES|QL-запросов:

1. `det-schtasks-persistence.esql`: 1 событие 4698, задача `MordorElevated` на WORKSTATION5.
2. `det-schtasks-process.esql`: 2 события одного `schtasks.exe`, Sysmon 1 и Security 4688 на WORKSTATION5. Это не два разных процесса; упоминание отдельного родительского PowerShell в исходном README неточно.
3. `det-service-lateral.esql`: 1 событие 7045, служба `Updater` на WORKSTATION6. Событие 7045 относится к журналу System.

Ноль совпадений на семи фоновых учебных наборах не означает отсутствие ложных срабатываний в реальной сети.

## Файлы

- `source/week9/`: неизменённые файлы задания.
- `source/week7/scripts/`: оригинальные скрипты для справки, не исполнялись.
- `prepare_data.py`: загрузка архивов с проверкой опубликованных Git blob SHA и безопасное извлечение только JSON.
- `run_week9.py`: пакетный импорт с проверкой ошибок и запуск исходных ES|QL-запросов. Идентификаторы документов стабильны; повторный запуск не дублирует события.
- `start-lab.sh`: воспроизводимый запуск контейнера.
- `data/`: скачанные архивы и исходные JSON-логи.
- `output/`: журнал загрузки, манифесты и результаты.

Для стенда не менялись системные настройки Fedora, настройки сна или существующие проекты.
