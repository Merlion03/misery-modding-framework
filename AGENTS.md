Ты работаешь над проектом **MISERY Modding Framework**.

В корне репозитория находится `AGENTS.md`.

Сначала полностью прочитай его и считай его основным набором правил проекта.

> **Статус этого файла.** Ниже — исходное задание, из которого выросли `plan.md`
> и вся Phase 1. Оно сохранено как есть: правила работы, запреты и стиль в нём
> действуют. Устарела ровно одна его часть — утверждения о том, на каком этапе
> проект находится и чего «сейчас не нужно» строить. Раздел «Текущий этап»
> исправлен по месту; **описание текущего состояния платформы живёт только в
> `README.md`**, и при расхождении прав он.

## Текущий этап

**Обновлено после закрытия Stage 8.** Phase 1 (Research) закрыта; фундамент
построен и работает. Production bootstrap, нативный `MiseryRuntime.dll`,
CoreCLR-хост и публичный C#-API `Misery.ModAPI` **существуют и доказаны в живой
игре** — что именно и на каком уровне доказательности, перечислено в `README.md`
§2. Следующий этап — **Stage 9, Multiplayer Foundations**.

Исходная формулировка этого раздела гласила, что мы «только на Phase 1» и что
production Mod Loader, Bootstrap, SDK и `MiseryRuntime.dll` создавать не нужно.
Это было верно, когда писалось, и перестало быть верным к Stage 5B. Строка
сохранена здесь как история, а не как указание.

Задача остаётся той же по существу: строить собственную modding platform без
зависимости от UE4SS.

Конечный пользовательский UX должен быть таким:

```text
MISERY/
└── Mods/
    ├── ModA/
    ├── ModB/
    └── ModC/
```

Framework устанавливается один раз.

После этого пользователь просто кладёт моды отдельными папками в `Mods` и запускает MISERY обычным способом через Steam.

Оригинальные файлы игры мы не изменяем и не перезаписываем.

Целевая будущая архитектура:

```text
Steam
  ↓
MISERY-Win64-Shipping.exe
  ↓
Bootstrap
  ↓
MiseryRuntime
  ↓
Version-specific bindings
  ↓
Misery public API
  ↓
Mods/*
```

Но сейчас эта архитектура является только направлением исследования, а не разрешением сразу её реализовывать.

---

# Твоя задача сейчас

НЕ начинай реализацию.

Сначала:

1. Изучи весь существующий репозиторий.
2. Найди уже существующие исследования, заметки, инструменты и код.
3. Определи, есть ли локально установленная MISERY.
4. Если путь к игре не указан явно, сначала попробуй обнаружить его самостоятельно:

   * стандартные Steam library locations;
   * дополнительные Steam libraries;
   * `libraryfolders.vdf`;
   * Windows registry, если полезно;
   * существующие конфиги/пути проекта.
5. Ничего не изменяй внутри оригинальной установки игры.
6. Если бинарник нужен для анализа, работай read-only либо используй копию в исследовательском workspace.
7. После первичного осмотра создай **`plan.md`**.

Сейчас твой основной deliverable — именно хороший `plan.md`.

Не начинай выполнять сам research plan до тех пор, пока `plan.md` не будет полностью сформирован.

---

# Что должно быть в plan.md

План должен быть достаточно подробным, чтобы другой сильный инженер или AI-агент мог продолжить работу по нему без дополнительного объяснения контекста.

Разбей исследование на этапы.

Минимально должны присутствовать следующие направления.

---

## 1. Repository audit

Опиши:

* что уже существует;
* какие файлы относятся к research;
* какие инструменты уже присутствуют;
* что можно переиспользовать;
* чего пока нет.

Не делай предположений без проверки.

---

## 2. Game installation discovery

Опиши, как будет:

* обнаружена установка MISERY;
* определён основной executable;
* найдена директория `Content/Paks`;
* обнаружены `.pak`, `.utoc`, `.ucas`;
* найдены конфиги;
* определена Steam App installation.

Никаких изменений файлов игры.

---

## 3. Build fingerprinting

Разработай точный процесс создания fingerprint конкретной сборки.

Он должен включать минимум:

* SHA-256 executable;
* размер;
* PE metadata;
* file/product version;
* game version;
* Unreal Engine version evidence;
* modules;
* package layout;
* IoStore/Pak status.

Опиши, куда эти данные будут сохраняться.

Предложи стабильный `build-id`.

---

## 4. Unreal Engine version identification

Не полагайся только на одно свидетельство.

Запланируй несколько способов подтверждения Unreal Engine version/build.

Например:

* binary metadata;
* engine strings;
* asset/package versions;
* known UE structures;
* dependencies;
* Unreal-specific serialized data.

В плане должна быть стратегия cross-validation.

---

## 5. Asset and package research

Нужно определить:

* Pak vs IoStore;
* mount points;
* AssetRegistry;
* package names;
* Blueprint assets;
* DataAssets;
* DataTables;
* Niagara;
* meshes;
* animations;
* sounds;
* maps;
* dependencies.

Особый приоритет:

> понять, возможно ли позже добавлять собственный cooked content без изменения оригинальных контейнеров игры.

Запланируй отдельные эксперименты для:

```text
custom texture
custom mesh
custom Blueprint/Actor
custom Niagara effect
```

Но пока только спроектируй исследование.

Не начинай производство полноценного content pipeline.

---

## 6. Unreal Reflection research

Нужно выяснить, как в конкретной сборке получить доступ к:

```text
UObject
UClass
UStruct
UFunction
FProperty
FName
GUObjectArray / equivalent object storage
World
GameInstance
PlayerController
PlayerCharacter
```

План должен идти от наименее invasive методов к более глубоким.

Цель:

создать машинно-читаемую карту reflected game classes.

Не использовать UE4SS как runtime dependency.

---

## 7. Static binary research

Опиши стратегию анализа `MISERY-Win64-Shipping.exe`.

Предпочтительно через Ghidra или сопоставимый воспроизводимый pipeline.

Не пытайся декомпилировать игру целиком.

Исследование должно быть семантическим.

Пример:

```text
Known reflected class
        ↓
known string/property
        ↓
xrefs
        ↓
candidate function
        ↓
callers/callees
        ↓
runtime validation
```

Запланируй инструменты для:

* strings;
* xrefs;
* function lookup;
* decompilation;
* callers;
* callees;
* signatures;
* constants;
* pattern validation.

---

## 8. Research Probe

Спроектируй минимальный временный `MiseryResearchProbe`.

Это НЕ production loader.

Его возможные задачи:

* enumerating objects;
* dumping reflected classes;
* dumping functions;
* dumping properties;
* finding World;
* finding GameInstance;
* identifying local PlayerController;
* identifying local PlayerCharacter;
* runtime observation;
* validating static-analysis hypotheses.

В `plan.md` отдельно обозначь:

```text
Research Probe != MiseryRuntime
```

Не позволяй архитектуре исследовательского probe автоматически стать архитектурой production framework.

---

## 9. Knowledge Base

Спроектируй, как результаты должны сохраняться между сессиями.

Мне не нужен research, который существует только в контексте Claude.

Нужна постоянная база знаний.

Например:

```text
research/
├── builds/
├── unreal/
├── systems/
├── evidence/
├── RESEARCH_LOG.md
└── unknowns.md
```

Можно улучшить структуру.

Определи:

* JSON для machine-readable data;
* Markdown для semantic documentation;
* при необходимости SQLite для большого количества сущностей.

Особенно важно хранить:

```text
raw identifier
semantic alias
evidence
confidence
game build
relationships
```

---

## 10. Evidence model

В план обязательно включи систему:

```text
OBSERVED
INFERRED
HYPOTHESIS
UNKNOWN
```

и confidence:

```text
0.00–1.00
```

Публично значимые будущие bindings не должны считаться подтверждёнными только по одной слабой догадке.

Опиши критерии подтверждения.

---

## 11. Gameplay subsystem research

Не исследовать всё одновременно.

Создай последовательность исследования.

Приоритет примерно такой:

```text
World
GameInstance
LocalPlayer
PlayerController
PlayerCharacter
Components
Inventory
Items
Weapons
Actor spawning
Damage
Interaction
Effects
AI
Time
Weather
Save system
Networking/Replication
UI
```

Для каждого subsystem в плане укажи:

* какие вопросы надо ответить;
* какие данные собрать;
* какой результат считать достаточным;
* какие данные нужны будущему SDK.

---

## 12. Multiplayer and replication

MISERY — multiplayer/co-op game, поэтому нельзя проектировать API как полностью single-player систему.

Запланируй исследование:

* authority;
* server/host;
* client;
* replicated actors;
* RPC;
* replicated properties;
* ownership;
* local vs remote players.

Не разрабатывай функции для читинга в публичных сессиях.

Нам нужна архитектура корректных multiplayer-модов.

---

## 13. Bootstrap feasibility research

Мы хотим Variant B:

> пользователь запускает MISERY обычным способом через Steam, а небольшой bootstrap автоматически поднимает наш runtime.

Однако способ bootstrap пока НЕ выбран.

В плане сравни возможные подходы по:

* надёжности;
* сложности;
* Steam compatibility;
* необходимости изменения оригинальных файлов;
* survivability после обновлений;
* моменту инициализации;
* uninstall experience;
* crash behavior.

Результатом Phase 1 должна стать аргументированная рекомендация.

Не выбирай механизм заранее только потому, что он привычный.

---

## 14. Content loading feasibility

Это один из важнейших вопросов всего проекта.

Нужно понять, сможет ли будущий Runtime делать примерно следующее:

```text
Mods/MyWeapon/Content/...
        ↓
mount additional container
        ↓
discover asset
        ↓
load asset
        ↓
spawn/use it in MISERY
```

Разделяй:

```text
mounting asset
```

и:

```text
registering asset in gameplay
```

Это разные проблемы.

Запланируй исследование обеих.

---

## 15. Future SDK implications

На основании каждого исследования фиксируй:

> Что этот результат означает для будущего публичного API?

Например:

```text
Raw:
BP_PlayerCharacter_C.HealthComponent.CurrentHealth

Potential public API:
player.GetHealth()
```

Но НЕ проектируй весь SDK заранее.

API должен появляться из понимания игры, а не наоборот.

---

## 16. Version compatibility strategy

Запланируй исследование того, что можно использовать как:

```text
stable reflected identifier
structural relationship
signature
version-specific binding
raw offset
```

Предполагаемая будущая схема:

```text
Mod
 ↓
Stable Misery API
 ↓
Runtime
 ↓
Bindings for current game build
 ↓
MISERY
```

После патча игры желательно обновлять Runtime/Bindings, а не все существующие моды.

---

## 17. Toolchain

В `plan.md` перечисли инструменты, которые действительно потребуются.

Для каждого укажи:

* назначение;
* откуда его безопасно получить;
* будет ли он частью repository;
* нужен ли он однократно или постоянно;
* какие артефакты производит.

Предпочитай:

* воспроизводимые;
* scriptable;
* open-source;
* хорошо документированные решения.

Не скачивай и не запускай сомнительные бинарники.

---

## 18. Milestones

План должен иметь понятные milestones.

Например:

```text
M0 — Environment + repository audit
M1 — Build fingerprint
M2 — Package/asset map
M3 — Unreal reflection access
M4 — World/player identification
M5 — Core gameplay system maps
M6 — Content loading feasibility
M7 — Bootstrap feasibility
M8 — Networking model
M9 — Phase 1 architecture report
```

Можешь предложить лучший вариант.

Для каждого milestone нужны exit criteria.

---

## 19. Expected artifacts

Укажи конкретные файлы, которые должны появиться в процессе исследования.

Например:

```text
research/builds/<build>/fingerprint.json
research/RESEARCH_LOG.md
research/unknowns.md
research/systems/player.md
research/systems/inventory.md
research/systems/weapons.md
docs/bootstrap-feasibility.md
docs/content-feasibility.md
docs/phase1-report.md
```

Не ограничивайся этим списком, если нужна лучшая структура.

---

## 20. Phase 1 final report

В конце Phase 1 должен появиться отдельный документ, отвечающий:

1. Как устроена исследованная сборка MISERY?
2. Какой Unreal runtime мы имеем?
3. Насколько доступна Reflection?
4. Как представлены основные gameplay systems?
5. Можно ли загружать custom cooked assets?
6. Можно ли использовать custom Blueprint content?
7. Как должен работать future Bootstrap?
8. Как должен работать future Runtime?
9. Какие части требуют build-specific bindings?
10. Какие самые большие технические риски?
11. Реалистична ли конечная цель:

```text
install framework
 ↓
put mod in Mods/
 ↓
launch Steam
 ↓
mod works
```

12. Что именно следует реализовывать в Phase 2?

---

# Важные ограничения

Не:

* модифицируй оригинальные файлы MISERY;
* патчь executable на диске;
* заменяй оригинальные containers;
* используй UE4SS как фундамент будущего framework;
* ~~строй production loader сейчас~~ — **снято после Stage 5B**: production
  bootstrap построен и является частью продукта. Остаётся в силе то, чем он
  ограничен: не зависит от UE4SS, не патчит образ на диске, ставится ровно в
  одну явно спроектированную точку;
* начинай массово писать API wrappers;
* декомпилируй бессистемно весь executable;
* называй догадки фактами;
* удаляй существующую работу;
* обходи DRM/licensing/access-control;
* превращай multiplayer research в cheat framework.

Если какая-либо операция потенциально разрушительна — сначала найди read-only вариант.

---

# Стиль работы

Исследование должно быть:

```text
question
 ↓
method
 ↓
evidence
 ↓
finding
 ↓
confidence
 ↓
persistent artifact
 ↓
next question
```

а не:

```text
попробовали случайную штуку
 ↓
вроде заработало
 ↓
забыли почему
```

---
