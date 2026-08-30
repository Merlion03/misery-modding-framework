# GameInstance

> Заполнен в **M4**. Живое наблюдение (read-only) + сверка с исходниками UE 5.4.4.
> Офсеты получены из живых `FProperty`, а не из констант.

## Questions to answer

Из plan.md §11.1, строка 2:

1. Какой класс используется как GameInstance?
2. Есть ли игровые subsystems (`UGameInstanceSubsystem`)?
3. Что в них лежит?

## Data to collect

Класс, список subsystems, их свойства.

## Method

Перечисление живых объектов по классу-предку (`/Script/Engine.GameInstance`,
`/Script/Engine.GameInstanceSubsystem`) через `research/instruments/lifecycle/resolver.py` и
`census.py`; обход объявленных свойств по цепочке `SuperStruct`; проверка отношения владения
через `UObjectBase::OuterPrivate`.

## Findings (evidence level, confidence, build_key)

**build_key:** `sha256:bace50f7185d095d03ee18a2fea701c747810c31f2037bda21ea57a81f013331`
**Evidence level:** OBSERVED · **Confidence:** 0.9

### 1. Класс GameInstance

| | |
|---|---|
| Живых экземпляров | **ровно 1** (проверено в обоих запусках) |
| Класс | `BP_SGKGameInstance_C` |
| Путь класса | `/Game/SurvivalGameKitV2/Blueprints/Saving/BP_SGKGameInstance.BP_SGKGameInstance_C` |
| Путь объекта | `/Engine/Transient.GameEngine:BP_SGKGameInstance_C` |
| Цепочка | `BP_SGKGameInstance_C → GameInstance → Object` |

Между Blueprint-классом и движковым `UGameInstance` **нет собственного C++-класса**. Расположение
исходника под `.../Saving/` — указание на то, что этот класс несёт состояние сохранения; проверка
этого относится к `save.md` (M6), здесь не делается.

### 2. Subsystems — и почему их нельзя спросить у GameInstance

`UGameInstance::SubsystemCollection` **не отражён** (как и `Subsystems`). Спросить GameInstance,
какие у него подсистемы, невозможно. Они находятся обходом `GUObjectArray` по классу-предку с
проверкой `Outer == GameInstance`.

Живые `UGameInstanceSubsystem` — **2, перечислены полностью**:

| Класс | Путь класса | Объявленных свойств |
|---|---|---|
| `ReplaySubsystem` | `/Script/Engine.ReplaySubsystem` | 1: `bLoadDefaultMapOnStop` (`FBoolProperty`, `+48`) |
| `MiseryFocusSubsystem` | **`/Script/MISERY.MiseryFocusSubsystem`** | 0 |

Живые `ULocalPlayerSubsystem` — **1**: `EnhancedInputLocalPlayerSubsystem`, `Outer` —
`/Engine/Transient.GameEngine:LocalPlayer`.

### 3. Что в них лежит

`ReplaySubsystem` объявляет одно свойство. `MiseryFocusSubsystem` **не объявляет ни одного
отражённого свойства** — это утверждение об отражении, а не о том, что объект пуст: у нативного
класса могут быть обычные C++-члены, которых reflection не видит и которые этим проектом не
угадываются.

### 4. Побочный, но важный факт: у MISERY есть собственный нативный модуль

`MiseryFocusSubsystem` лежит в пакете **`/Script/MISERY`**, то есть в нативном игровом модуле, а
не в Blueprint. Там же найден `MiseryGameViewportClient` — живой `UGameViewportClient` в этой
сборке именно этого класса. Значит утверждение «в MISERY нет своего C++» неверно в целом; верно
лишь то, что **в цепочке GameMode и GameInstance** своего C++-класса нет. Это различение важно
для этапов 5 и 6 и записано здесь, чтобы позже не быть выведенным заново из более слабых данных.

### 5. Время жизни

`UGameInstance` **переживает** каждый наблюдённый внутрипроцессный переход, включая смену мира
меню → загрузка сейва → геймплей: адрес `0x244f9109100` неизменен во всех пяти наблюдениях
запуска 2. Это согласуется с движком, который переиспользует тот же объект
(`UnrealEngine.cpp:15379`, `World.cpp:7427`), но здесь это **измерено**, а не выведено.

Через границу процесса не переживает ничего: другой процесс — другая куча, и совпадение путей
объектов там ничего не значит.

## What is "enough" (definition of done)

Критерий подсистемы: **перечислены все subsystems с их классами** — выполнено: 2
`UGameInstanceSubsystem` и 1 `ULocalPlayerSubsystem`, каждый с полным путём класса.

## Implications for future SDK

- GameInstance — естественное место для регистрации сервисов мода: это единственный
  игровой объект, переживший все наблюдённые переходы.
- Собственные подсистемы мода не смогут быть найдены через `SubsystemCollection` — он не
  отражён. Фреймворк обязан вести собственный реестр, а не рассчитывать на обход движка.
- `/Script/MISERY` — существующий нативный модуль. Любая схема загрузки на этапе 5 обязана
  сосуществовать с ним, а не предполагать, что нативного кода в игре нет.

## Open unknowns

- Содержимое `MiseryFocusSubsystem` — нет отражённых свойств; его назначение не установлено.
- Что именно `BP_SGKGameInstance_C` хранит для сохранений — относится к `save.md` (M6).
- Поведение при co-op — не наблюдалось (M8/Stage 8).
