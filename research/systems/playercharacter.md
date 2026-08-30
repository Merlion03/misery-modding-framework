# PlayerCharacter

> Заполнен в **M4**. Живое наблюдение (read-only). Офсеты получены из runtime и действительны
> **только** при `build_key` ниже (plan.md §6.3).

## Questions to answer

Из plan.md §11.1, строка 5:

1. Какой класс pawn или character используется?
2. Что здесь C++-база, а что Blueprint-класс?
3. Какие компоненты входят в состав?

## Data to collect

Иерархия класса, список компонентов, ключевые свойства.

## Method

Разрешение владеемого pawn через reflection (`AController::Pawn` и
`APlayerController::AcknowledgedPawn`, оба обязаны согласиться); обход цепочки `SuperStruct`;
перечисление компонентов обходом `GUObjectArray` с проверкой `Outer == pawn` — потому что
`ULevel::Actors` **не отражён** и спросить уровень нельзя; разрешение свойств по имени.

## Findings (evidence level, confidence, build_key)

**build_key:** `sha256:bace50f7185d095d03ee18a2fea701c747810c31f2037bda21ea57a81f013331`
**Evidence level:** OBSERVED · **Confidence:** 0.85

### 1. Класс и что здесь Blueprint, а что C++

```
BP_SGKMasterCharacter_C
  /Game/SurvivalGameKitV2/Blueprints/Characters/BP_SGKMasterCharacter.BP_SGKMasterCharacter_C
    → /Script/Engine.Character      ← C++, движок
      → /Script/Engine.Pawn         ← C++, движок
        → /Script/Engine.Actor      ← C++, движок
          → /Script/CoreUObject.Object
```

**Blueprint — только верхний класс.** Собственного C++-класса персонажа у MISERY нет: цепочка
уходит прямо в движковый `ACharacter`. (Нативный модуль `/Script/MISERY` в игре существует — см.
`gameinstance.md` — но в этой цепочке его нет.)

Отличать игрока от ИИ по классу нельзя: в загруженной сессии живы десятки `APawn`-производных, и
почти все — ИИ. Единственный корректный признак — тот pawn, которым контроллер **владеет**, то
есть согласие `AController::Pawn` и `APlayerController::AcknowledgedPawn`.

### 2. Ключевые свойства (требуется ≥3 подтверждённых офсета; приведено 9)

| Свойство | Офсет | Тип | Объявлено на | Значение |
|---|---|---|---|---|
| `Mesh` | `+792` | `FObjectProperty` | `Character` | `CharacterMesh0` |
| `CharacterMovement` | `+800` | `FObjectProperty` | `Character` | `CharMoveComp` |
| `CapsuleComponent` | `+808` | `FObjectProperty` | `Character` | `CollisionCylinder` |
| `RootComponent` | `+416` | `FObjectProperty` | `Actor` | `CollisionCylinder` |
| `Instigator` | `+392` | `FObjectProperty` | `Actor` | сам персонаж |
| `Controller` | `+712` | `FObjectProperty` | `Pawn` | контроллер (null после смерти) |
| `PlayerState` | `+688` | `FObjectProperty` | `Pawn` | — |
| `PreviousController` | `+720` | `FObjectProperty` | `Pawn` | — |
| `bIsCrouched` | `+1116` | `FBoolProperty` | `Character` | — |

`RootComponent` и `CapsuleComponent` указывают на **один и тот же** компонент — это ожидаемо для
`ACharacter` и служит перекрёстной проверкой корректности чтения.

### 3. Компоненты — полный список (48)

`Outer == pawn`, не-CDO. Сгруппировано по назначению; список полный.

**Меши и вид (9):** `CharacterMesh0` (SkeletalMesh), `FirstPersonArms`, `FirstPersonBody`,
`InvisibleTPBody`, `TP_Mesh`, `SK_Skeleton` (SkeletalMesh), `FP_Compass`, `TP_Compass`,
`NeedleFP`, `NeedleTP`, `SM_grabbed_GhoulFP`, `SM_grabbed_GhoulTP` (StaticMesh)

**Камера и движение (4):** `FirstPersonCamera`, `ThirdPersonCamera` (CameraComponent),
`CameraBoom` (SpringArm), `CharMoveComp` (CharacterMovement)

**Столкновение (1):** `CollisionCylinder` (Capsule) — он же `RootComponent`

**Игровые компоненты игры (5):** `BP_CharacterComponent_C`, `BP_ClimbLadderComponent_C`,
`BP_SittingComponent_C`, `C_FS_ComponentPlayer_C`, `NODE_AddBP_EquipmentInventory-0`
(`BP_EquipmentInventory_C`)

**Timeline (9):** `CameraCrouch`, `FovTimeline`, `LeftFPLean`, `RightFPLean`, `LeftTPLean`,
`RightTPLean`, и шесть безымянных `Timeline`

**Звук (8):** семь `AudioComponent` + `Audio_Weather`

**Эффекты (2):** `FX_Rain`, `FX_Snow` (Niagara)

**Прочее (4):** `ChatWidget` (Widget), `ChildActor`, `Indicator Point`, `ThrowPoint` (Scene)

Инвентарь игрока в этот список **не входит**: `BP_PlayerInventory` принадлежит **контроллеру**, а
не персонажу. Ранняя версия инструмента искала его на pawn и была неправа; это записано, потому
что ошибка правдоподобна и повторима.

### 4. Время жизни — половина измерена, половина нет

**Смерть наблюдалась** (персонаж умер от голода, пока сессия простаивала — ровно тот случай, что
описан в README раннера). Измерено в этом состоянии:

- `AController::Pawn` → null, `APawn::Controller` → null;
- `APlayerController::AcknowledgedPawn` некоторое время ещё указывает на труп, затем тоже null;
- живых `BP_SGKMasterCharacter_C` — 0;
- **`PlayerController`, `PlayerState`, `PlayerCameraManager` и `BP_PlayerInventory` — те же
  объекты по тем же адресам, что и до смерти.**

Значит: **контроллер переживает смерть, персонаж — нет.** Это наблюдение, а не вывод.

**Возрождение не наблюдалось.** Раннер намеренно fail-closed на экране смерти и не нажимает
«ВОЗРОДИТЬСЯ В БУНКЕРЕ»: это игровое решение, меняющее сейв, а не шаг навигации.

Отдельно: обоснование «возрождение идёт по движковому пути, потому что `BP_SGKGameMode_C` не
переопределяет `RestartPlayer`» **несостоятельно** и здесь не используется. Независимый разбор
показал, что `RestartPlayer` и `RestartPlayerAtPlayerStart` не помечены `FUNC_BlueprintEvent`,
поэтому Blueprint и не мог бы их переопределить — их отсутствие не несёт доказательной нагрузки.
Что действительно поддерживает вывод — отсутствие в цепочке собственного C++-класса. При этом
`BP_SGKGameMode_C` **переопределяет** `SpawnDefaultPawnAtTransform`, то есть спавн pawn игра взяла
на себя, а семейство `ServerRespawnPlayer` / `FindSpawnPoint` объявлено на `BP_PlayerInventory_C`.
Иначе говоря, возрождение в MISERY, по-видимому, вообще не проходит через `AGameModeBase::RestartPlayer`.

## What is "enough" (definition of done)

Критерий подсистемы: полный список компонентов **плюс подтверждённые офсеты не менее трёх
свойств** — выполнено: 48 компонентов перечислены полностью, подтверждено девять офсетов.

Ограничение plan.md §6.3 соблюдено: все офсеты получены из runtime и привязаны к `build_key`.

## Implications for future SDK

- «Персонаж игрока» обязан определяться через владение контроллером, а не по классу: ИИ
  использует те же классы.
- Ссылку на pawn держать нельзя — он уничтожается при смерти и при смене карты. Контроллер живёт
  дольше, инвентарь живёт с контроллером.
- Компоненты перечисляются только обходом по `Outer`: `ULevel::Actors` не отражён, и это
  свойство сборки, а не временное неудобство.

## Open unknowns

- **Возрождение не наблюдалось** — единственный непокрытый переход M4.
- Здоровье/сытость и прочие игровые показатели не искались: это M6 (`components.md`).
- Что делают `ClearInventoryOnDeath` и `DeletePlayerSaveOnDeath` (объявлены на
  `BP_PlayerInventory_C`) — относится к M6, но означает, что **якорь инвентаря** — самая вероятная
  точка риска при возрождении, а не контроллер.
