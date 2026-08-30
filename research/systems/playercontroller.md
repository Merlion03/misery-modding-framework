# PlayerController

> Заполнен в **M4**. Живое наблюдение (read-only). Каждый офсет ниже получен из живого
> `FProperty` при `build_key` ниже и является **подтверждением**, а не интерфейсом.

## Questions to answer

Из plan.md §11.1, строка 4:

1. Какой класс используется как игровой PlayerController?
2. Какие у него ключевые свойства и функции?
3. Как устроен input-стек?

## Data to collect

Класс, иерархия, список `UFunction`, input mapping contexts.

## Method

Перечисление живых экземпляров по классу-предку `/Script/Engine.PlayerController`; обход цепочки
`SuperStruct`; перечисление `UFunction` через `cr01c3_recon.class_functions`; разрешение свойств по
имени через живую reflection; перечисление живых `InputMappingContext` и подсистем ввода.

## Findings (evidence level, confidence, build_key)

**build_key:** `sha256:bace50f7185d095d03ee18a2fea701c747810c31f2037bda21ea57a81f013331`
**Evidence level:** OBSERVED · **Confidence:** 0.85

### 1. Класс и иерархия

Живых экземпляров — **ровно 1** в геймплее. Считаются только не-garbage объекты: `DestroyActor` лишь помечает, и уничтоженный контроллер остаётся в `GUObjectArray` до следующей сборки мусора.

```
BP_SGKController_C
  /Game/SurvivalGameKitV2/Blueprints/Characters/BP_SGKController.BP_SGKController_C
    → /Script/Engine.PlayerController
      → /Script/Engine.Controller
        → /Script/Engine.Actor
          → /Script/CoreUObject.Object
```

Собственного C++-класса между Blueprint и движковым `APlayerController` нет.

В меню контроллер **другой** — `BP_SGKMenuController_C`; при загрузке сейва он уничтожается и
создаётся `BP_SGKController_C`. Это измерено по смене адреса внутри одного процесса, а не выведено.

### 2. Ключевые свойства (≥5 требуется; приведено 8)

| Свойство | Офсет | Тип | Объявлено на | Значение в геймплее |
|---|---|---|---|---|
| `Player` | `+816` | `FObjectProperty` | `PlayerController` | `LocalPlayer` |
| `AcknowledgedPawn` | `+824` | `FObjectProperty` | `PlayerController` | `BP_SGKMasterCharacter_C` |
| `Pawn` | `+720` | `FObjectProperty` | `Controller` | `BP_SGKMasterCharacter_C` |
| `PlayerState` | `+664` | `FObjectProperty` | `Controller` | `PlayerState` |
| `PlayerCameraManager` | `+840` | `FObjectProperty` | `PlayerController` | `PlayerCameraManager` |
| `MyHUD` | `+832` | `FObjectProperty` | `PlayerController` | `HUD` |
| `bIsLocalPlayerController` | `+1724` | `FBoolProperty` | `PlayerController` | — |
| `NetConnection` | `+1304` | `FObjectProperty` | `PlayerController` | **null** (standalone) |
| `BP_PlayerInventory` | `+2176` | `FObjectProperty` | `BP_SGKController_C` | `BP_PlayerInventory` |

Последняя строка — собственное свойство игры: контроллер сам объявляет ссылку на компонент
инвентаря. Это используется как **второй независимый маршрут** к якорю инвентаря: первый ищет
компонент по `Outer == контроллер`, второй спрашивает контроллер, какое из его отражённых свойств
на него указывает. Один маршрут не может подтвердить сам себя.

### 3. Функции

`BP_SGKController_C` объявляет **51** `UFunction`. Среди них — сетевые обёртки
(`ClientInitialize`, `ClientPossess`, `ClientInGameLoad`, `Client_KickPlayer`), меню-колёса
(`InitWheelMenus`, `IsWheelInputAllowed`, `InterruptWheelInput`) и именованные входные обработчики
(`Misery Game Input`, `Misery Inventory Input`, `Misery UI Input`, `Misery In Game Menu Input`,
`MiseryDeathScreenInput`).

**`ClientRespawn` и `MiseryDeathScreenInput` объявлены на контроллере** — то есть путь возрождения
проходит через него, а не через `AGameModeBase::RestartPlayer` (см. «Open unknowns» и
`playercharacter.md`).

### 4. Input-стек — Enhanced Input

- Живых `EnhancedInputLocalPlayerSubsystem` — **1**, `Outer` — `LocalPlayer` (не контроллер).
- Живых `InputMappingContext` — **5**:
  - `/Game/SurvivalGameKitV2/Blueprints/Controls/SGKCharacterInputs`
  - `/Game/SurvivalGameKitV2/Blueprints/Controls/SGKCharacterInputs_Backup`
  - `/Game/SurvivalGameKitV2/Blueprints/Controls/Inventory/SGKCharacterInventoryInputs`
  - `/Game/SmartAI/Blueprints/Controls/SmartAICharacterInputs`
  - `/Game/Blueprints/WheelMenu/IMC_WheelMenu`
- В списке функций контроллера присутствуют обработчики вида
  `InpActEvt_<Action>_K2Node_EnhancedInputActionEvent`, что подтверждает Enhanced Input, а не
  legacy input bindings.

### 5. Способ доступа — структурное отношение, а не офсет

Требование plan.md §18.2 выполняется так: контроллер получают **не** по адресу и **не** по
офсету, а по согласию двух отношений — перечисление живых `APlayerController` (счёт является
ответом: 0 или 2 — это расхождение, а не молчание) и обратное ребро
`UPlayer::PlayerController`. Офсеты в таблице выше — подтверждение при данном `build_key`, и
переносить их между сборками нельзя.

## What is "enough" (definition of done)

Критерий подсистемы: найден локальный PlayerController и прочитано **не менее пяти** осмысленных
свойств — выполнено: найден в обоих запусках, прочитано девять свойств.

Требование M4 «способ доступа описан как структурное отношение» — выполнено (§5).

## Implications for future SDK

- Ввод, HUD и камера достижимы от контроллера, но сам контроллер **пересоздаётся** при смене
  карты — держать на него ссылку нельзя.
- Собственное свойство `BP_PlayerInventory` показывает, что игровые классы объявляют свои
  компоненты как отражённые свойства: у фреймворка есть законный способ находить их по имени, не
  прибегая к офсетам.
- Enhanced Input привязан к `LocalPlayer`, не к контроллеру, — модам, добавляющим ввод, работать
  нужно с подсистемой локального игрока.

## Open unknowns

- Полная семантика 51 функции не разбиралась; здесь перечислены только те, что относятся к M4.
- Путь возрождения: `ClientRespawn` на контроллере и (по независимому обзору) семейство
  `ServerRespawnPlayer` / `FindSpawnPoint` на `BP_PlayerInventory_C`. Разбор — в M6
  (`inventory.md`), сам факт зафиксирован здесь, чтобы не выводиться заново.
- Поведение в co-op и роль `NetConnection` — не наблюдалось.
