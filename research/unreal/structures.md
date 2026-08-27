# Восстановленные layout-ы структур движка

**Build_key для ВСЕХ офсетов ниже, если не оговорено иное:**
`sha256:bace50f7185d095d03ee18a2fea701c747810c31f2037bda21ea57a81f013331`
(`misery-24953925-ue5.4.4-bace50f7185d`, установка на момент M3). Ни один офсет в этом файле не
переносится молча на другую сборку — при смене `build_key` каждый требует повторного
подтверждения (plan.md §16.1).

**Дисциплина этого файла (plan.md §6.3, дословно по смыслу):** офсет фиксируется как `OBSERVED`
только при подтверждении из runtime-дампа (ERI, `research/instruments/eri/eri.py`, возможности
I-02..I-06, PE-02) или live self-consistency проверки (IPP). Офсет, полученный только статическим
анализом (Ghidra/чтением исходника UE 5.4.4 CL 35576357), остаётся `HYPOTHESIS`, даже если он
впоследствии совпал с независимой live-проверкой landmark-полей вокруг него — совпадение соседних
полей не подтверждает офсет, которого сама проверка не касалась напрямую.

Источник каждого офсета — константа в `research/instruments/eri/eri.py` (грепается по имени) и/или
запись в `research/RESEARCH_LOG.md`, указана в столбце «Источник».

## UObjectBase (`UObjectBase.h`)

Итоговый размер: **0x28 байт**. Подтверждено вживую I-04 (пятикратное соответствие с offline RF-01
для `/Script/MISERY`, `LOG-0053`) и переиспользуется без изменений в I-05/I-06/PE-02/P-02.

| Офсет | Поле | Тип | Статус | Источник |
|---|---|---|---|---|
| `0x00` | vtable ptr | — | OBSERVED | универсально для любого полиморфного C++-объекта; PE-02 читает и разыменовывает |
| `0x08` | `ObjectFlags` | `EObjectFlags` (4 байта) | HYPOTHESIS | `UObjectBase.h`, ERI не декодирует это поле напрямую |
| `0x0C` | `InternalIndex` | `int32` | HYPOTHESIS | `UObjectBase.h`, не декодируется ERI напрямую |
| `0x10` | `ClassPrivate` | `UClass*` | OBSERVED | `eri.py DEFAULT_CLASS_PRIVATE_OFFSET`; I-04 (5/5 `/Script/MISERY`), переиспользуется I-05/I-06 |
| `0x18` | `NamePrivate` | `FName` (8 байт) | OBSERVED | `eri.py DEFAULT_NAME_PRIVATE_OFFSET`; I-04 |
| `0x20` | `OuterPrivate` | `UObject*` | OBSERVED | `eri.py DEFAULT_OUTER_PRIVATE_OFFSET`; I-04, `resolve_object_path()` |

## UField (`Class.h`, `: public UObject`)

| Офсет | Поле | Тип | Статус | Источник |
|---|---|---|---|---|
| `0x28` | `Next` | `UField*` | OBSERVED | `eri.py DEFAULT_UFIELD_NEXT_OFFSET`; I-05 `walk_children_chain()`, live-подтверждено на 247/247 функций |

## FStructBaseChain (приватный второй базовый класс `UStruct` в этой сборке)

**Не отдельный C++-объект в GUObjectArray** — приватная база `UStruct`, добавляющая 2 поля между
`UField::Next` и `UStruct::SuperStruct`. Существование этой базы в ЭТОЙ сборке — не предположение:
`UE_EDITOR` разрешается в `0` для non-editor/Shipping таргета (`Build.h`), что делает
`USTRUCT_FAST_ISCHILDOF_IMPL == USTRUCT_ISCHILDOF_STRUCTARRAY` (`ObjectMacros.h:39-46`) и включает
эту базу (`Class.h:382-385`). Найдена и подтверждена дважды независимо, 2026-08-27 (для нужд P-02,
`LOG-0060`, коммит `00209bf`), обоими выводами получен один и тот же результат.

| Офсет | Поле | Тип | Статус | Источник |
|---|---|---|---|---|
| `0x30` | `StructBaseChainArray` | `FStructBaseChain**` | HYPOTHESIS | `Class.h:368`, не подтверждено прямым live-чтением ЭТОГО конкретного поля |
| `0x38` | `NumStructBasesInChainMinusOne` | `int32` | HYPOTHESIS | `Class.h:369`, аналогично |

**Почему база в целом — не HYPOTHESIS, а фактически подтверждена косвенно:** два независимых
source-вывода (см. ниже, `UStruct`) предсказали `Children`/`ChildProperties` на `+0x48`/`+0x50`
ТОЛЬКО при условии, что эта база существует и занимает ровно 16 байт (`0x30`-`0x40`); оба офсета
уже подтверждены живым чтением (см. `UStruct` ниже) — совпадение с точностью до байта на двух
независимых landmark-полях после этой базы — сильное косвенное подтверждение её размера и
положения, но не замена прямого чтения `StructBaseChainArray`/`NumStructBasesInChainMinusOne` как
таковых.

## UStruct (`Class.h`, `: public UField[, private FStructBaseChain]`)

Итоговый размер: **0xB0 байт** — подтверждено живым чтением (первое поле `UFunction`,
`FunctionFlags`, найдено ровно на `+0xB0` от базы объекта на 247/247 живых функций).

| Офсет | Поле | Тип | Статус | Источник |
|---|---|---|---|---|
| `0x40` | `SuperStruct` | `UStruct*` | HYPOTHESIS | `Class.h:394`, не декодируется ERI напрямую |
| `0x48` | `Children` | `UField*` (голова связного списка) | OBSERVED | `eri.py USTRUCT_CHILDREN_OFFSET`; I-05 `walk_children_chain()`, 247/247 живых функций |
| `0x50` | `ChildProperties` | `FField*` (голова связного списка) | OBSERVED | `eri.py USTRUCT_CHILD_PROPERTIES_OFFSET`; I-06, 234 живых свойства у 35 классов. **Найден и исправлен реальный офсетный баг** (изначально предполагалось `+0x40`) живым self-check'ом, `LOG-0052` |
| `0x58` | `PropertiesSize` | `int32` | HYPOTHESIS | `Class.h:403`, не декодируется ERI напрямую |
| `0x5C` | `MinAlignment` | `int32` | HYPOTHESIS | `Class.h:405` |
| `0x60`-`0xA7` | `Script`/`PropertyLink`/`RefLink`/`DestructorLink`/`PostConstructLink`/`ScriptAndPropertyObjectReferences`/`UnresolvedScriptProperties`/`UnversionedGameSchema` | разное | HYPOTHESIS | `Class.h:408-434`, ни одно не декодируется ERI напрямую |

## UClass (`Class.h`, `: public UStruct`)

| Офсет | Поле | Тип | Статус | Источник |
|---|---|---|---|---|
| `0xB0`-`0x10F` | `ClassConstructor`..`NetFields` | разное | HYPOTHESIS | `Class.h:2749-2801`, source-вывод этой сессии (двумя независимыми агентами, см. `LOG-0060` metod), не декодируется ERI напрямую |
| `0x110` | `ClassDefaultObject` | `UObject*` (CDO) | **OBSERVED** | Source-вывод (двумя независимыми агентами) + **живая self-consistency проверка** 2026-08-27 (`P-02`, `ipp_controller.py::resolve_target()`): кандидат по `UClass+0x110` прочитан у живого `MiseryBlueprintFunctionLibrary`, его собственное поле `ClassPrivate` (`+0x10`) указывает точно назад на этот же `UClass` — единственный офсет в этом файле, подтверждённый живым чтением ПОСЛЕ первоначального вывода из исходника, а не одновременно с ним. `LOG-0060`, `research/instrument-runs/2026-08-27T204010Z/` |

## FField (`Field.h`, базовый класс для всех `FProperty`)

| Офсет | Поле | Тип | Статус | Источник |
|---|---|---|---|---|
| `0x08` | `ClassPrivate` | `FFieldClass*` | OBSERVED | `eri.py FFIELD_CLASS_PRIVATE_OFFSET` (`Field.h:452`); I-06 |
| `0x10` | `Owner` | `FFieldVariant` | OBSERVED | `eri.py FFIELD_OWNER_OFFSET` (`Field.h:472`); I-06 |
| `0x18` | `Next` | `FField*` | OBSERVED | `eri.py FFIELD_NEXT_OFFSET` (`Field.h:475`); I-06, связный список `ChildProperties` |
| `0x20` | `NamePrivate` | `FName` | OBSERVED | `eri.py FFIELD_NAME_PRIVATE_OFFSET` (`Field.h:478`); I-06 |

## FFieldClass (`Field.h`, метакласс `FField`)

| Офсет | Поле | Тип | Статус | Источник |
|---|---|---|---|---|
| `0x00` | `Name` | `FName` (**без ведущей `F`** — `Field.cpp:46-61` обрезает её в конструкторе) | OBSERVED | `eri.py FFIELDCLASS_NAME_OFFSET`; I-06. **Найден и исправлен реальный баг** (ожидалось имя с `F`), `LOG-0052` |
| `0x20` | `SuperClass` | `FFieldClass*` | OBSERVED | `eri.py FFIELDCLASS_SUPERCLASS_OFFSET`; I-06, обход цепочки суперклассов |

## FProperty (`UnrealType.h`, база всех decoded properties)

| Офсет | Поле | Тип | Статус | Источник |
|---|---|---|---|---|
| `0x30` | `ArrayDim` | `int32` | OBSERVED | `eri.py FPROPERTY_ARRAY_DIM_OFFSET`; I-06, 234 свойства |
| `0x34` | `ElementSize` | `int32` | OBSERVED | `eri.py FPROPERTY_ELEMENT_SIZE_OFFSET`; I-06 |
| `0x38` | `PropertyFlags` | `EPropertyFlags` (`uint64`) | OBSERVED | `eri.py FPROPERTY_PROPERTY_FLAGS_OFFSET` (`ObjectMacros.h:395`); I-06, включая биты `CPF_ZeroConstructor`/`CPF_IsPlainOldData`/`CPF_NoDestructor`, использованные Phase 2 (`LOG-0057`) |
| `0x40` | `RepIndex` | `uint16` | OBSERVED | `eri.py FPROPERTY_REP_INDEX_OFFSET`; I-06 |
| `0x44` | `Offset_Internal` | `int32` | OBSERVED | `eri.py FPROPERTY_OFFSET_INTERNAL_OFFSET`; I-06 |
| `0x68` | `RepNotifyFunc` | `FName` | OBSERVED | `eri.py FPROPERTY_REP_NOTIFY_FUNC_OFFSET`; I-06 |

### Подклассы `FProperty` — поля, начинающиеся с `+0x70` (сразу после базового `FProperty`)

| Класс | Офсет | Поле | Статус | Источник |
|---|---|---|---|---|
| `FBoolProperty` | `0x70`/`0x71`/`0x72`/`0x73` | `FieldSize`/`ByteOffset`/`ByteMask`/`FieldMask` (все `uint8`) | OBSERVED | `eri.py FBOOLPROPERTY_*`; I-06 |
| `FObjectProperty`/`FClassProperty` (наследник) | `0x70` | `PropertyClass` (`UClass*`) | OBSERVED | `eri.py FOBJECTPROPERTY_PROPERTY_CLASS_OFFSET`; I-06 |
| `FClassProperty` | `0x78` | `MetaClass` (`UClass*`) | OBSERVED | `eri.py FCLASSPROPERTY_META_CLASS_OFFSET`; I-06 |
| `FStructProperty` | `0x70` | `Struct` (`UScriptStruct*`) | OBSERVED | `eri.py FSTRUCTPROPERTY_STRUCT_OFFSET`; I-06 |
| `FEnumProperty` | `0x70`/`0x78` | `UnderlyingProp`/`Enum` | OBSERVED | `eri.py FENUMPROPERTY_*`; I-06 |
| `FArrayProperty` | `0x70`/`0x78` | `ArrayFlags`(`uint8`)/`Inner` | OBSERVED | `eri.py FARRAYPROPERTY_*`; I-06 |
| `FSetProperty` | `0x70` | `ElementProp` | OBSERVED | `eri.py FSETPROPERTY_ELEMENT_PROP_OFFSET`; I-06 |
| `FMapProperty` | `0x70`/`0x78` | `KeyProp`/`ValueProp` | OBSERVED | `eri.py FMAPPROPERTY_*`; I-06 |

## UFunction (`Class.h`, `: public UStruct`)

| Офсет | Поле | Тип | Статус | Источник |
|---|---|---|---|---|
| `0xB0` | `FunctionFlags` | `EFunctionFlags` (`uint32`) | OBSERVED | `eri.py UFUNCTION_FUNCTION_FLAGS_OFFSET` (`Script.h:130`, `Class.h:1797`); I-05, 247/247 функций |
| `0xB4` | `NumParms` | `uint8` | OBSERVED | `eri.py UFUNCTION_NUM_PARMS_OFFSET` (`Class.h:1802`); I-05. **Найден и исправлен реальный семантический баг** (Blueprint-локальные переменные ошибочно считались параметрами), `LOG-0054` |
| `0xB6` | `ParmsSize` | `uint16` (padding на `+0xB5`) | OBSERVED | `eri.py UFUNCTION_PARMS_SIZE_OFFSET` (`Class.h:1804`); I-05, дополнительно **живо перепроверено внутри `probe.cpp`** непосредственно перед единственным вызовом `ProcessEvent` (`P-02`, `LOG-0060`) |
| `0xB8` | `ReturnValueOffset` | `uint16` | OBSERVED | `eri.py UFUNCTION_RETURN_VALUE_OFFSET_OFFSET` (`Class.h:1806`); I-05 |

## FUObjectArray (`GUObjectArray`)

RVA (от базы образа): `0x07A78ED0` (`eri.py DEFAULT_GUOBJECTARRAY_RVA`) — кандидат RF-05, живо
подтверждён I-02.

| Офсет | Поле | Тип | Статус | Источник |
|---|---|---|---|---|
| `0x10` | `Objects` | `FUObjectItem**` | OBSERVED | `eri.py GUOBJECTARRAY_OFFSET_OBJECTS`; I-02 |
| `0x20` | `MaxElements` | `int32` | OBSERVED | `eri.py GUOBJECTARRAY_OFFSET_MAX_ELEMENTS`; I-02 |
| `0x24` | `NumElements` | `int32` | OBSERVED | `eri.py GUOBJECTARRAY_OFFSET_NUM_ELEMENTS`; I-02 |

`FUObjectItem` (элемент массива `Objects`): `0x00` = `UObjectBase* Object` (`eri.py
FUOBJECTITEM_OFFSET_OBJECT`), OBSERVED, I-02.

## FNamePool (`GNamePool` / `FNamePool`)

RVA: `0x079C2180` (`eri.py DEFAULT_NAMEPOOL_RVA`), инициализация проверяется по RVA
`0x07995E5E` (`eri.py DEFAULT_NAME_POOL_INITIALIZED_RVA`) — кандидат RF-06, живо подтверждён I-03.

| Офсет | Поле | Тип | Статус | Источник |
|---|---|---|---|---|
| `0x10` | `Blocks` | массив блоков имён | OBSERVED | `eri.py NAMEPOOL_OFFSET_BLOCKS`; I-03, `decode_fname_entry_id()` |

## ProcessEvent — vtable slot, не офсет структуры

Слот **77** таблицы виртуальных функций `UObject` (считая от `0`) — live-подтверждён ДВУМЯ
независимыми методами (130 000-объектное сканирование живых vtable + перекрёстная сверка с
декомпиляцией `ScriptCore.cpp:1971`/`Actor.cpp:1064`), `eri.py DEFAULT_PROCESSEVENT_VTABLE_SLOT`,
`LOG-0056` (OBSERVED, 0.90). Зависит от `UE_WITH_IRIS=1` для этой сборки — подтверждено тем же
измерением (при `UE_WITH_IRIS=0` слот был бы 76). Реально исполнен через этот слот один раз, живьём,
`P-02`/`LOG-0060`.

## Что сюда сознательно НЕ включено

`UWorld`, `UGameInstance`, `ULocalPlayer`, `APlayerController`, `APawn`/`ACharacter`, `UEngine` —
названы в plan.md §6.1 как целевые сущности этого файла, но M4 (`ERI I-07..I-10`, world/player
identification) ещё не начат в этой сессии. Добавляются сюда по мере готовности M4, не задним
числом сейчас.
