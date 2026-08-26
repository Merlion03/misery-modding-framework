# Собственный cook UE 5.4.4 как оракул сравнения: CK-01, CK-04, AssetRegistry, `.usmap`

Дата прогона: 2026-08-23. Движок: `D:\Program Files\UE_5.4`, UE **5.4.4**, changelist **35576357**,
ветка `++UE5+Release-5.4`, installed build — тот же changelist, из которого собрана игра
(`research/unreal/engine-version.json`, 0.93).
Артефакты-доказательства: `research/evidence/CK-COOK/`.
Инструменты, добавленные этим прогоном: `tools/content/package_summary.py`,
`tools/content/iostore_chunks.py`.

---

## 0. Граница research / production — это раздел, а не формальность

Всё, что описано ниже, — **research-возможность на машине автора**, и ничего из этого не является
и не станет технической зависимостью фреймворка.

| Что | Research (этот прогон) | Production (публичный фреймворк) |
|---|---|---|
| Установленный Unreal Engine 5.4.4 | нужен | **не нужен** |
| Прогон cook / staging | нужен | **не нужен** |
| Ключ шифрования контейнера | **не использовался и не нужен** | не нужен и не поставляется |
| Распакованные контейнеры игры | **не создавались** | не нужны, и пользователь ничего не распаковывает |
| Оригинальные ассеты игры | **не читались** (кроме plaintext-метаданных TOC) | не поставляются |
| Cooked-ассеты в репозитории | **нет ни одного** | нет |

Что попало в репозиторий: JSON-структуры сравнения, счётчики, размеры, смещения, хэши, отфильтрованные
логи. Что не попало: ни одного cooked-пакета, ни одного байта payload игрового контейнера, ни одного
пути внутри профиля пользователя (C-13).

Фреймворк должен работать против обычной установки MISERY из Steam. Приготовленный нами эталонный
cook — это **измерительный прибор**, а не деталь продукта: он существует, чтобы сравнить структуру
того, что производит движок, со структурой того, что мы можем прочитать в установке, — и чтобы
ответы CK-01 и CK-04 были измерением, а не ожиданием.

---

## 1. Что запускалось, что записано и куда — аудит следа

Reference-проект: `D:\UEScratch\CookRef` (Blueprint-only, `.uproject` из двух плагинов —
`PythonScriptPlugin`, `EditorScriptingUtilities`). DDC вынесен на `D:` через переменные окружения
`UE-LocalDataCachePath=D:\UEScratch\DDC` и `UE-SharedDataCachePath=None`; на `C:` свободно ~6 ГиБ,
и ни один байт вывода туда не пошёл. Итого на `D:\UEScratch` — 3,1 ГиБ (проект, DDC, пять вариантов
cook, три staged-сборки, логи).

| Запуск | Команда (сокращённо) | Лог | Что записала |
|---|---|---|---|
| assets | `UnrealEditor-Cmd -run=pythonscript -script="make_assets.py base"` | `make_assets.log` | 4 ассета в `D:\UEScratch\CookRef\Content\Ref` |
| cook A | `-run=Cook -TargetPlatform=Windows` | `cookA.log` | 382 пакета, `Saved/A_Cooked` |
| stage A | `RunUAT BuildCookRun -skipcook -stage -pak -iostore` | `stageA.log` | `Saved/A_Staged` |
| cook B | то же, что A, с ini-gate `False` | `cookB.log` | **упал**: `Assertion failed: CanUseUnversionedPropertySerialization()` |
| cook U | `-run=Cook -TargetPlatform=Windows -unversioned` | `cookU.log` | `Saved/U_Cooked` |
| stage U | `RunUAT ... -stage -pak -iostore` | `stageU.log` | `Saved/U_Staged` |
| stage U-nc | то же `+ -forceuncompressed` | `stageU_nocompress.log` | `Saved/StagedBuilds` |
| cook X | `-unversioned` + ini-gate `False` | `cookX.log` | `Saved/X_Cooked` |
| grow | `-run=pythonscript -script="make_assets.py parentgrown"` | `make_assets_grown.log` | +1 компонент в `BP_RefParent` |
| cook G | `-unversioned`, родитель вырос | `cookG.log` | `Saved/G_Cooked` |
| uat cook | `RunUAT BuildCookRun -cook` (без своих флагов) | `uat_cook_default.log` | наблюдение флагов по умолчанию |

**Записи вне `D:\UEScratch`, которые сделала сама тулчейн движка** (перечисляю, потому что след должен
быть проверяемым): 18 файлов под `D:\Program Files\UE_5.4\Engine\Programs\` —
`AutomationTool\Saved\ResponseFiles\PakList*.txt`, `UnrealPak\Saved\Logs\*.log`,
`UnrealPak\Saved\Config\CrashReportClient\*`, плюс `__pycache__` встроенного Python. Это штатное
поведение `RunUAT` и `UnrealPak`, и это внутри установки **движка**, не игры.
**В установке игры (`D:\Games\Steam\steamapps\common\MISERY`) не записано ничего**: игра в этом
прогоне открывалась только на чтение и только на уровне TOC-метаданных.

### 1.1 Почему ассеты сделаны компонентами, а не переменными Blueprint

`FBlueprintEditorUtils::AddMemberVariable` (`Kismet2/BlueprintEditorUtils.h:843`) не является
`UFUNCTION` и Python недоступна, а прямая запись `UBlueprint::NewVariables` через
`set_editor_property` отвергается: `PropertyAccessUtil` отвечает
`Property 'PinCategory' ... is protected and cannot be set`, потому что у `FEdGraphPinType` поля
объявлены простым `UPROPERTY()` без `EditAnywhere`/`BlueprintReadWrite`. C++-модуль тоже недоступен:
MSVC-тулчейна на машине нет (`C:\Program Files\Microsoft Visual Studio` отсутствует), а устанавливать
что-либо этому прогону запрещено.

Поэтому структурные свойства классов сделаны узлами SCS-компонентов через
`unreal.SubobjectDataSubsystem.add_new_subobject` (у `FAddNewSubobjectParams` поля
`BlueprintReadWrite`, `SubobjectDataSubsystem.h:33-48`): каждый узел даёт настоящий `FObjectProperty`
в generated-классе (`ParentMesh_GEN_VARIABLE`, `ParentLight_GEN_VARIABLE`,
`ChildBillboard_GEN_VARIABLE` видны в ассетах). Значения задавались переопределением
**унаследованных нативных** свойств в CDO (`InitialLifeSpan`, `CustomTimeDilation`,
`NetCullDistanceSquared`, `Tags`) и на экземплярах в уровне.

Что это ограничило: `UserDefinedStruct` создан фабрикой (`S_RefStruct`), но добавить в него
несколько членов headless нельзя — `FStructureEditorUtils` тоже не экспонирован. Поэтому «структура с
несколькими свойствами» в этом прогоне представлена нативными структурами (`FVector` в трансформах
компонентов, `TArray<FName> Tags`) и составом свойств самих generated-классов, а не пользовательской
структурой из нескольких членов. **Чем закрывается:** редактор с GUI или C++-модуль (тогда же
закрывается CK-07/CK-03 в более сильной форме).

---

## 2. Четыре варианта cook и настройка, различающая ровно один бит

Управляют режимом две разные вещи, и это первое, что пришлось выяснить эмпирически:

1. **ключ cook `-unversioned`** — выставляет `ECookInitializationFlags::Unversioned`, из которого
   `CookOnTheFlyServer.cpp:6255` собирает `SAVE_Unversioned` = `SAVE_Unversioned_Native |
   SAVE_Unversioned_Properties` (`ObjectMacros.h:102-107`);
2. **ini-разрешение** `[Core.System] CanUseUnversionedPropertySerialization` — литеральная строка
   ключа и секции читается движком дважды: `UnversionedPropertySerialization.cpp:803` (текущая
   платформа) и `:810` (произвольная `TargetIni`); резолюция **для целевой платформы**, кэширующая
   результат по платформе, — там же, `:826-856`. `SaveContext.h:473` вызывает эту резолюцию
   (`CanUseUnversionedPropertySerialization(SaveArgs.GetTargetPlatform())`), а `SaveContext.h:659`
   лишь проверяет уже вычисленный bool (`IsSaveUnversionedProperties`) — ни та, ни другая строка не
   читает ini напрямую, что стоит сказать явно: unversioned-свойства даются только если И флаг
   сохранения, И разрешение.

Отсюда: без `-unversioned` значение ini не имеет никакого эффекта — это подтверждено прогоном
(cook A и cook V с разными ini дали побайтово идентичные пакеты). А выключить ini глобально нельзя:
редактор сам падает на `check(CanUseUnversionedPropertySerialization())`
(`UnversionedPropertySerialization.cpp:884`), потому что `FDuplicateDataReader`/`Writer` всегда
включают unversioned-сериализацию (`DuplicateDataReader.cpp:30`, `DuplicateDataWriter.cpp:41`).
Изоляция сделана так: `Config/DefaultEngine.ini` = `False` (это видит **целевая** ini-иерархия
платформы `Windows`), а `Saved/Config/WindowsEditor/Engine.ini` = `True` (это видит **процесс
редактора**, у него другой каталог сгенерированного ini). Результат — три разных вывода из одного
проекта:

| Вариант | `-unversioned` | ini-gate | Заголовок пакета | Свойства |
|---|---|---|---|---|
| **V** | нет | (не важно) | versioned | versioned tagged |
| **X** | да | `False` | unversioned | versioned tagged |
| **U** | да | `True` | unversioned | **unversioned** |
| **G** | да | `True` | unversioned | unversioned, **родитель вырос на одно свойство** |

**U ↔ X различаются ровно одной настройкой.** **X ↔ V** различаются ровно ключом `-unversioned` при
одинаковых (versioned) свойствах — то есть два эффекта одного ключа разложены на два измерения.

Наблюдение о значении по умолчанию: `RunUAT BuildCookRun` без дополнительных ключей запустил
`UnrealEditor-Cmd ... -run=Cook -TargetPlatform=Windows -unversioned ...` (лог
`uat_cook_default.log`); в исходниках это `ProjectParams.cs:1962 UnversionedCookedContent = true` и
`CookCommand.Automation.cs:44`. А `Engine/Config/BaseEngine.ini:1439` в секции `[Core.System]`
содержит `CanUseUnversionedPropertySerialization=True`. То есть **стандартный путь упаковки на стоковом
движке 5.4.4 даёт unversioned-свойства без единой настройки со стороны проекта.**

---

## 3. CK-01 — что структурно отличает unversioned-пакет от versioned

### 3.1 На уровне пакета: шесть независимых признаков

Субъект — `/Game/Ref/BP_RefChild`: Blueprint, родитель которого — другой Blueprint, с
переопределением четырёх унаследованных свойств. Все числа — из
`research/evidence/CK-COOK/structural-comparison.json`.

| Признак | U (unversioned) | X (versioned) | V (versioned + versioned header) |
|---|---|---|---|
| `PackageFlags` | `0x80002200` | `0x80000200` | `0x80000200` |
| декодировано | `PKG_Cooked`, **`PKG_UnversionedProperties`**, `PKG_FilterEditorOnly` | `PKG_Cooked`, `PKG_FilterEditorOnly` | то же |
| ширина записи export map | **96** байт | **112** байт | 112 байт |
| span export map / `ExportCount` | 768 / 8 | 896 / 8 | 896 / 8 |
| `NameCount` | **36** | **54** | 54 |
| форма payload экспорта | фрагменты `FUnversionedHeader` | цепочка `FPropertyTag` | цепочка `FPropertyTag` |
| `.uexp` (данные свойств) | **379** байт | **956** байт | 956 байт |
| `.uasset` (заголовок) | 2867 | 3430 | 3610 |
| версии `ue3/ue4/ue5` | `0/0/0` | `0/0/0` | `864/522/1012` |
| custom versions | 0 | 0 | **9** |

Три вещи здесь стоит назвать прямо.

**Ширина записи export map — это признак в заголовке, а не в payload.**
`ObjectResource.cpp:208-212`: `ScriptSerializationStartOffset` и `ScriptSerializationEndOffset`
(два `int64`) пишутся **только если архив НЕ использует unversioned-сериализацию свойств**. 96 против
112 байт на запись. Это измерено независимо от флага: `(DependsOffset − ExportOffset) / ExportCount`
не опирается на `PKG_UnversionedProperties` вообще, и совпало с шириной, которую флаг предсказывает,
во всех четырёх вариантах. (В первой версии инструмента эта проверка была замкнута на сам флаг —
дефект исправлен в причине, а не в формулировке: см. `package_summary.py`, «The stride check has to be
INDEPENDENT of the flag».)

**Имена свойств физически исчезают из name map.** В versioned-варианте в name map ребёнка появляются
18 имён, которых нет в unversioned: `CustomTimeDilation`, `InitialLifeSpan`, `NetCullDistanceSquared`,
`Tags`, `ArrayProperty`, `FloatProperty`, `NameProperty`, `StructProperty`, `ComponentClass`,
`ComponentTemplate`, `Guid`, `VariableGuid`, `AllNodes`, `RootNodes`, `DefaultSceneRootNode`,
`InternalVariableName`, `ParentComponentOrVariableName`, `ParentComponentOwnerClassName`. В
unversioned-варианте нет ни одного имени, которого нет в versioned.

**Различие «versioned header» и «versioned properties» — это два разных различия.** X↔V меняет только
поля версий и список из 9 custom versions (`3610 − 3430 = 180 = 9 × 20` байт — GUID плюс `int32` на
запись), не трогая ни `.uexp` (956 в обоих), ни ширину export map (112), ни name map (54).

Тот же паттерн на остальных трёх пакетах (U → V): `BP_RefParent` `.uexp` 538 → 1201, `RefMap`
`.uexp` 917 → 2586, `S_RefStruct` `.uexp` 110 → 192.

### 3.2 На уровне контейнера: почти ничего

| Признак | ours U (сжатый) | ours V (сжатый) | ours U (`-forceuncompressed`) |
|---|---|---|---|
| `.utoc` | 100 534 | 100 546 | 100 502 |
| `.ucas` | 27 444 368 | 27 770 000 | 114 613 392 |
| chunk'ов | 886 | 886 | 886 |
| блоков | 2485 | **2486** | 2485 |
| `ContainerFlags` | `0x09` Compressed\|Indexed | `0x09` | `0x08` Indexed |
| directory index | 20 036 | 20 036 | 20 036 |
| сумма длин chunk'ов | 114 024 283 | 114 827 452 | 114 024 283 |
| `ExportBundleData`, байт | 100 498 755 | 101 301 924 | 100 498 755 |

Разница между U и V на уровне контейнера — это **+803 169 байт (+0,80 %) в сумме
`ExportBundleData`, +1 блок и +12 байт в `.utoc`**. Ни один флаг, ни один тип chunk'а, ни одно поле
заголовка TOC, ни размер directory index не меняются. Причина понятна: контейнер даже крошечного
проекта на 88 % состоит из движковых ассетов, у которых основной вес — не данные свойств.

### 3.3 Сравнение с тем, что читается у игры

Читаются, без всякой расшифровки, **plaintext-массивы TOC**: chunk id, offset/length, блоки сжатия,
таблица методов, chunk metas. Шифруется в UE 5.4 IoStore ровно одна секция — directory index.

| Признак | MISERY-Windows | ours (U, uncompressed) | Совпадает? |
|---|---|---|---|
| версия TOC | 6 | 6 | да |
| `TocHeaderSize` | 144 | 144 | да |
| размер блока | 65 536 | 65 536 | да |
| `ContainerFlags` | `0x0a` Encrypted\|Indexed | `0x08` Indexed | **нет: у игры добавлен Encrypted** |
| таблица методов сжатия | 0 записей | 0 записей | да |
| method index у всех блоков | 0 | 0 | да (**оба не сжаты**) |
| chunk'ов | 19 510 | 886 | по типам — да, см. ниже |
| блоков | 79 914 | 2485 | модель совпала в обоих |
| `Σ ceil(len/65536) == blocks` | **да** (79 914) | **да** (2485) | да |
| `Σ uncompressed == Σ len` | да | да | да |
| directory index | 844 960 байт, **не читается** | 20 036 байт, читается | структура та же, доступ разный |
| padding `.ucas` − `Σ len` | 15 457 815 | 589 109 | да, выравнивание |

Типы chunk'ов — здесь сравнение работает лучше всего, потому что тип лежит в 12-м байте
`FIoChunkId` (`IoChunkId.h:136-150`) и не зашифрован:

| `EIoChunkType` | MISERY-Windows | ours (U) | у нас сверено с directory index |
|---|---|---|---|
| `ExportBundleData` (1) | **12 933** (2 257 891 527 Б) | 375 | 375 файлов пакетов (373 `.uasset` + 2 `.umap`) |
| `BulkData` (2) | **5 513** (2 047 178 937 Б) | 26 | 26 файлов `.ubulk` |
| `ShaderCode` (9) | 1 061 | 482 | не именованы в индексе |
| `ShaderCodeLibrary` (8) | **2** | **2** | 2 файла `.ushaderbytecode` |
| `ContainerHeader` (6) | 1 (767 320 Б) | 1 | не файл |
| `ScriptObjects` (5) | 1 — в `global.utoc` | 1 — в `global.utoc` | не файл |
| прочие типы | нет | нет | — |

И `global`-контейнер — совпадение один-в-один:

| | game `global` | ours `global` |
|---|---|---|
| `.utoc` | 623 | 599 |
| `.ucas` | 2 269 168 | 2 129 440 |
| chunk'ов | 1, тип `ScriptObjects` | 1, тип `ScriptObjects` |
| длина chunk'а | 2 269 159 | 2 129 430 |
| `ContainerFlags` | `0x00` | `0x00` |
| `ContainerId` | `0xffffffffffffffff` | `0xffffffffffffffff` |
| блоков | 35 | 33 |

Наш cook пишет тот же самый артефакт ещё и отдельным файлом:
`Saved/.../Metadata/scriptobjects.bin` имеет размер **ровно 2 129 430** — длину chunk'а
`ScriptObjects` — и совпадает с началом `global.ucas` в первых 16 байтах (дальше идут разные данные,
потому что состав script-объектов разный). То есть формат plaintext-`global.ucas` игры теперь имеет
эталонный производитель на этой машине.

### 3.4 Вердикт по CK-01

**Сравнение НЕ решает CK-01 на уровне container-metadata — и теперь это измерено, а не предположено.**
Единственный след настройки в контейнере — доля процента в суммарной длине `ExportBundleData` и
единица в счётчике блоков; у игры нет второго варианта того же контента, с которым это можно было бы
сопоставить. Признаки, которые решают вопрос однозначно (`PKG_UnversionedProperties`, ширина записи
export map, состав name map, форма payload), лежат в **заголовке пакета**, а заголовки пакетов игры —
внутри `MISERY-Windows.ucas`, за флагом `Encrypted`.

Что сравнение **сужает** до одного варианта:

1. стоковый путь `RunUAT BuildCookRun` **наблюдаемо** передаёт `-unversioned` (лог этого прогона);
2. стоковый `BaseEngine.ini` **наблюдаемо** содержит `CanUseUnversionedPropertySerialization=True`;
3. структура установки игры — 1:1 с выводом ровно этого пути: `global.utoc` с единственным
   `ScriptObjects`, основной `.utoc` версии 6 с теми же полями, `.pak` без cooked-ассетов с
   `AssetRegistry.bin` и `Config/*.ini` внутри, две `ShaderCodeLibrary`;
4. отклонений от стокового пути в наблюдаемой части найдено **два**, и оба ортогональны
   свойствам: включено шифрование контейнера (`0x0a` против `0x08`) и **выключено сжатие** (таблица
   методов пуста, method index 0 у всех 79 914 блоков).

Итоговая формулировка, которую я готов защищать, — строка **CKC-06** сводной таблицы §9:
MISERY почти наверняка использует unversioned property serialization, и это вывод, а не чтение.
Сам бит флага не прочитан ни разу. Понижать оценку не за что: есть две независимые наблюдаемые
линии — значения по умолчанию тулчейна и структурная идентичность контейнеров. Повышать её тоже
нечем: пока бит не прочитан, любая надбавка была бы надбавкой за уверенность, а не за измерение.

**Чем закрывается до OBSERVED, в порядке дешевизны:**

1. `runtime-reflection`: у загруженного пакета игры прочитать `UPackage::GetPackageFlags() & 0x2000`.
   Это один бит, и его читает любой внешний инспектор уровня 1 (`docs/protection-assessment.md` 9.1).
2. `asset-registry` в runtime: реестр игры расшифровывается самой игрой при старте (см. §5).
3. Формат `FZenPackageSummary` в `ContainerHeader`/`ExportBundleData` — недоступен без ключа, и этот
   путь **не** предлагается.

---

## 4. CK-04 — запекается ли офсет свойства в cooked-данные

### 4.1 Что лежит в сериализованных данных ребёнка

CDO ребёнка — экспорт `Default__BP_RefChild_C`, `SerialSize` = **34 байта**. Полностью:

```
29 04 | 0b 02 | 0a 03 | 0000b441 | 00002040 | 38b49649 | 01000000 | 03000000 | 0000000000000000
```

Разбор по `UnversionedPropertySerialization.cpp:529-556, 569-598`: первые шесть байт — три
16-битных фрагмента `FUnversionedHeader`, `SkipNum` в битах 0..6, `IsLast` в бите 8, `ValueNum` со
сдвигом 9:

| фрагмент | `packed` | `SkipNum` | `ValueNum` | индексы схемы |
|---|---|---|---|---|
| 1 | `0x0429` | 41 | 2 | 41, 42 |
| 2 | `0x020B` | 11 | 1 | 54 |
| 3 | `0x030A` | 10 | 1 (последний) | 65 |

Дальше — только значения, и они читаются насквозь: `0000b441` = 22.5, `00002040` = 2.5,
`38b49649` = 1234567.0, затем `01000000` — длина массива 1 и `03000000` — индекс имени в name map.
Это в точности то, что скрипт задал ребёнку: `InitialLifeSpan=22.5`, `CustomTimeDilation=2.5`,
`NetCullDistanceSquared=1234567.0`, `Tags=["child-tag"]`. Обратный проход «что задали → что в
байтах» сошёлся, и это заодно проверка самого декодера.

**Байтового офсета в этих 34 байтах нет и быть негде.** Свойство адресуется **порядковым номером в
схеме класса**, а `SkipNum` и `ValueNum` ограничены 127 (`U:571-572`) — в такое поле офсет вида
`0x2A8` не влезает физически.

### 4.2 Эксперимент: родитель вырос на одно свойство

`BP_RefParent` получил ещё один SCS-компонент (`ParentExtraAudio`), проект перекомпилирован,
cook повторён с теми же настройками (вариант **G**). Пакет ребёнка:

| | база (U) | родитель вырос (G) |
|---|---|---|
| `.uexp` размер | 379 | **379** |
| `.uexp` sha256 | `8c2201ec…` | **`5340c8ce…`** — другой |
| CDO `SerialSize` | 34 | 34 |
| первый байт CDO | `0x29` (41) | **`0x2a` (42)** |
| фрагменты | 41/2, 11/1, 10/1 | **42/2**, 11/1, 10/1 |
| индексы схемы | 41,42 / 54 / 65 | **42,43 / 55 / 66** |
| значения | 22.5, 2.5, 1234567.0, 1×FName | **те же** |
| `.uasset` | 2867 | 2964 (+2 имени, +1 import) |

**Внутри 34-байтового payload самого CDO** изменился ровно один байт — счётчик пропуска. Все
индексы схемы сдвинулись на +1, все значения остались теми же. Это не то же самое, что «во всём
`.uexp`-файле один байт»: `+1 import` в строке таблицы выше — не побочная деталь, а отдельный,
второй механизм рассинхронизации. Рост таблицы импортов на одну запись перенумеровывает
`FPackageIndex`-ссылки во **всех прочих экспортах того же пакета**, включая четыре несвязанных
generated-класса ребёнка (`ExecuteUbergraph`, конструктор, геттеры компонентов) — независимая
проверка байт-диффом обоих `.uexp` целиком нашла 6 различий на 379 байт, а не 1: пять из них —
это ровно такие сдвиги `FPackageIndex` на ±1 по 4-байтовой границе в других экспортах, шестой —
байт CDO, разобранный выше. Механизм тот же, что делает офсет свойства ненадёжным (перекомпоновка
структуры чужого пакета меняет чужие индексы), только на уровень выше — на уровне таблицы
импортов, а не таблицы свойств. Для reconstruction это значит: **рост родителя на одно свойство
инвалидирует не только офсеты в CDO, но потенциально любую ссылку по `FPackageIndex` в том же
cooked-пакете**, если она была записана до пересборки таблицы импортов.

Направление сдвига объясняется порядком обхода: `UStruct::Link` строит `PropertyLink`
итератором `TFieldIterator<FProperty>` (`Class.cpp:948,984-985`), то есть **сначала свойства самого
класса, потом вверх по цепочке предков**; схему unversioned-сериализации строит
`FUnversionedSchemaRange` прямо из `Struct->PropertyLink` (`U:490-500`). Поэтому новое свойство
родителя встало **перед** свойствами `AActor`, и индексы переопределённых нативных свойств выросли.

### 4.3 Что говорит код — второй, независимый метод

`FProperty::Serialize` (`Runtime/CoreUObject/Private/UObject/Property.cpp:836-872`) пишет
`ArrayDim`, `ElementSize`, `PropertyFlags`, `RepIndex`, `RepNotifyFunc`,
`BlueprintReplicationCondition` — и **на загрузке явно обнуляет офсет**:

```cpp
if (Ar.IsLoading())
{
    Offset_Internal = 0;
    DestructorLinkNext = nullptr;
}
```

Офсета в потоке нет; он вычисляется позже в `UStruct::Link`. Размер элемента (`ElementSize`) при этом
сериализуется — то есть **размер запекается, а офсет нет**.

### 4.4 Вердикт по CK-04 и режим отказа

**Офсет свойства в cooked-данные не запекается** — строка **CKC-07** сводной таблицы §9, где
стоят оба независимых метода: чтение кода (`Property.cpp:836-872`) и чтение того, что код
произвёл (34 байта CDO, где офсету негде быть).

**Но запекается порядковый номер свойства в схеме всей цепочки классов, и это и есть реальный риск
§14A** — строка **CKC-08**, измерено на нашем cook. Отсюда прямые следствия для mod-kit:

1. У stub-а должны совпадать **состав и порядок** свойств всей цепочки предков — до одного элемента.
   Не совпадёт на одно свойство — все индексы после точки вставки уедут.
2. **Размеры и офсеты stub-а совпадать не обязаны**: они пересчитываются `Link()` в процессе игры.
3. Режим отказа — **тихий**: в потоке нет ни имён, ни размеров, ни GUID-ов, по которым загрузчик мог
   бы заметить рассинхронизацию. Значения просто прочитаются в соседние свойства. Ровно это
   `plan.md` RISK-15 называет самым опасным исходом, и теперь это не ожидание, а измеренный механизм.
4. Порядок обхода — производный-первым — означает, что вставка свойства в **любой** класс цепочки
   сдвигает индексы всех свойств в классах **выше** точки вставки.

Чего этот эксперимент **не** сделал: не загрузил устаревший пакет ребёнка в движок с выросшим
родителем и не прочитал получившиеся значения. Это следующий шаг, и он дешёвый:
подменить `BP_RefChild.uasset`/`.uexp` в staged-сборке варианта G файлами варианта U, запустить
`CookRef.exe` и прочитать четыре значения. Дополнительно в движке есть штатный самотест —
`BaseEngine.ini` содержит `TestUnversionedPropertySerializationWhenCooking=False`, и его включение
даёт проверку тем же кодом, что сериализует.

---

## 5. Где оказывается `AssetRegistry.bin` — и что это решает про оракул asset-registry

Наш cook пишет два реестра:

| Артефакт | Путь | Размер (наш прогон) |
|---|---|---|
| runtime-реестр | `Saved/Cooked/Windows/CookRef/AssetRegistry.bin` | 106 669 |
| development-реестр | `Saved/Cooked/Windows/CookRef/Metadata/DevelopmentAssetRegistry.bin` | 286 803 |

При staging **runtime-реестр попадает в `.pak` как обычный файл**, а не в IoStore:
в нашем `CookRef-Windows.pak` он лежит записью `CookRef/AssetRegistry.bin` (24 514 байт сжато из
106 669, метод 1, не зашифрован). Ни один тип `EIoChunkType` в контейнере его не несёт — перечень
типов в §3.3 полон, и `PackageStoreEntry`/`DerivedData`/`PackageResource` в контейнерах не встречаются
вообще.

У игры — то же самое место: `MISERY/AssetRegistry.bin`, **4 148 187** байт, запись
`MISERY-Windows.pak` (`research/evidence/CK-01/pak-paths.txt`, строка 4388), флаг entry —
`Flag_Encrypted`, без сжатия.

**Вывод для оракула `asset-registry`.** Реестр игры **не** внутри зашифрованного IoStore-контейнера, а
внутри `.pak`, у которого индекс — plaintext (доказано SHA1), а payload каждой из 4424 записей
зашифрован. Значит:

* **офлайн-разбор реестра недоступен** без ключа — и этот путь не предлагается (D-02);
* **в runtime реестр доступен**: игра сама расшифровывает и загружает его при старте, поэтому
  `asset-registry` остаётся достижимым через наблюдение процесса, а не через файл. Это тот же
  внешний инспектор уровня 1, который закрывает и CK-01;
* формат для будущего парсера у нас теперь есть эталонный: `AssetRegistry.bin` нашего cook читается
  свободно и совпадает по роли и месту.

---

## 6. `.usmap`: стоковый cook его не производит

| Проверка | Результат |
|---|---|
| `grep` (регистрозависимый) по `Engine/Source`, `Engine/Plugins`, `Engine/Config` | ни одного вхождения `usmap` |
| `find` по всему выводу cook и staging (5 вариантов, 3 staged-сборки) | ни одного файла `*.usmap` |
| расширения в инвентаре установки игры (53 файла) | `.bat .bin .cur .dll .exe .html .json .pak .sh .tps .ttf .txt .ucas .utoc .vdf` — `.usmap` нет |

То есть: формат `.usmap` — это то, что **сторонняя тулчейн (FModel, retoc) требует**, а не то, что
UE 5.4.4 умеет писать. Для mod-kit это существенно: маппинги для собственных классов придётся
**генерировать самим** — по данным reflection, а не извлекать из сборки. Отсутствие `.usmap` в
установке игры — отдельный факт, и он проверен: его там нет.

---

## 7. Побочные находки о контейнере игры, полученные без расшифровки

Эти числа — прямое следствие §3.3 и заслуживают того, чтобы быть названными, потому что до этого
прогона про содержимое `MISERY-Windows.ucas` не было известно ничего, кроме размера:

1. **В контейнере игры 12 933 пакета** (chunk'и `ExportBundleData`) суммарной длиной
   2 257 891 527 байт; на нашем контейнере соответствие «один `ExportBundleData` = один файл пакета»
   проверено по читаемому directory index (375 = 373 `.uasset` + 2 `.umap`).
2. **5 513 chunk'ов bulk-данных** суммарно 2 047 178 937 байт — примерно половина объёма контейнера;
   у нас это 1:1 файлы `.ubulk`.
3. **Две `ShaderCodeLibrary`** и 1 061 chunk `ShaderCode`: столько же библиотек, сколько у нашего
   cook под одну шейдерную платформу (global + проектная). Это признак **одной** шейдерной платформы
   в поставке, а не нескольких.
4. **Контейнер игры не сжат**: таблица методов пуста, у всех 79 914 блоков method index 0. При этом
   он зашифрован. То есть `0x0a = Indexed | Encrypted`, ровно наш `0x08` плюс шифрование.
5. **Directory index игры (844 960 байт) должен именовать 18 448 файлов** — 12 933 + 5 513 + 2, по
   модели, проверенной на нашем контейнере (403 именованных = 375 + 26 + 2, при 483 неименованных
   `ShaderCode`/`ContainerHeader`). Это предсказание, а не чтение, и оно проверяемо тем же ключом,
   которого мы не берём.
6. **`global.ucas` игры — plaintext-chunk `ScriptObjects` длиной 2 269 159 байт**, и наш cook пишет
   ровно такой же артефакт отдельным файлом `Metadata/scriptobjects.bin`. Это подтверждает
   назначение `global.ucas` из `plan.md` §10.5 эмпирически и даёт эталон формата для RF-01.

Ни одно из этих чисел не потребовало ключа: всё прочитано из plaintext-массивов TOC.

---

## 8. Инструменты, добавленные под `tools/content/`

| Инструмент | Что делает | Почему он переиспользуемый |
|---|---|---|
| `package_summary.py` | полный разбор `FPackageFileSummary` UE 5.4, name/import/export map, независимое измерение ширины записи export map, декод `FUnversionedHeader` и имени первого `FPropertyTag`; режим `--compare` даёт структурный diff двух пакетов | это единственный способ проверить структуру **нашего** приготовленного пакета до запуска игры — контрольная точка MK-2 из `plan.md` §14A |
| `iostore_chunks.py` | перечёт plaintext-массивов `.utoc`: типы chunk'ов, длины, блоки, методы, модель блоков, а при незашифрованном индексе — имена файлов по chunk'ам | превращает «directory index зашифрован» из тупика в ограничение: типы и размеры 19 510 chunk'ов игры читаются без ключа |

Тесты: `tests/test_content_readers.py`, 20 проверок. Ни одна из них не открывает установку игры и
не трогает эталонный cook на `D:`: и пакет, и контейнер собираются побайтово в самом тесте, из
таблицы полей, а не из кода читателя, — иначе тест доказывал бы только то, что парсер согласен с
собой. Отдельно закреплены три регрессии: измерение ширины записи export map, независимое от флага;
форма evidence-блока против `research/schema/kb-record.schema.json`; отказ читать что-либо внутри
дерева установки.

### 8.1 Два дефекта существующих инструментов, найденных этим прогоном

Оба найдены тем, что старым инструментам дали новые данные, и оба относятся к репозиторию, а не к
игре. Ни один из них я не правил: они за пределами задачи прогона, и оба меняют поведение гейта.

1. **`tools/content/pak_index.py` на НЕзашифрованном `.pak`.** На игровом `.pak` все 4424 записи
   зашифрованы, полезная нагрузка не читается, и класс-P слой инструмента остаётся коротким. На нашем
   staged-`.pak` записи не зашифрованы, инструмент читает локальные заголовки — и его `claim`-строки
   начинают называть поля. Валидатор базы знаний справедливо отвечает на это `EV-05` + `MIX-SPLIT`
   (86 нарушений на файл): один класс-P/класс-I смешанный рекорд на каждую такую запись. Поэтому
   `pak-index-ours.json` в доказательства не положен, положен только список путей.
2. **Ложное срабатывание `BINARY_NAMING_RE` в `tools/kb/validate.py` на имени файла.** Второй
   половиной этого правила является регистрозависимый шаблон CamelCase-идентификатора — он ловит
   имена полей и типов вида `TocEntryCount`. Имя файла нашего reference-проекта устроено так же, и
   класс-P чтение «N байт по смещению X файла <имя>» из-за одного имени файла выводилось в класс I.
   Обходной путь не понадобился: класс-P слой для `.utoc` и так принадлежит
   `tools/fingerprint/container_info.py`, и дублировать его в `iostore_chunks.py` было незачем.

Оба — стандартная библиотека, только чтение, заголовок TOC берётся импортом из
`tools/fingerprint/container_info.py`, а не вторым разбором (одно мнение о том, где начинается
массив). `package_summary.py` отказывается читать что-либо внутри установки игры: cooked-пакеты игры
зашифрованы, и «наполовину разобранный» результат был бы уверенной бессмыслицей.

---

## 9. Сводная таблица фактов

| ID | Утверждение | Уровень | Confidence | Claim class | Oracle | Метод | Evidence |
|---|---|---|---|---|---|---|---|
| CKC-01 | В файле `D:\Program Files\UE_5.4\Engine\Config\BaseEngine.ini` в секции `[Core.System]` есть строка `CanUseUnversionedPropertySerialization=True` | OBSERVED | 0.99 | P | `filesystem` | чтение файла двумя разными командами — `grep` по каталогу `Engine/Config` и печать строк 1430-1450 того же файла, обе показали строку; повторено 2026-08-23 | `research/evidence/CK-COOK/cook-runs.log` |
| CKC-02 | `RunUAT BuildCookRun` без дополнительных ключей запустил cook-commandlet со ключом `-unversioned` | OBSERVED | 0.97 | P | `filesystem` | запуск `RunUAT BuildCookRun -cook` и чтение строки запуска commandlet в логе; метод перезапущен и результат воспроизведён 2026-08-23: второй прогон `uat_cook_default_run2.log` дал ту же строку с `-unversioned` | `research/evidence/CK-COOK/cook-runs.log` |
| CKC-03 | Пакет с `PKG_UnversionedProperties` несёт запись export map шириной 96 байт, без флага — 112 байт | OBSERVED | 0.93 | I | `filesystem` + `external-doc` | (1) измерение `(DependsOffset − ExportOffset)/ExportCount` инструментом `tools/content/package_summary.py` на четырёх вариантах cook; (2) чтение условия в `ObjectResource.cpp:208-212`, предсказывающего ровно 16 байт разницы | `research/evidence/CK-COOK/structural-comparison.json` |
| CKC-04 | При unversioned-свойствах из name map пакета исчезают имена свойств и типов: 36 имён против 54 у того же ассета | OBSERVED | 0.92 | I | `filesystem` + `external-doc` | (1) разбор name map обоих пакетов `tools/content/package_summary.py`; (2) независимый `strings`-diff тех же двух файлов: только в versioned-варианте есть 23 строки, из них те самые 18 имён, остальные пять — бинарный шум; в обратную сторону — 0 строк | `research/evidence/CK-COOK/compare-onesetting-U-vs-X.json` |
| CKC-05 | На уровне container-metadata настройка unversioned-свойств не оставляет ни одного различимого признака, кроме суммарной длины chunk'ов (+0,80 %), +1 блока и +12 байт `.utoc` | OBSERVED | 0.90 | I | `container-metadata` + `filesystem` | (1) перечёт chunk'ов и блоков `tools/content/iostore_chunks.py` на двух staged-сборках, различающихся только этой настройкой; (2) независимая арифметическая проверка в том же прогоне: сумма несжатых размеров блоков равна сумме длин chunk'ов, а предсказанное число блоков равно счётчику в заголовке — обе сошлись на обеих сборках, и разошлись бы, если бы разбор массивов сдвинулся | `research/evidence/CK-COOK/chunks-ours-unversioned-compressed.json`, `research/evidence/CK-COOK/chunks-ours-versioned-compressed.json` |
| CKC-06 | MISERY использует unversioned property serialization | INFERRED | 0.85 | I | `filesystem` + `container-metadata` | (1) наблюдение значений по умолчанию тулчейна: `-unversioned` в запуске `RunUAT` и `=True` в `BaseEngine.ini`; (2) структурное сравнение установки игры с выводом того же пути — типы chunk'ов, `global`-контейнер, состав `.pak` — совпало по всем сверенным признакам, кроме шифрования и сжатия | `research/evidence/CK-COOK/structural-comparison.json` |
| CKC-07 | Байтовый офсет свойства в сериализованные данные cooked-пакета не попадает | OBSERVED | 0.93 | I | `filesystem` + `external-doc` | (1) чтение `FProperty::Serialize` (`Property.cpp:836-872`), где офсет не пишется и обнуляется на загрузке; (2) разбор 34 байт CDO нашего приготовленного пакета инструментом `tools/content/package_summary.py`: шесть байт заголовка и четыре значения, поля под офсет нет | `research/evidence/CK-COOK/ck04-child-parent-grown-vs-base.json` |
| CKC-08 | Порядковый номер свойства в схеме цепочки классов запекается: рост родителя на одно свойство сдвинул все индексы в CDO ребёнка на +1 при неизменных значениях и неизменном размере | OBSERVED | 0.92 | I | `filesystem` + `external-doc` | (1) эксперимент: рост родителя, повторный cook, побайтовое сравнение пакета ребёнка — изменился один байт, счётчик пропуска, `0x29 → 0x2a`; (2) чтение порядка обхода в `Class.cpp:948,984` и `UnversionedPropertySerialization.cpp:490-500`, предсказывающего сдвиг именно у предков выше точки вставки | `research/evidence/CK-COOK/ck04-child-parent-grown-vs-base.json` |
| CKC-09 | Устаревший пакет ребёнка, загруженный против изменившегося родителя, прочитает значения в соседние свойства без диагностики | INFERRED | 0.75 | I | `external-doc` + `filesystem` | (1) измеренная зависимость индексов от состава родителя (CKC-08); (2) чтение формата: в потоке нет ни имён, ни размеров, ни GUID-ов свойств (`U:529-556`), то есть у загрузчика нет данных для проверки | `research/evidence/CK-COOK/ck04-child-parent-grown-vs-base.json` |
| CKC-10 | В cook `AssetRegistry.bin` пишется в `Saved/Cooked/<Platform>/<Project>/AssetRegistry.bin`, а при staging попадает записью в `.pak`, и ни один тип chunk'а IoStore его не несёт | OBSERVED | 0.92 | I | `filesystem` + `container-metadata` | (1) перечёт вывода cook и разбор индекса нашего `.pak` инструментом `tools/content/pak_index.py`, где запись `CookRef/AssetRegistry.bin` найдена; (2) полный перечёт типов chunk'ов нашего контейнера `tools/content/iostore_chunks.py`, где встречаются только пять типов и ни один не соответствует реестру | `research/evidence/CK-COOK/pak-paths-ours.txt`, `research/evidence/CK-COOK/chunks-ours-unversioned-uncompressed.json` |
| CKC-11 | Реестр ассетов игры лежит записью `MISERY/AssetRegistry.bin` размером 4 148 187 байт в `MISERY-Windows.pak`, и флаг этой записи — зашифрована. Метод прогнан дважды и результат воспроизведён (`pak-index-run1.log`, `pak-index-run2.log` прогона CK-01). build_key=sha256:0eef3715244b467c830022c4260a0e2c29c7def1429cb34aa37fdf9b7e14a383. Попытка опровержения: если бы бит шифрования читался неверно, перечёт дал бы не 4424 зашифрованных записи из 4424, а смесь, и три probe-проверки инструмента (перечёт флаговых слов, локальный заголовок записи, арифметика выравнивания) разошлись бы между собой; они сошлись | OBSERVED | 0.95 | I | `container-metadata` + `external-doc` | (1) разбор индекса пакета `tools/content/pak_index.py` (прогон CK-01, строка 4388 списка путей); (2) сверка места с местом в нашем staged-выводе, где тот же путь и та же роль получены собственным staging | `research/evidence/CK-01/pak-paths.txt`, `research/evidence/CK-COOK/structural-comparison.json` |
| CKC-12 | Стоковый UE 5.4.4 не производит `.usmap`: ни одного вхождения строки в `Engine/Source`, `Engine/Plugins`, `Engine/Config`, ни одного файла в выводе пяти cook и трёх staging | OBSERVED | 0.90 | P | `filesystem` | (1) регистрозависимый `grep` по трём каталогам движка; (2) `find` по всему выводу cook и staging; метод перезапущен и результат воспроизведён 2026-08-23 — второй `grep` с регистронезависимым шаблоном дал только пять ложных совпадений вида `StatusMap`, и ни одного `.usmap` | `research/evidence/CK-COOK/structural-comparison.json` |
| CKC-13 | В установке игры (53 файла) нет ни одного файла `.usmap` | OBSERVED | 0.97 | P | `filesystem` | перечёт расширений в `install-inventory.json`; повторено 2026-08-23 обходом того же реестра | `research/builds/misery-24826585-ue5.4.4-0eef3715244b/install-inventory.json` |
| CKC-14 | В `MISERY-Windows.utoc` 12 933 chunk'а имеют в 12-м байте значение 1, 5 513 — значение 2, 1 061 — значение 9, 2 — значение 8, 1 — значение 6. Метод прогнан дважды и результат воспроизведён 2026-08-23: два прогона дали побайтово совпадающий вывод, кроме `generated_at`. build_key=sha256:0eef3715244b467c830022c4260a0e2c29c7def1429cb34aa37fdf9b7e14a383. Попытка опровержения: неверный декод дал бы значения вне `EIoChunkType` либо перечёт, не совпадающий с перечётом файлов по расширениям на нашем контейнере (375/26/2); ни того, ни другого не случилось | OBSERVED | 0.95 | I | `container-metadata` + `external-doc` | (1) перечёт массива chunk id инструментом `tools/content/iostore_chunks.py`; (2) та же процедура на нашем контейнере, где перечёт по типам совпал с перечётом файлов по расширениям из читаемого directory index (375/26/2), то есть декод типа проверен на образце с известным ответом | `research/evidence/CK-COOK/chunks-game-main.json` |
| CKC-15 | Основной контейнер игры не сжат: таблица методов сжатия пуста, у всех 79 914 блоков индекс метода 0, а сумма длин chunk'ов равна сумме несжатых размеров блоков | OBSERVED | 0.93 | I | `container-metadata` + `external-doc` | (1) разбор блоков `tools/content/iostore_chunks.py`; (2) независимая арифметическая проверка: `Σ ceil(len/65536) = 79 914` совпало со счётчиком заголовка, и та же модель проверена на нашей несжатой и на нашей сжатой сборке, где она различает случаи | `research/evidence/CK-COOK/chunks-game-main.json` |
| CKC-16 | `global.ucas` игры содержит один chunk типа `ScriptObjects` длиной 2 269 159 байт, а наш cook пишет тот же артефакт файлом `Metadata/scriptobjects.bin` (2 129 430 байт = длина нашего chunk'а) | OBSERVED | 0.92 | I | `container-metadata` + `filesystem` | (1) разбор `global.utoc` обоих контейнеров `tools/content/iostore_chunks.py`; (2) сверка размера и первых байт `scriptobjects.bin` с payload нашего `global.ucas` — совпали размер и первые 16 байт | `research/evidence/CK-COOK/chunks-game-global.json`, `research/evidence/CK-COOK/chunks-ours-global.json` |
| CKC-17 | Редактор UE 5.4.4 не работает при `CanUseUnversionedPropertySerialization=False` в своей ini-иерархии: cook падает на `check` в `SerializeUnversionedProperties` | OBSERVED | 0.90 | I | `filesystem` + `external-doc` | (1) прогон cook с этим значением — падение с текстом assert и кодом 3; (2) чтение причины в исходниках: `DuplicateDataReader.cpp:30` включает unversioned-сериализацию безусловно, а `UnversionedPropertySerialization.cpp:884` требует разрешения | `research/evidence/CK-COOK/cook-runs.log` |

---

## 10. Что осталось UNKNOWN и чем закрывается

| Вопрос | Статус | Названный метод закрытия |
|---|---|---|
| Бит `PKG_UnversionedProperties` у пакетов игры | прямого чтения нет, строка CKC-06 | внешний инспектор уровня 1: `UPackage::GetPackageFlags()` у загруженного пакета |
| Что именно прочитает устаревший ребёнок против изменившегося родителя | вывод, строка CKC-09 | подмена `.uasset`/`.uexp` варианта U в staged-сборку варианта G и чтение четырёх значений в запущенном `CookRef.exe` |
| Имена пакетов `/Game/...` в контейнере игры | UNKNOWN | `FPackageId::FromName` = CityHash64 по имени пакета в нижнем регистре в UTF-16LE (`Core/Private/IO/PackageId.cpp:22-31`); chunk id — plaintext, поэтому кандидатное имя проверяется хэшем без всякой расшифровки. Реализацию проверить на нашем контейнере, где имена известны из directory index |
| Пользовательская структура из нескольких членов в cooked-выводе | UNKNOWN | редактор с GUI либо C++-модуль (нет MSVC — устанавливать нельзя) |
| Custom versions модулей игры (CK-05) | UNKNOWN | список из 9 custom versions нашего versioned-cook даёт эталон; у игры заголовки пакетов зашифрованы, остаётся runtime |
| Совпадают ли прочие настройки cook игры с нашими (CK-06) | частично | наблюдаемые отличия: шифрование включено, сжатие выключено; остальное — за заголовками пакетов |

---

## 11. Чего этот прогон не доказал

* Не прочитан ни один байт payload игрового контейнера и ни один заголовок игрового пакета.
  Все утверждения об игре — о TOC-метаданных и о `.pak`-индексе.
* Не доказано, что MISERY готовили именно `RunUAT BuildCookRun`. Доказано, что структура установки
  совпадает с выводом этого пути по всем сверенным признакам, кроме двух названных.
* Наш reference-проект — Blueprint-only и крошечный. Он воспроизводит **форму** cooked-вывода, а не
  масштаб и не состав игры; ни один вывод здесь не опирается на сходство содержимого.
* Соответствие «один `ExportBundleData` = один пакет» проверено на нашем контейнере и перенесено на
  контейнер игры как модель. Это INFERRED, и §7 п. 5 говорит это прямо.
