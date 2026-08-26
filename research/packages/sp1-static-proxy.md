# SP-1 — статический прокси (`plan.md` §14.7, задача CT-04)

| Поле | Значение |
|---|---|
| Задача | **CT-04 / SP-1** (`plan.md` §14.7, строка 1363); milestone **M2s** (`plan.md` строка 1775) |
| Что закрывает | два вопроса: (а) прокси к **E-3a** — зависит ли регистрация `UClass` от происхождения контейнера; (б) **CK-04** — запекаются ли офсеты свойств дочернего BP-класса при cook или пересчитываются при `Link()` |
| Чем SP-1 **не** является | заменой E-3a/E-3b. `plan.md` §14.7 говорит прямо: «Это **не заменяет** E-3a/E-3b (по §10.3 для публичного API нужно ≥0.95 и runtime-подтверждение)». Ни одна цифра отсюда не даёт права строить публичный API |
| Зачем тогда | чтобы решать про 40 ГБ и про весь трек §14A, **зная ожидаемый результат**. Это прокси, а не вердикт |
| Build | `build_key=sha256:0eef3715244b467c830022c4260a0e2c29c7def1429cb34aa37fdf9b7e14a383` |

> **Структура файла.** Каждый вопрос SP-1 живёт под своим заголовком второго уровня и правится
> независимо. Раздел «CK-04» ниже написан агентом, который занимался только CK-04; раздел про
> E-3a — другим. Пересечений в тексте нет намеренно: смешанный раздел означал бы, что два
> вердикта нельзя развести, а их можно и нужно.

---

## CK-04 — запекаются ли офсеты свойств дочернего BP-класса при cook?

### 0. Вердикт, и сразу его граница

**Ожидание: офсеты НЕ запекаются. Они пересчитываются при загрузке, в `UStruct::Link`, от того
размера родителя, который родитель имеет в момент загрузки.** В cooked-пакет офсет не пишется
вовсе, а при десериализации свойства он принудительно обнуляется.

Что это означает для трека §14A практически:

> Реконструированный stub родителя обязан быть верен относительно **порядка и типов** свойств.
> Относительно **суммарного размера** родителя — не обязан: размер, от которого отсчитываются
> офсеты дочерних свойств, берётся из настоящего родителя в игре, а не из пакета.

Это ровно то смягчение, на которое `plan.md` §14A.3 (опасность 2) надеялась, и оно снимает
именно опасность 2 — **и только её**. Опасность 1 (unversioned property serialization, порядок и
**количество** свойств) остаётся в полной силе и от CK-04 не зависит; см. §7.

**Граница, которую нельзя обойти.** Матрица `plan.md` §10.5 для типа утверждения «функция X
делает Z» требует `binary-analysis` **плюс** подтверждение наблюдением через `runtime-reflection`,
и помечает: «**нет**, нужны оба». Runtime-наблюдения здесь нет ни одного. Поэтому вердикт выше —
**обоснованное ожидание, а не закрытый факт**, его потолок 0.79 (§8), и он закрывается
названным runtime-тестом **RT-CK-04** (§6), а не ещё одним чтением исходников.

### 1. Метод: два разных акта измерения, отвечающие на два разных вопроса

`plan.md` и `AGENTS.md` требуют различать их, и здесь это различие несущее:

| # | Акт измерения | Объект | На какой вопрос отвечает | Oracle |
|---|---|---|---|---|
| 1 | Чтение first-party исходников UE 5.4.4 на changelist сборки | дерево `Engine/Source` версии 5.4.4, CL 35576357, ветка `++UE5+Release-5.4`, `IsPromotedBuild 1` | что делает **движок UE 5.4.4** | `external-doc` (+ `filesystem` на факт «файл существует и содержит этот текст») |
| 2 | Поиск в самом образе диагностических литералов, уникальных для найденных функций, и их ссылок из исполняемых секций | `MISERY/Binaries/Win64/MISERY-Win64-Shipping.exe`, sha256 которого **и есть** `build_key` | попал ли этот код в **эту** сборку | `binary-analysis` (+ `external-doc` на атрибуцию литерала к строке исходника) |

Ни один из них по отдельности ничего не говорит об игре. Первый доказывает утверждение о
движке; второй — о содержимом файла. Утверждение об игре — это их конъюнкция, и она градуируется
отдельной записью (§8, `CK-04-4`).

**Чего у этого метода нет и не может быть.** В этой установке **нет ни одного читаемого cooked-пакета**
(CK-01: `MISERY-Windows.pak` содержит 4424 записи, все зашифрованы, cooked-пакетов 0;
`MISERY-Windows.utoc` — `Encrypted|Indexed`, D-02 запрещает извлечение ключа). Поэтому
подтверждения **на уровне пакета** — «вот cooked BPGC, вот его байты, офсета в них нет» — получить
негде, и оно здесь не заявляется. Это ограничение метода, а не оговорка для вида: см. §5, где из-за
него один подвопрос остаётся `UNKNOWN`.

Инструмент: `tools/static/link_path_probe.py` (только stdlib, read-only, вывод через `pathguard`).
Ни один литерал в нём не задан константой — все читаются из дерева UE в момент запуска, вместе с
файлом и номером строки; переформулированное сообщение он сообщает, а не угадывает.

---

### 2. Цепочка в первоисточнике, со ссылкой на файл и строку на каждом шаге

Все пути ниже относительны `Engine/Source/`. Дерево — UE 5.4.4, CL 35576357.

#### 2.1 Где вообще живёт офсет

`Runtime/CoreUObject/Public/UObject/UnrealType.h:162-188` — объявление `FProperty`. Автор класса сам
разделил его поля на две группы, и это разделение — не наш вывод, а комментарий в исходнике:

* `:166` `// Persistent variables.` → `ArrayDim`, `ElementSize`, `PropertyFlags`, `RepIndex` (`:167-170`);
* `:175` `// In memory variables (generated during Link())` → и единственный член под ним,
  `int32 Offset_Internal` (`:176`).

Офсет лежит в группе «в памяти, порождается во время `Link()`». Дальше вся §2 — проверка того, что
код делает то, что говорит этот комментарий.

#### 2.2 Native-класс: офсет приходит из компилятора и **не** пересчитывается

| Шаг | Файл:строка | Что там |
|---|---|---|
| 1 | `Runtime/CoreUObject/Public/UObject/ObjectMacros.h:2075-2090` | `IMPLEMENT_CLASS_NO_AUTO_REGISTRATION` передаёт в `GetPrivateStaticClassBody` `sizeof(TClass)` (`:2080`) и `alignof(TClass)` (`:2081`) |
| 2 | `Runtime/CoreUObject/Private/UObject/Class.cpp:6740-6755` | эти значения идут в конструктор `UClass(EC_StaticConstructor, …, InSize, InAlignment, …)` (`:6746-6747`) |
| 3 | `Runtime/CoreUObject/Private/UObject/Class.cpp:613-630` | `UStruct::UStruct(EStaticConstructor, int32 InSize, …)` инициализирует `PropertiesSize(InSize)` (`:618`) и `MinAlignment(InMinAlignment)` (`:619`). **`PropertiesSize` native-класса — это C++ `sizeof`, зафиксированный при компиляции** |
| 4 | `Runtime/CoreUObject/Private/UObject/Property.cpp:760-776` | native-свойство строится из `UECodeGen_Private::FPropertyParamsBaseWithOffset` и берёт офсет прямо из сгенерированных данных: `this->Offset_Internal = Prop.Offset;` (`:773`). `Prop.Offset` — константа, выданная UnrealHeaderTool из `offsetof` |
| 5 | `Runtime/CoreUObject/Private/UObject/UObjectGlobals.cpp:6284-6309` | путь регистрации compiled-in класса: `ConstructFProperties(NewClass, Params.PropertyArray, …)` (`:6284`), затем `NewClass->StaticLink();` (`:6309`) — **без аргумента** |
| 6 | `Runtime/CoreUObject/Public/UObject/Class.h:490` | `void StaticLink(bool bRelinkExistingProperties = false);` — значение по умолчанию **`false`** |
| 7 | `Runtime/CoreUObject/Private/UObject/Class.cpp:871-880` | при `false` `UStruct::Link` идёт в `else`-ветку и вызывает `Property->LinkWithoutChangingOffset(Ar)` (`:877`) |
| 8 | `Runtime/CoreUObject/Public/UObject/UnrealType.h:353-356` | `LinkWithoutChangingOffset` — это `LinkInternal(Ar)` и **больше ничего**. `SetupOffset()` не вызывается |

Тот же путь у intrinsic-классов: `ObjectMacros.h:2102-2117`, `Class->StaticLink();` на `:2115`, тоже
без аргумента.

Два подтверждения из самого движка, что native-класс на этом пути **не грузится из пакета вообще**:

* `Class.cpp:5368-5369` — в `UClass::Serialize`, на пути загрузки, стоят два `checkf`:
  «Class %s loaded with CLASS_Native….we should not be loading any native classes.» и та же
  строка для `CLASS_Intrinsic`;
* `Class.cpp:4906-4910` — `UClass::Link` начинается с
  `check(!bRelinkExistingProperties || !(ClassFlags & CLASS_Intrinsic));` (`:4908`): попытка
  перелинковать intrinsic-класс — жёсткая ошибка.

**Ответ на вопрос 1.** Для native-класса в cooked-сборке офсет свойства берётся **из
исполняемого файла**: это `offsetof`, вычисленный компилятором и вписанный в сгенерированные
`FPropertyParams`. Он не читается из пакета (пакета для этого класса не существует) и **не**
пересчитывается при регистрации, потому что штатный вызов `StaticLink()` идёт с
`bRelinkExistingProperties == false`. Размер native-класса — `sizeof` того же компилятора.

#### 2.3 Blueprint-класс: офсет обнуляется при десериализации и пересчитывается при `Link`

| Шаг | Файл:строка | Что там |
|---|---|---|
| 1 | `Runtime/Engine/Private/BlueprintGeneratedClass.cpp:2551-2560` | `UBlueprintGeneratedClass::Serialize` → `Super::Serialize(Ar)` (`:2560`), то есть `UClass::Serialize`. Своей работы с офсетами нет |
| 2 | `Runtime/CoreUObject/Private/UObject/Class.cpp:5269-5277` | `UClass::Serialize` → `Super::Serialize(Ar)` (`:5277`), то есть `UStruct::Serialize` |
| 3 | `Runtime/CoreUObject/Private/UObject/Class.cpp:2086-2089` | `UStruct::Serialize` вызывает `SerializeProperties(Ar)` |
| 4 | `Runtime/CoreUObject/Private/UObject/Class.cpp:1957-1977` | при загрузке каждое свойство создаётся **заново** по имени типа: `FField* Prop = FField::Construct(PropertyTypeName, this, NAME_None, RF_NoFlags);` (`:1966`), затем `Prop->Serialize(Ar)` (`:1968`) |
| 5 | `Runtime/CoreUObject/Private/UObject/Property.cpp:865-869` | **`FProperty::Serialize` при загрузке делает `Offset_Internal = 0;`** (`:867`). Офсет не просто отсутствует в потоке — он принудительно затирается, чтобы устаревшее значение не выжило |
| 6 | `Runtime/CoreUObject/Private/UObject/Class.cpp:5366-5375` | вернувшись в `UClass::Serialize`: `if (Ar.IsLoading()) { … Link(Ar, true); }` — вызов на `:5373`, аргумент **`true`**. Ни `#if WITH_EDITOR`, ни другого гейта на этом пути нет |
| 6a | `Runtime/CoreUObject/Private/UObject/Class.cpp:2105-2109` | парная строка для не-`UClass` (`UScriptStruct`, `UFunction`): `Link(Ar, true)` (`:2108`) с комментарием «classes are linked in the UClass serializer, which just called me» |
| 7 | `Runtime/Engine/Private/BlueprintGeneratedClass.cpp:2248-2271` | `UBlueprintGeneratedClass::Link` → `Super::Link(Ar, bRelinkExistingProperties)` (`:2250`), затем только поиск `UberGraphFramePointerProperty` (`:2258-2266`) и `AssembleReferenceTokenStream(true)` (`:2270`). Офсетами не занимается |
| 8 | `Runtime/CoreUObject/Private/UObject/Class.cpp:780-785` | в ветке `bRelinkExistingProperties` первым делом `Ar.Preload(InheritanceSuper)` (`:784`) — родитель доводится до конца загрузки **до** того, как у него спросят размер. Комментарий на `:778`: «Preload everything before we calculate size» |
| 9 | `Runtime/CoreUObject/Private/UObject/Class.cpp:797-804` | **ключевые четыре строки.** `PropertiesSize = 0; MinAlignment = 1;` (`:797-798`), затем `if (InheritanceSuper) { PropertiesSize = InheritanceSuper->GetPropertiesSize(); MinAlignment = InheritanceSuper->GetMinAlignment(); }` (`:800-804`). Стартовая точка раскладки — размер родителя **в момент загрузки** |
| 10 | `Runtime/CoreUObject/Private/UObject/Class.cpp:806-839` | цикл по собственным свойствам (`Field->GetOwner<UObject>() != this` → `break`, `:808-811`), и в нём `PropertiesSize = Property->Link(Ar);` (`:827`). Аккумулятором служит само поле `UStruct::PropertiesSize` |
| 11 | `Runtime/CoreUObject/Public/UObject/UnrealType.h:358-362` | `int32 FProperty::Link(FArchive& Ar) { LinkInternal(Ar); return SetupOffset(); }` |
| 12 | `Runtime/CoreUObject/Private/UObject/Property.cpp:1345-1364` | **`FProperty::SetupOffset`**: `Offset_Internal = Align(OwnerStruct->GetPropertiesSize(), GetMinAlignment());` (`:1351`) и возврат `Offset_Internal + GetSize()` (`:1358-1363`) с проверкой на переполнение `int32` |

Замкнутый круг: `SetupOffset` читает текущее `OwnerStruct->GetPropertiesSize()`, кладёт свойство на
выровненную границу и возвращает новый суммарный размер, который строка `:827` записывает обратно в
`PropertiesSize`. Следующее свойство читает уже новое значение.

**Ответ на вопрос 2.** Для Blueprint-generated класса офсет каждого собственного свойства
**вычисляется при загрузке** как `Align(накопленный_размер, выравнивание_свойства)`, где начальным
значением накопленного размера служит `GetPropertiesSize()` **настоящего** родителя, уже полностью
загруженного. Значение из пакета не участвует: его там нет, а поле обнуляется на шаге 5.

#### 2.4 Побочный, но важный факт: `ElementSize` тоже пересчитывается

`LinkInternal` вызывается в **обеих** ветках `UStruct::Link` — и в пересчитывающей (`:827` через
`FProperty::Link`), и в непересчитывающей (`:877` через `LinkWithoutChangingOffset`). И он
переписывает размер элемента:

* `Runtime/CoreUObject/Public/UObject/UnrealType.h:1387-1392` — у фундаментальных типов
  `TProperty::LinkInternal` вызывает `SetElementSize()` (`:1389`);
* `Runtime/CoreUObject/Private/UObject/PropertyStruct.cpp:101-131` —
  `FStructProperty::LinkInternal` делает `Ar.Preload(Struct)` (`:112`) с комментарием «Preload is
  required here in order to load the value of `Struct->PropertiesSize`» (`:111`), а затем
  `ElementSize = Align(Struct->PropertiesSize, Struct->GetMinAlignment());` (`:121`).

То есть `ElementSize`, который **есть** в потоке (`Property.cpp:846`), при линковке затирается
размером настоящего разрешённого по имени типа. Это усиливает вывод §2.3 на один шаг: из пакета
берутся имя, тип, флаги и порядок — но не геометрия.

#### 2.5 Пересчитанный размер действительно используется

`Runtime/CoreUObject/Private/UObject/UObjectGlobals.cpp:3415` — в `StaticAllocateObject`:
`int32 TotalSize = InClass->GetPropertiesSize();`. Объект выделяется по тому размеру, который
посчитал `Link`, а не по какому-то другому. Иначе пересчёт офсетов был бы пересчётом в пустоту.

---

### 3. Вопрос 3: пишется ли офсет в cooked-пакет — и читается ли обратно

Проверено механически, а не утверждением: инструмент извлекает из дерева список членов, которые
каждый сериализатор реально прогоняет через `Ar <<`, и ищет среди них офсет. Результат
(`research/evidence/CK-04/link-path-shipping.json`, `source_probes`):

| Сериализатор | Строки | Что реально стримит | Офсет среди них |
|---|---|---|---|
| `FProperty::Serialize` | `Property.cpp:836-872` | `ArrayDim`, `ElementSize`, `SaveFlags`, `RepIndex`, `RepNotifyFunc`, `BlueprintReplicationCondition` | **нет** |
| `UStruct::Serialize` | `Class.cpp:2003-2199` | `SuperStruct`, `Children` / `ChildArray`, `ScriptBytecodeSize`, `ScriptStorageSize`, `ScriptAndPropertyObjectReferences` | **нет** (`PropertiesSize` и `MinAlignment` отсутствуют) |
| `UClass::Serialize` | `Class.cpp:5269-5542` | `FuncMap`, `SavedClassFlags`, `ClassFlags`, `ClassWithin`, `ClassConfigName`, `NumInterfaces`, `ClassGeneratedBy`, `SerializedInterfaces`, `Interfaces`, `ClassDefaultObject`, `SparseClassDataStruct`, … | **нет** офсетов свойств |

Подкрепляющие проверки того же вопроса, каждая способна дать положительный ответ и не дала:

1. **Поиск по всему дереву.** `grep -rn "Ar << PropertiesSize\|Ar << MinAlignment\|<< Offset_Internal"`
   по всем `*.cpp`/`*.h` в `Engine/Source` — **0 совпадений**.
2. **Байткод не несёт офсетов.** Опкоды доступа к переменной — `EX_LocalVariable`,
   `EX_InstanceVariable`, `EX_DefaultVariable`, `EX_LocalOutVariable`,
   `EX_ClassSparseDataVariable`, `EX_PropertyConst` — все сериализуются через одну макро-ветку
   `XFER_PROP_POINTER` (`Runtime/CoreUObject/Public/UObject/ScriptSerialization.h:236-245`), а это
   `XFERPTR(FProperty*)` (`:153`, тело `:107-125`): в поток идёт **ссылка на объект свойства**, не
   число. На исполнении `execInstanceVariable` читает эту ссылку и берёт адрес через
   `VarProperty->ContainerPtrToValuePtr<uint8>(P_THIS)`
   (`Runtime/CoreUObject/Private/UObject/ScriptCore.cpp:2223`), то есть
   `(uint8*)ContainerPtr + Offset_Internal + …` (`UnrealType.h:633`) — офсет из объекта в памяти.
   Единственное слово «Offset» во всём `ScriptSerialization.h` — `EX_SkipOffsetConst` (`:372`), и
   это смещение в байткоде, а не в памяти.
3. **Unversioned-поток не несёт офсетов.** Схема строится **в рантайме** обходом
   `Struct->PropertyLink` / `PropertyLinkNext`
   (`Runtime/CoreUObject/Private/Serialization/UnversionedPropertySerialization.cpp:331` и `:497`), а
   офсет каждого сериализатора — это `Property->GetOffset_ForInternal() + Property->ElementSize * InArrayIndex`
   (`:52`), взятый из уже слинкованного `FProperty`. На диске лежит только цепочка фрагментов
   `(SkipNum, ValueNum)` (`:569-598`) — чистая позиционная адресация, без имён и без офсетов.

**Два честных исключения. Ни одно из них не является офсетом свойства.**

**(а) `UFunction`: офсеты параметров сериализуются — но только при дублировании в памяти.**
`Class.cpp:6884-6891` стримит `NumParms`, `ParmsSize`, `ReturnValueOffset`, `FirstPropertyToInit`
под условием `if ((Ar.GetPortFlags() & PPF_Duplicate) != 0)`. `PPF_Duplicate` — это копирование
объекта в памяти (editor-side reinstancing), не сохранение и не загрузка пакета. На обычной
загрузке идёт `else`, и там `InitializeDerivedMembers()` (`:6894-6897`), которая пересчитывает эти
поля из офсетов, только что назначенных `Link`: `ParmsSize` на `:6815`, `ReturnValueOffset` на
`:6818`, оба из `Property->GetOffset_ForUFunction()` (`Class.cpp:6803-6819`). Комментарий над блоком
в сериализаторе — «`// Precomputation.`».

Это исключение стоит выписать именно потому, что оно **могло** бы опровергнуть вывод и не
опровергает: код, пишущий офсет в архив, в движке есть, и надо было проверить, тот ли это архив.

**(б) `FImplementedInterface::PointerOffset` сериализуется безусловно.**
`Class.cpp:5634-5641`, строка `:5637`: `Ar << A.PointerOffset;`. Это смещение подобъекта интерфейса
внутри объекта (C++ vtable displacement), а не офсет свойства, и на пути раскладки дочерних
свойств он не участвует. Что именно лежит в этом поле у cooked BPGC этой игры — **не проверено**;
см. §5.

**Ответ на вопрос 3.** В cooked-пакет офсет свойства **не пишется**: ни в записи `FProperty`, ни в
записи `UStruct`/`UClass`, ни в байткоде, ни в unversioned-потоке значений. Обратно читать нечего.
Единственный код в движке, который вообще стримит офсеты (`UFunction`), закрыт условием
`PPF_Duplicate`, то есть работает при копировании в памяти, а не при сохранении пакета; на загрузке
он их пересчитывает.

---

### 4. Вопрос 4: если размер родителя разошёлся между cook и load

**Ни проверки, ни расхождения — пересчёт.** Сравнивать нечего: размер родителя на момент cook
нигде не записан (§3). Код, который решает:

* `Class.cpp:800-804` — стартовое значение раскладки берётся у живого родителя;
* `Class.cpp:782-785` — родитель до этого доведён `Ar.Preload` до финального состояния;
* `Property.cpp:1351` — каждое свойство кладётся на выровненную границу текущего накопленного размера.

Если настоящий родитель окажется на N байт больше или меньше нашего представления о нём, все
собственные свойства дочернего класса просто получат офсеты, сдвинутые на соответствующую величину,
и это будут **правильные** офсеты для настоящего родителя.

Единственный жёсткий контроль размера в этой области — `Class.cpp:3484`,
`checkf(Stride == ClearedSize && PropertiesSize == ClearedSize, TEXT("C++ and the property system
struct size mismatch for %s …"))`. Он сравнивает C++ `sizeof` **native** структуры с её же
отражённым размером внутри одной и той же сборки. Он не сравнивает cook-time с load-time и не
может: у него нет ни одной cook-time величины.

**Но у вопроса 4 есть вторая половина, и там ответ другой — «тихое расхождение».**

Речь про **значения по умолчанию** (CDO и дефолты компонентов), а не про офсеты. В режиме
unversioned property serialization значение сопоставляется свойству **по позиции** в рантайм-схеме:
схема — это обход `PropertyLink` (`UnversionedPropertySerialization.cpp:331`/`:497`), поток —
цепочка `(SkipNum, ValueNum)` (`:569-598`). Ни имён, ни типов в потоке нет.

Проверки целостности схемы в cooked-рантайме **нет**: `SchemaHash` объявлен внутри
`#if WITH_EDITORONLY_DATA` (`:319-321`), считается только под тем же гейтом (`:350-358`), а
`GetSchemaHash` целиком закрыт `#if WITH_EDITORONLY_DATA` (`:967-976`). В пакет он не пишется и при
загрузке не сверяется. Единственное место, где хэши вообще сравниваются, — отладочная команда
`DumpClassSchemas` (`:978-1012`), тоже editor-only.

Уточнение, которое стоит сделать точно, а не грубо: `UStruct::Link` строит `PropertyLink` через
`TFieldIterator<FProperty> It(this)` (`Class.cpp:948`), у которого по умолчанию
`EFieldIterationFlags::Default = IncludeSuper | IncludeDeprecated`
(`UnrealType.h:6724-6734`), и итератор идёт «сначала свой класс, потом родители» — что и записано в
комментарии `UnrealType.h:179` («from most-derived to base»). Значит **собственные** свойства
дочернего класса стоят в схеме **первыми**, и расхождение в количестве свойств родителя сдвигает
позиции свойств **родителя**, а не дочерних. Это делает опасность 1 менее катастрофичной, чем
«поедет всё», но не менее реальной: унаследованные значения по умолчанию поедут молча.

**Ответ на вопрос 4.** Для того, о чём спрашивает CK-04 — офсеты — исход **recompute**, и решают
это `UStruct::Link` (`Class.cpp:800-804`) вместе с `FProperty::SetupOffset` (`Property.cpp:1351`).
Отказа не будет: не будет и повода для отказа. Для соседнего вопроса — раскладки значений
по умолчанию в unversioned-режиме — исход **silent mismatch**, потому что позиционная схема ничем не
подписана в cooked-сборке. Разводить эти два ответа обязательно: слитый вердикт «офсеты
пересчитываются, значит всё хорошо» был бы неправдой.

---

### 5. Что осталось `UNKNOWN`, с названным способом закрытия

| ID | Вопрос | Почему не закрыт | Чем закрывается |
|---|---|---|---|
| CK-04-U1 | Что лежит в `FImplementedInterface::PointerOffset` у cooked BPGC этой игры и влияет ли оно на что-нибудь при загрузке нашего пакета | это единственный офсет, который действительно попадает в cooked-пакет (`Class.cpp:5637`), а читаемого cooked-пакета в установке нет ни одного (CK-01, D-02) | разбор **любого** cooked BPGC-пакета. Маршрут появился в этом же репозитории и его надо использовать, а не ждать: в `research/evidence/CK-COOK/` есть приготовленные пакеты `BP_RefChild` / `BP_RefParent` (артефакты параллельной работы, содержимое здесь не пересказывается). Значение сравнить с тем, что кладёт native-путь (`UObjectGlobals.cpp:6301`) |
| CK-04-U2 | Использует ли эта сборка unversioned property serialization | это **CK-01**, и он из `MISERY-Windows.pak` не отвечается ни в какую сторону: cooked-пакетов там 0 | MK-2 (наш пакет + наши парсеры) или чтение флага сборки через `binary-analysis`; от CK-04 не зависит |
| CK-04-U3 | Совпадает ли фактическое поведение образа с прочитанной цепочкой | статически недостижимо: §10.5 требует `runtime-reflection` для утверждения «функция делает Z» | **RT-CK-04**, §6 |

---

### 6. RT-CK-04 — названный runtime-тест, который подтверждает или опровергает

`plan.md` §14.7 прямо запрещает считать SP-1 заменой E-3a/E-3b, поэтому здесь не «дальнейшая
работа», а конкретный тест с предсказанием и с условием опровержения.

**Форма A (дешёвая, только наблюдение; требует M3 / I-04..I-06).** Через ERI на работающей игре
прочитать для одного BPGC `C`, унаследованного от native-класса `P`:

* `P->PropertiesSize`, `P->MinAlignment`;
* для каждого собственного свойства `C` по порядку `ChildProperties`: `Offset_Internal`,
  `ElementSize`, `ArrayDim`, `GetMinAlignment()`;
* `C->PropertiesSize`.

*Предсказание, если пересчёт верен:* первое собственное свойство лежит по
`Align(P->PropertiesSize, align₀)`; каждое следующее — по
`Align(prevOffset + prevElementSize·prevArrayDim, alignᵢ)`; и
`C->PropertiesSize == lastOffset + lastElementSize·lastArrayDim`.
*Опровержение:* любое собственное свойство `C` с офсетом **меньше** `P->PropertiesSize`, либо
пропуск, который не объясняется ни одним выравниванием из наблюдённых.

Форма A подтверждает **арифметику**, но не отличает «пересчитано при загрузке» от «запечено
правильно»: если stub совпал с настоящим родителем, оба объяснения дают те же числа.

**Форма B (решающая; это MK-2 + MK-3 с одной лишней переменной).** Приготовить **два** BP от одного
и того же native-родителя, от stub-ов, различающихся **только** суммарным размером родителя:
в stub `S₂` добавить фиктивное `UPROPERTY`-заполнение так, чтобы `sizeof` вырос на известное `Δ`,
при **неизменном** списке свойств, которые BP использует. Загрузить оба в настоящей игре и
прочитать офсеты собственных свойств.

* *Если офсеты пересчитываются:* оба пакета дают **одинаковые** офсеты, равные
  `Align(P_настоящий->PropertiesSize, …)`. Размер stub-а не влияет ни на что.
* *Если офсеты запекаются:* офсеты из `S₂` больше на `Δ`, и как минимум один из двух пакетов читает
  чужую память — это и есть отказ, которого боится §14A.3 опасность 2.

Форма B стоит ровно одну дополнительную сборку stub-а поверх того, что MK-3 делает и так, и
проверяет **точно ту** опасность, ради которой задан CK-04. Пока она не выполнена, вердикт §0
остаётся ожиданием.

**Что RT-CK-04 не проверяет** — раскладку значений по умолчанию (§4, вторая половина). Для неё
нужен отдельный тест: переопределить в BP унаследованное свойство и прочитать его значение в
игре (это MK-4 из `plan.md` §14A.5).

---

### 7. Что CK-04 снимает и что не снимает в §14A

| §14A.3 | Опасность | Снимает ли CK-04 |
|---|---|---|
| 1 | Unversioned property serialization: идентификация свойств по порядку/индексу | **Нет.** Не зависит от офсетов вовсе. Остаётся за CK-01 + I-06 (порядок из reflection). §4 уточняет её форму: страдают значения **родителя**, потому что свои идут в схеме первыми |
| 2 | **Размер родительского класса** | **Да, ожидаемо снимает** — при подтверждении RT-CK-04. Требование к stub-у смещается с «побайтово совпасть по размеру» на «совпасть по составу, порядку и типам» |
| 3 | Сигнатуры native-функций | **Нет**, но §3(а) даёт полезное: `ParmsSize` и `ReturnValueOffset` тоже пересчитываются на загрузке (`Class.cpp:6894-6897`, `:6803-6819`). Значит и здесь критичен **порядок и типы** параметров, а не их офсеты. Это остаётся за I-05 |
| 4 | Custom versions | Нет, CK-05 |
| 5 | Настройки cook | Нет, CK-06 |
| 6 | Версия редактора | Нет, E-7 |
| 7 | Полнота stub-ов | Нет, CK-07 |

**Для триггера `plan.md` §14.7 условие 3** («SP-1 не дал уверенного отрицательного ответа ни по
E-3a, ни по CK-04») со стороны CK-04 **выполнено**: ответ положительный, а не отрицательный.
Решение по D-06 это условие не закрывает целиком — нужна ещё половина про E-3a.

---

### 8. Градация

Записи разведены по `plan.md` §10.3: примитивные чтения отдельно от интерпретаций, утверждение о
движке отдельно от утверждения об образе, и оба отдельно от утверждения об **игре**.

#### 8.1 Класс P — буквальные чтения образа

Метод: `python tools/static/link_path_probe.py <образ> --ue-root <дерево UE 5.4.4> --install-dir <корень установки>`.
Каждое чтение выполнено повторно из свежего дескриптора в том же прогоне и совпало; весь прогон
выполнен дважды и дал идентичный вывод, кроме `generated_at`.

| Утверждение | Класс | Level | Conf. | Oracle | Метод | Build | Evidence |
|---|---|---|---|---|---|---|---|
| 118 байт по смещению 98 927 520 файла `MISERY/Binaries/Win64/MISERY-Win64-Shipping.exe` начинаются с `27 00 53 00 74 00 72 00 75 00 63 00 74 00 20 00` | P | OBSERVED | 0.99 | `binary-analysis` | прогон `python tools/static/link_path_probe.py MISERY/Binaries/Win64/MISERY-Win64-Shipping.exe --ue-root <дерево UE 5.4.4> --install-dir <корень установки>`, затем чтение поля `literal_reads[]` по ключу `offset`/`length`; **метод перезапущен и результат воспроизведён**: инструмент перечитывает каждое смещение из нового дескриптора в том же прогоне, и весь прогон выполнен дважды (run1/run2) с идентичным выводом | `build_key=sha256:0eef3715244b467c830022c4260a0e2c29c7def1429cb34aa37fdf9b7e14a383` | `research/evidence/CK-04/link-path-shipping.json` |
| 120 байт по смещению 99 068 944 того же файла начинаются с `49 00 6e 00 76 00 61 00 6c 00 69 00 64 00 20 00` | P | OBSERVED | 0.99 | `binary-analysis` | прогон `python tools/static/link_path_probe.py MISERY/Binaries/Win64/MISERY-Win64-Shipping.exe --ue-root <дерево UE 5.4.4> --install-dir <корень установки>`, затем чтение поля `literal_reads[]` по ключу `offset`/`length`; **метод перезапущен и результат воспроизведён**: инструмент перечитывает каждое смещение из нового дескриптора в том же прогоне, и весь прогон выполнен дважды (run1/run2) с идентичным выводом | `build_key=sha256:0eef3715244b467c830022c4260a0e2c29c7def1429cb34aa37fdf9b7e14a383` | `research/evidence/CK-04/link-path-shipping.json` |
| В файле `Engine/Source/Runtime/CoreUObject/Private/UObject/Property.cpp` дерева UE 5.4.4 строка 1351 существует и содержит текст `Offset_Internal = Align(OwnerStruct->GetPropertiesSize(), GetMinAlignment());` | P | OBSERVED | 0.99 | `filesystem` | чтение строки по её номеру из файла дерева UE, выполняемое инструментом на каждом запуске (`needles[].source_line`, `needles[].text`); **метод перезапущен и результат воспроизведён**: run1/run2 дали одинаковые номер строки и текст | — (утверждение о дереве UE, не о сборке игры) | `research/evidence/CK-04/link-path-shipping.json`, `ue_source_tree` |
| В файле `Engine/Source/Runtime/CoreUObject/Private/UObject/Property.cpp` строка 867 существует и содержит текст `Offset_Internal = 0;` | P | OBSERVED | 0.99 | `filesystem` | чтение строки по её номеру из файла дерева UE, выполняемое инструментом на каждом запуске (`needles[].source_line`, `needles[].text`); **метод перезапущен и результат воспроизведён**: run1/run2 дали одинаковые номер строки и текст | — | `research/evidence/CK-04/link-path-shipping.json` |
| `Engine/Build/Build.version` дерева UE объявляет `Changelist 35576357`, `BranchName ++UE5+Release-5.4`, `IsPromotedBuild 1` | P | OBSERVED | 0.99 | `filesystem` | чтение `Engine/Build/Build.version` как JSON инструментом на каждом запуске (`ue_source_tree.build_version`); **метод перезапущен и результат воспроизведён**: run1/run2 дали одинаковые значения | — | `research/evidence/CK-04/link-path-shipping.json`, `ue_source_tree.build_version` |

Класс P здесь допустим по `plan.md` §10.3 v2.4 потому, что в утверждениях об образе указаны и
смещение, и длина, и не назван ни один смысл прочитанного: что это за байты — сказано ниже, в
записях класса I, и оценено ниже.

#### 8.2 Класс I — интерпретации

| # | Утверждение | Класс | Level | Conf. | Oracle | Метод | Build | Evidence |
|---|---|---|---|---|---|---|---|---|
| CK-04-2 | **Исправлено 2026-08-23** (адверсариальное ревью нашло недосчитанное исключение — см. LOG-0038): **В движке UE 5.4.4 на CL 35576357** офсеты собственных свойств класса назначаются в `UStruct::Link` при `bRelinkExistingProperties == true` от текущего `PropertiesSize` владельца (`Class.cpp:800-804`, `:827`; `Property.cpp:1351`); ни `Offset_Internal`, ни `PropertiesSize`, ни `MinAlignment` не сериализуются, и `Offset_Internal` обнуляется при загрузке свойства (`Property.cpp:867`). Утверждение сужено до этих трёх идентификаторов: `FBoolProperty::Serialize` (`PropertyBool.cpp:164-187`) безусловно стримит `ByteOffset` — тем же способом отбрасываемый при загрузке (`SetBoolSize` перевычисляет его на `:113`/`:122`), но это третье, ранее не учтённое исключение, а не опровержение вывода | I | INFERRED | 0.79 | `external-doc` + `filesystem` | (1) проход по цепочке вызовов с цитированием файла и строки на каждом шаге; (2) механическое извлечение списка членов, реально проходящих через `Ar <<`, в трёх сериализаторах (`FProperty::Serialize`, `UStruct::Serialize`, `UClass::Serialize`), плюс поиск `Ar << PropertiesSize` / `<< Offset_Internal` / `<< MinAlignment` по всему дереву — **0 совпадений для этих трёх идентификаторов**; поиск не покрывал сериализаторы подклассов `FProperty` (`FBoolProperty` и другие) | — | `research/evidence/CK-04/link-path-shipping.json`, `source_probes` |
| CK-04-3 | Образ `MISERY/Binaries/Win64/MISERY-Win64-Shipping.exe` (sha256 = `build_key`) **содержит**, со ссылкой из исполняемой секции, диагностический литерал `Class.cpp:855` — он стоит внутри ветки `bRelinkExistingProperties` функции `UStruct::Link` — и литерал `Property.cpp:1340`, единственный вызывающий которого во всём дереве — `FProperty::SetupOffset` | I | INFERRED | 0.88 | `binary-analysis` + `external-doc` | (1) дерево UE даёт текст литерала, его файл, строку и объемлющую функцию (`external-doc`); (2) образ даёт байты по смещению и RIP-относительную ссылку на них из секции с `IMAGE_SCN_MEM_EXECUTE` — **другой источник данных**, а не второе прочтение того же (`binary-analysis`). Шесть проб опровержения, все PASS | `build_key=sha256:0eef3715244b467c830022c4260a0e2c29c7def1429cb34aa37fdf9b7e14a383` | `research/evidence/CK-04/link-path-shipping.json` |
| CK-04-4 | **Ожидание для этой сборки:** офсеты собственных свойств дочернего BP-класса пересчитываются при загрузке от размера настоящего родителя, а не запекаются при cook | I | INFERRED | 0.79 | `binary-analysis` + `external-doc` | (1) чтение first-party исходников на changelist сборки; (2) подтверждение присутствия и достижимости этого кода в самом образе. Два разных источника данных. Runtime-наблюдений — **ноль** | `build_key=sha256:0eef3715244b467c830022c4260a0e2c29c7def1429cb34aa37fdf9b7e14a383` | `research/evidence/CK-04/link-path-shipping.json`, `research/evidence/CK-04/link-path-development.json` |
| CK-04-5 | Для native-класса в cooked-сборке офсет свойства — это `offsetof` компилятора, попавший в исполняемый файл через `FPropertyParams`, а `PropertiesSize` — его `sizeof`; штатная регистрация не пересчитывает их, так как `StaticLink()` вызывается со значением по умолчанию `false` | I | INFERRED | 0.75 | `external-doc` + `filesystem` | один источник данных (дерево UE): цепочка `ObjectMacros.h:2080` → `Class.cpp:618` → `Property.cpp:773` → `UObjectGlobals.cpp:6309` → `Class.h:490` → `Class.cpp:877` → `UnrealType.h:353`. Подтверждения в образе для **этого** пути нет: ветка без пересчёта не содержит уникального литерала, который можно было бы найти | — | этот документ, §2.2 |

**Почему CK-04-2 и CK-04-4 не выше 0.79.** Не из-за слабости доводов, а по правилу о **виде**
доказательства:

* CK-04-2 опирается на **один источник данных** — дерево UE. §10.3 прямо говорит: «независимых =
  разные источники данных, а не два прочтения одного файла». Два разных способа прочитать то же
  дерево не дают второго метода, поэтому полоса ≥0.80 закрыта.
* CK-04-4 имеет два независимых источника, но §10.2 требует для полосы 0.80–0.94 «два+ независимых
  подтверждения, **включая одно runtime-наблюдение**», а его нет. Это ограничение по виду
  доказательства, а не по количеству, и обойти его аккуратной формулировкой нельзя.

**Почему CK-04-3 — 0.88, а не 0.79 или 0.95 — и почему это не противоречит потолку CK-04-2/CK-04-4
(два независимых ревью спорили об этом 2026-08-23, LOG-0038 и LOG-0039).** Строка §10.2 «полоса
0.80–0.94: два+ независимых подтверждения, включая одно runtime-наблюдение» — сокращённая форма.
Полный текст правила, `plan.md` §10.3 критерий 2: «≥1 из методов — runtime-наблюдение (для
утверждений о **runtime-структурах/поведении**) **или** проверка формата данных (для утверждений
о **форматах**)». CK-04-3 — утверждение о формате: «этот литерал физически присутствует в образе
и на него физически ссылается код». Это структурный факт о скомпилированном файле, а не
наблюдение за исполнением, и он закрывается вторым методом ровно того типа, который правило для
форматов и называет — разбором PE и арифметикой RIP-относительных ссылок. CK-04-2 и CK-04-4
капнуты **по другой причине каждый**, а не по той же: CK-04-2 — потому что у него **один**
источник данных (дерево UE), а не потому что отсутствует runtime-наблюдение; CK-04-4 — потому что
это утверждение о **поведении** загрузчика («функция X делает Z», `plan.md` §10.5, требует
`binary-analysis` **и** `runtime-reflection` обязательно), и там runtime-альтернативы формату
действительно нет. Оставшийся зазор для CK-04-3 — «литерал присутствует и на него ссылаются» →
«объемлющая функция присутствует» взят по исходникам, а не по дизассемблированному коду — держит
запись ниже 0.95, и это единственная причина, по которой она не выше. Дизассемблирование функции
вокруг найденной ссылки (S-05/S-06 в Ghidra) — способ поднять её дальше, а не способ удержать на
месте.

#### 8.3 Попытка опровержения — что мы бы увидели, если бы вывод был неверен

Сформулировано **до** измерения и выполнено как шесть машинных проб (все PASS в обоих образах;
`probes[]` в артефактах):

| Проба | Что бы её провал означал | Итог |
|---|---|---|
| `no_serializer_streams_the_offset` | `Ar << Offset_Internal` или `Ar << PropertiesSize` есть в сериализаторе → офсет **пишется** в пакет, и весь §2.3 неверен | PASS. Тест на сам механизм тоже есть: `tests/test_link_path_probe.py::LinkPathProbeTests::test_serializer_probe_catches_a_streamed_offset` подсаживает `Ar << Offset_Internal` в синтетическое дерево и требует, чтобы проба **упала** |
| `required_needles_unique` | литерал из ветки пересчёта отсутствует → эта ветка не была слинкована в образ | PASS: по одному вхождению каждого |
| `required_needles_referenced` | литерал есть, ссылок нет → он выжил как мёртвые данные, и его присутствие ничего не значит | PASS. Здесь метод и ошибся один раз, и был исправлен: первая версия декодировала только форму `lea reg,[rip+disp32]` и объявила литералы в 282-МБ образе недостижимыми. Настоящая причина — вторая форма: статическая запись лога в `.rdata`, первое поле которой — указатель на строку. Обе формы теперь декодируются и **считаются раздельно**; счёт заведомо неполный, и неполнота работает против вывода, а не за него |
| `compile_gating_consistent` | текст `checkf`/`ensureMsgf` найден там, где нет ни одного текста `UE_LOG(Fatal)` → модель компиляционного гейта перевёрнута, и тогда **все** отсутствия в этом прогоне нечитаемы | PASS, и картина различает конфигурации сама: в Shipping-образе найдены **только** два `Fatal`-литерала, в 282-МБ образе — все шесть, включая `checkf` |
| `negative_control` | заведомо мутированная строка «найдена» → матчер сообщает несуществующее | PASS: 0 вхождений |
| `required_needles_distinct_origin` | оба литерала происходят из одного файла → это одно наблюдение под двумя именами | PASS: `Class.cpp` и `Property.cpp` |

#### 8.4 Что именно измерено в двух образах

| Образ | Литералы `UE_LOG(Fatal)` | Литералы `checkf` / `ensureMsgf` / `UE_LOG(Error)` | Вердикт инструмента |
|---|---|---|---|
| `MISERY/Binaries/Win64/MISERY-Win64-Shipping.exe` — sha256 равен `build_key` | 2 из 2, каждый по одному вхождению, каждый со ссылкой `lea` из секции с флагом исполнения | 0 из 4 — ожидаемое чтение для сборки с выключенными `check` | `PATH_PRESENT_AND_REFERENCED` |
| `MISERY/Binaries/Win64/MISERY.exe` (282 МБ; статус этого образа и градуировка предположения «Development build» — решение **D-04** в `research/decisions.md`, здесь не пересказываются) | 2 из 2, через статические записи лога в `.rdata`, на которые есть `lea` | 4 из 4, включая «*we should not be loading any native classes*» (`Class.cpp:5368`) и «*C++ and the property system struct size mismatch*» (`Class.cpp:3484`) | `PATH_PRESENT_AND_REFERENCED` |

Второй образ — **подкрепление, а не основание**: `build_key` принадлежит первому. Его ценность в
том, что он показывает первым лицом слова движка про native-классы, которые в Shipping вырезаны
вместе с `checkf`, и что он независимо подтверждает модель компиляционного гейта.

#### 8.5 Артефакты и воспроизведение

```
research/evidence/CK-04/link-path-shipping.json          полный документ по образу build_key
research/evidence/CK-04/link-path-shipping-run1.log      прогон 1 (с записью артефакта)
research/evidence/CK-04/link-path-shipping-run2.log      прогон 2 (без записи) — вывод идентичен
research/evidence/CK-04/link-path-development.json       то же по 282-МБ образу (D-04)
research/evidence/CK-04/link-path-development-run1.log
research/evidence/CK-04/link-path-development-run2.log
tools/static/link_path_probe.py                          инструмент, только stdlib, read-only
tests/test_link_path_probe.py                            15 тестов + 8 subtests, синтетические PE и дерево
```

Ни один тест не открывает установку игры и не открывает дерево UE: и PE, и исходники в тестах
собираются побайтово во временном каталоге из **формата**, а не из кода инструмента. Инструмент
никогда не пишет внутрь установки — путь вывода проходит через `tools/inventory/pathguard.py`
(D-01).

---

### 9. Итог CK-04 одной таблицей

Последний столбец **ссылается на запись**, а не повторяет её оценку: `plan.md` §10.1 — пересказ
никогда не повышает градацию, и семь строк с переписанными от руки уровнями были бы семью
новыми записями без методов. Оценки живут в §8 и только там.

| Вопрос | Ответ | Кто решает | Градуировано в |
|---|---|---|---|
| 1. Native-класс в cooked-сборке: откуда офсет | из **исполняемого файла**: `offsetof`/`sizeof` компилятора, через `FPropertyParams`; регистрация не пересчитывает (`StaticLink()` по умолчанию `false`) | `ObjectMacros.h:2080`, `Class.cpp:618`, `Property.cpp:773`, `Class.h:490`, `Class.cpp:877` | запись `CK-04-5` |
| 2. Blueprint-класс: откуда офсет | **пересчитывается при загрузке** от `PropertiesSize` настоящего родителя | `Class.cpp:800-804`, `:827`; `UnrealType.h:358-362`; `Property.cpp:1351` | записи `CK-04-2`, `CK-04-4` |
| 3. Пишется ли офсет в cooked-пакет | **нет для `Offset_Internal`, `PropertiesSize`, `MinAlignment`** — ни в свойстве, ни в структуре, ни в байткоде, ни в unversioned-потоке. Единственный код, стримящий офсеты (`UFunction`), закрыт `PPF_Duplicate` и на загрузке пересчитывает. **Исправлено 2026-08-23** (LOG-0038): формулировка сужена — `FBoolProperty::Serialize` стримит `ByteOffset` безусловно (`PropertyBool.cpp:169`), и это офсет свойства в буквальном смысле; вывод не меняется, потому что он тоже отбрасывается на загрузке (`SetBoolSize`, `PropertyBool.cpp:113,122`), тем же способом, что и `Offset_Internal` | `Property.cpp:836-872`, `Class.cpp:2003-2199`, `ScriptSerialization.h:236-245`, `Class.cpp:6884-6897`, `PropertyBool.cpp:113,122,164-187` | запись `CK-04-2` |
| 4. Расхождение размера родителя | для офсетов — **пересчёт**, проверки нет и не нужно; для значений по умолчанию в unversioned-режиме — **тихое расхождение**, схема ничем не подписана в cooked-рантайме | `Class.cpp:800-804`, `Property.cpp:1351`; `UnversionedPropertySerialization.cpp:331`, `:497`, `:569-598`, `:967-976` | записи `CK-04-2`, `CK-04-4` |
| Есть ли этот код в этой сборке | **да** — оба обязательных литерала на месте по одному разу и достижимы из исполняемого кода | `research/evidence/CK-04/link-path-shipping.json` | запись `CK-04-3` |
| Подтверждение на уровне пакета | **Исправлено 2026-08-23** (LOG-0038): было заявлено недоступным на момент написания этого раздела — верно на ту дату (21:35), но с 21:48 того же дня существует `research/evidence/CK-COOK/ck04-child-parent-grown-vs-base.json` (собственный кук, `docs/modkit-...`/`research/modkit/cooker-comparison.md`), сравнивающий два `BP_RefChild.uasset` от выросшего и базового родителя: `uexp_size` 379 в обоих, `export_entry_stride` 96 в обоих, `uses_unversioned_properties = True`. Это пакетный, форматный (не runtime) второй метод именно для CK-04-4 — не использован при первой записи оценки, использование как второго метода класса I (§10.3 крит. 2, «проверка формата» вместо runtime-наблюдения) — следующий шаг, не выполнено этой правкой | `research/evidence/CK-COOK/ck04-child-parent-grown-vs-base.json` | не градуировано этой правкой; см. `NEW-16` |
| Закрывающий тест | **RT-CK-04**, форма B: два stub-а, различающихся только `sizeof` родителя | §6 | не выполнен, поэтому записи нет |

---

## E-3a — зависит ли регистрация `UClass` от происхождения контейнера?

Артефакты: `research/evidence/SP-1/`. Инструмент:
`tools/static/loader_admission_probe.py` (только stdlib, read-only, D-01/D-02).
Источник по движку — `D:\Program Files\UE_5.4`, `Engine/Build/Build.version` объявляет 5.4.4,
`Changelist` **35576357**, `BranchName` `++UE5+Release-5.4`, `IsPromotedBuild` 1: тот же CL, что
записан для сборки игры в `research/unreal/engine-version.json`. Все ссылки вида
`Runtime/…:NNN` — пути внутри `Engine/Source` и номера строк именно этого дерева. Чтение
исходников — оракул `external-doc`: он доказывает, **как устроен UE 5.4.4**, и по §10.5 ничего
не доказывает про эту сборку, поэтому каждое утверждение про образ подтверждается отдельным
измерением (§E-3a.6).

### 1. Вопрос распадается на три, и они закрываются по-разному

Формулировка §14.7 — «если загрузка пакета идёт общим путём независимо от обслуживающего
контейнера, класс из внешнего контейнера регистрируется так же, как из штатного» — содержит три
разных вопроса:

| | Вопрос | Чем закрывается |
|---|---|---|
| **Q1** | есть ли в цепочке «монтирование → загрузка пакета → создание и регистрация класса» хоть одно ветвление по тому, из какого контейнера пришёл пакет? | чтение исходников + аргумент об отсутствии различающего входа на границе |
| **Q2** | какая из двух цепочек (legacy pak / IoStore) в **этой** сборке вообще принимает пакеты? | измерение образа и данных установки |
| **Q3** | есть ли на цепочке шлюз — подпись, allowlist, chunk-id, shipping-define, — который отвергнет чужой контейнер? | целенаправленная охота на опровержение |

Ответ по Q1 без ответа по Q2 бесполезен: «общий путь» ничего не даёт, если внешний контейнер до
этого пути не доходит. Ответ по Q3 может обнулить оба.

### 2. Цепочка A — как смонтированный контейнер становится источником пакетов

**A1. Обнаружение.** `FPakPlatformFile::Initialize`
(`Runtime/PakFile/Private/IPlatformFilePak.cpp:8202`) в конце вызывает `GetPakFolders`
(там же, `:8132`) и `MountAllPakFiles` (`:8803`). `GetPakFolders` добавляет **три жёстко
заданных каталога** — `{ProjectContentDir}Paks/`, `{ProjectSavedDir}Paks/`,
`{EngineContentDir}Paks/` (`:8147-8149`) — и, только под `#if !UE_BUILD_SHIPPING`, каталоги из
`-pakdir=` (`:8137`). `MountAllPakFiles` → `FindAllPakFiles` → `FindPakFilesInDirectory`
(`:8071`) собирает всё, что подходит под `ALL_PAKS_WILDCARD`, а он определён как `"*.pak"`
(`:81`). Списка разрешённых имён нет: любой `*.pak` в этих каталогах будет предъявлен к
монтированию.

**A2. Приём файла.** `FPakPlatformFile::Mount` (`:8469`). Проверок ровно три:
`LowerLevel->FileExists` (`:8474`), `FPakFile::IsValid()` (`:8477`) и наличие ключа для
`EncryptionKeyGuid` контейнера (`:8479`) — при отсутствии ключа монтирование **откладывается**
(`:8532`, `PendingEncryptedPakFiles`), а не запрещается. Единственное правило, зависящее от
имени файла, — суффикс `_P.pak` (`:8486-8511`), и оно меняет только `PakOrder`.

**A3. Раздвоение путей — самое важное место в цепочке A.** Внутри того же `Mount`, если
`IoDispatcherFileBackend` создан, берётся **файл-сосед с тем же basename и расширением
`.utoc`** (`:8564`). Если он есть — `IoDispatcherFileBackend->Mount(...)` и затем
`PackageStoreBackend->Mount(Pak->IoContainerHeader.Get(), PakOrder)` (`:8570-8574`). Если его
нет — `bIoStoreSuccess = false` и запись «IoStore container … not found» (`:8603-8604`).
Асимметрия: `bPakSuccess` при этом остаётся `true`, запись уже добавлена в `PakFiles`, то есть
**файлы из такого pak доступны, а пакетов он не даёт**, хотя `Mount` вернёт `false`
(`:8678`, `return bPakSuccess && bIoStoreSuccess`).

**A4. Приём контейнера IoStore.** `FFileIoStore::Mount`
(`Runtime/PakFile/Private/IoDispatcherFileBackend.cpp:1284`) → `FFileIoStoreReader::Initialize`
(`:671`) → `FIoStoreTocResource::Read` (`Runtime/Core/Private/IO/IoStore.cpp:3145`). Проверки:
magic (`:3164`), `TocHeaderSize == sizeof(FIoStoreTocHeader)` (`:3169`),
`TocCompressedBlockEntrySize` (`:3174`), версия не ниже `DirectoryIndex` и не выше `Latest`
(`:3179-3189`) и подпись (см. §E-3a.5, строка **G3**). `ContainerId` читается
(`IoDispatcherFileBackend.cpp:748`), но ни с чем не сверяется; читатели вставляются в
`IoStoreReaders` в порядке убывания `Order` (`:1320-1328`).

**A5. Package store.** `FFilePackageStoreBackend::Mount`
(`Runtime/PakFile/Private/FilePackageStore.cpp:387`) кладёт `FIoContainerHeader` в
`MountedContainers` и сортирует их `StableSort` по `(Order desc, Sequence desc)` (`:391-399`).
`Update` (`:558`) разворачивает **все** смонтированные контейнеры в **одну плоскую** карту
`PackageEntries` типа `FPackageId → FEntryHandle` (`:600-651`, `:696-704`).

### 3. Цепочка B — как запрос пакета находит источник

**B1. Выбор загрузчика, один раз на процесс.** `InitAsyncThread`
(`Runtime/CoreUObject/Private/Serialization/AsyncPackageLoader.cpp:186`). В не-редакторной
сборке ветвление сводится к одному предикату: существует ли чанк
`CreateIoChunkId(0, 0, EIoChunkType::ScriptObjects)` (`:202`). Если да —
`MakeAsyncPackageLoader2(IoDispatcher)` (`:212-215`), причём с `InUncookedPackageLoader ==
nullptr`. Если нет — `FAsyncLoadingThread` (`:220-223`). **Это «или-или», принимаемое на
старте, а не per-package fallback.**

**B2. Разрешение запроса в AsyncLoading2.**
`FAsyncLoadingThread2::CreateAsyncPackagesFromQueue` (`AsyncLoading2.cpp:4376-4460`): имя
пакета → `FPackageId::FromName(PackageNameToLoad)` (`:4400`) →
`PackageStore.GetPackageRedirectInfo` (`:4406`) → `PackageStore.GetPackageStoreEntry` (`:4414`).
`FPackageStore::GetPackageStoreEntry` (`Runtime/Core/Private/IO/PackageStore.cpp:161`)
опрашивает backend'ы по приоритету; `FFilePackageStoreBackend::GetPackageStoreEntry`
(`FilePackageStore.cpp:331`) делает **один** `PackageEntries.Find(PackageId)`. При `Missing` —
`QueueMissingPackage` (`:4456-4459`, тело `:9213`), и загрузка завершается отказом.

**B3. Файловый fallback вырезан препроцессором.** Между B2 и решением есть блок
`#if ALT2_ENABLE_LINKERLOAD_SUPPORT` с `TryGetPackagePathFromFileSystem` (`:4429-4435`),
который при находке файла на диске выставляет `PackageStatus = Ok` в обход package store. Сам
флаг: `#ifndef ALT2_ENABLE_LINKERLOAD_SUPPORT` / `#define ALT2_ENABLE_LINKERLOAD_SUPPORT
WITH_EDITOR` (`:264`). В cooked-сборке `WITH_EDITOR == 0`. Флаг объявлен через `#ifndef`,
поэтому проект теоретически может его переопределить — это проверено в образе, §E-3a.6 M4/M5.

**B4. Данные читаются по chunk id, не по контейнеру.** Чанк пакета —
`CreateIoChunkId(PackageId.Value(), Index, EIoChunkType::ExportBundleData)`
(`AsyncLoading2.cpp:1945`, `:5348`). `FFileIoStore::Resolve`
(`IoDispatcherFileBackend.cpp:1382-1386`) идёт по `IoStoreReaders` в порядке `Order` и берёт
**первый** контейнер, у которого этот chunk id есть.

**B5. Mount point в cooked-сборке не требуется.** `UE_SUPPORT_FULL_PACKAGEPATH` определён как
`WITH_EDITOR` (`Runtime/CoreUObject/Public/Misc/PackagePath.h:16`), поэтому в игре активен
облегчённый вариант `FPackagePath`
(`Runtime/CoreUObject/Private/Misc/PackagePath.cpp:1014-1210`), и
`FPackagePath::TryFromPackageName` (`:1046-1056`) проверяет **только текстовую форму** имени
через `FPackageName::IsValidTextForLongPackageName` (`PackageName.cpp:1194`): ведущий слэш, нет
хвостового слэша, нет `//`, длина ≥ 4. Зарегистрированный mount point не нужен. Предупреждение
«assets in this pak file may not be accessible until a corresponding UFS Mount Point is added
through `FPackageName::RegisterMountPoint`» (`IPlatformFilePak.cpp:8659-8666`) относится к
**файловому** доступу и является `Display`-логом, а не отказом.

### 4. Цепочка C — где создаются и регистрируются классы

**C1. Native-классы (компилируемые в образ).** `IMPLEMENT_CLASS`
(`Runtime/CoreUObject/Public/UObject/ObjectMacros.h:2095`, **исправлено 2026-08-23**: было
ошибочно `:2094` — пустая строка/комментарий; сам вызов `GetPrivateStaticClassBody` внутри
`IMPLEMENT_CLASS_NO_AUTO_REGISTRATION`, которую `IMPLEMENT_CLASS` разворачивает первой строкой,
лежит на `:2075-2076`) → `GetPrivateStaticClass` →
`GetPrivateStaticClassBody` (`Runtime/CoreUObject/Private/UObject/Class.cpp:6685`) →
`InitializePrivateStaticClass` (`Class.cpp:107`) → `UObjectBase::Register(PackageName, Name)`
(`Runtime/CoreUObject/Private/UObject/UObjectBase.cpp:463`) → `UObjectForceRegistration`
(`:540`) → `UObjectBase::DeferredRegister` (`:173`), который делает `CreatePackage(PackageName)`,
ставит `PKG_CompiledIn` и вызывает `AddObject` (`:176-187`). Аргументы `PackageName` и `Name` —
**строковые литералы из образа** (`StaticPackage()` из `DECLARE_CLASS`,
`ObjectMacros.h:1783-1786`). Ни файла, ни контейнера, ни mount point в этой цепочке нет вообще;
`UPackage` здесь — объект в памяти, а не пакет на диске.

**C2. Классы, приходящие из пакета** (в первую очередь `UBlueprintGeneratedClass`) — обычные
exports. `FAsyncPackage2::EventDrivenCreateExport` (`AsyncLoading2.cpp:6549`) →
`StaticConstructObject_Internal(Params)` (`:6760`) — тот же вызов, что и у любого другого
объекта. Ветвления внутри: `FilterExport` по `EExportFilterFlags` (`:6566-6590`, различает
client/server и решается препроцессором), `Export.ClassIndex` / `Export.OuterIndex`
(`:6609-6610`), `Desc.bCanBeImported` и `Export.PublicExportHash` (`:6775`). `bCanBeImported`
в не-редакторной сборке равен `Request.CustomName.IsNone()` (`:583-610`, ветка `#else` на
`:608`) — свойство запроса, не контейнера.

**C3. Таблица script-объектов, к которой привязываются импорты пакета, строится из образа, а не
из контейнера.** `FAsyncLoadingThread2::NotifyRegistrationEvent` (`:8701`) →
`FGlobalImportStore::AddScriptObject` (`:1498-1522`). Чанк `ScriptObjects` из контейнера при
этом **не читается**: во всём дереве `Runtime` и `Developer` он упомянут в четырёх местах, и
все четыре — проверка существования (`AsyncPackageLoader.cpp:202`,
`EditorPackageLoader.cpp:35`, `Runtime/Core/Private/IO/IoDispatcher.cpp:984`,
`Runtime/RenderCore/Private/ShaderCodeLibrary.cpp:127`); запись — только в
`Developer/IoStoreUtilities`. В не-редакторной сборке `FindAllScriptObjects` вызывается лишь
под `#elif DO_CHECK` и только сверяет (`:4954-4966`).

### 5. Охота на опровержение

Искали не подтверждения, а шлюз. Восемь заявленных мест плюс два найденных по ходу:

| | Что искали | Что нашли | Меняет ли ответ |
|---|---|---|---|
| **G1** | container-id / chunk-id проверку | `ContainerId` читается (`IoDispatcherFileBackend.cpp:748`) и используется только чтобы собрать chunk id заголовка своего же контейнера (`:873`). `PakchunkIndex` берётся из **имени файла**: `FGenericPlatformMisc::GetPakchunkIndexFromPakFile` (`Runtime/Core/Private/GenericPlatform/GenericPlatformMisc.cpp:1994-2019`) распознаёт префикс `pakchunk<N>` и иначе даёт `INDEX_NONE`. Используется в `IsPakFileInstalled` (`IPlatformFilePak.cpp:5754`, платформенный chunk-install) и для области действия delete-record (`:268-269`) | **нет** |
| **G2** | подпись legacy pak | `bSigned = FCoreDelegates::GetPakSigningKeysDelegate().IsBound()` (`IPlatformFilePak.cpp:8230`); при `bSigned` читатель pak требует `.sig` через `FChunkCacheWorker`, и при его отсутствии `MakeArchive` отдаёт `nullptr` (`:5936-5971`). В установке **нет ни одного `.sig`** (53 файла, `install-inventory.json`) | **нет**, но условно — см. конец §E-3a.6 |
| **G3** | подпись IoStore (`FIoStoreTocHeader`) | `FIoStoreTocResource::Read`, `IoStore.cpp:3273`: `if (IsSigningEnabled() \|\| bIsSigned)`, и сразу `if (!bIsSigned) return FIoStatus(EIoErrorCode::SignatureError, TEXT("Missing signature"))` (`:3275-3277`); при `IsSigningEnabled()` — `ValidateContainerSignature` против публичного ключа (`:3294-3300`). `IsSigningEnabled` (`:61-68`) = `GetPakSigningKeysDelegate().IsBound()` под `#if UE_BUILD_SHIPPING`, иначе литеральный `false`. **Это единственный настоящий шлюз в цепочке.** В этой сборке он выключен — доказательство в конце §E-3a.6 | **нет**, но это главный кандидат, и его пришлось закрывать измерением |
| **G4** | allowlist mount point'ов | нет. Единственная проверка mount point — `Display`-лог (`IPlatformFilePak.cpp:8659-8666`), и в cooked-сборке путь пакета вообще не требует зарегистрированного корня (§E-3a.3 B5) | **нет** |
| **G5** | правило порядка, меняющее **семантику** | `GetPakOrderFromPakFilePath` (`IPlatformFilePak.cpp:8874-8895`) даёт 4 для `Content/Paks/<Project>-*`, 3 для `Content/`, 2 для `Engine/Content/`, 1 для `Saved/`, 0 иначе; `_P.pak` добавляет `100 × ChunkVersion` (`:8511`). Дальше порядок работает только как приоритет: `FindFileInPakFiles` берёт первое совпадение (`:246-305`), `FFileIoStore::Resolve` — первого читателя с этим chunk id (`:1384-1386`), а в package store при дубликате `FPackageId` побеждает запись из контейнера с более высоким `Order` (`Pairs` строятся в порядке `Order desc` — `FilePackageStore.cpp:600-651`; `SortBySlotIndex` использует `RadixSort32`, про который `Runtime/Core/Public/Templates/Sorting.h:431` пишет «Is stable»; `FPackageIdMap::Find` возвращает первое совпадение при линейном проходе от слота — `:155-194`) | **нет**, но следствие важное: приоритет даёт полное перекрытие пакета по имени |
| **G6** | shipping-define на цепочке | Есть, и все — **в сторону сужения диагностики и командной строки, а не приёма контента**: `-pakdir=` (`:8137`), `-paklist=` (`:8812`), `StartupPaksWildcard=` (`:8237`), `LookLooseFirst` (`:8240`), консольная команда `FPakExec` (`:8294`). Обратное направление одно — G3, который включается **только** в Shipping | **нет** (при выключенном G3) |
| **G7** | разница между приёмом пакета по IoStore и по legacy pak | **Есть, и она принципиальна.** В cooked-сборке (`WITH_EDITOR == 0`) `ALT2_ENABLE_LINKERLOAD_SUPPORT == 0`, `UncookedPackageLoader == nullptr`, и загрузчик выбирается один на процесс (§E-3a.3 B1, B3). Пакет попадает в загрузку **только** через `FPackageStore`, то есть только из `FIoContainerHeader` смонтированного IoStore-контейнера. Legacy pak в этом режиме — файловый контейнер: он отдаёт байты через `IPlatformFile`, и загрузчик пакетов к нему не обращается | **да — но не в сторону «нельзя», а в сторону «только одним способом»** |
| **G8** | `EncryptionKeyGuid` как шлюз | Не шлюз: несовпадение откладывает монтирование до появления ключа (`:8527-8543`), а нулевой GUID проходит без ключа (`:8479`). Для внешнего контейнера это означает «можно вообще не шифровать» | **нет** |
| **G9** *(найдено по ходу)* | несёт ли `FPackageStoreEntry` признак происхождения | Нет. В не-редакторной сборке структура состоит ровно из двух полей: `ImportedPackageIds` и `ShaderMapHashes` (`Runtime/Core/Public/IO/PackageStore.h:36-44`; остальные два — под `#if WITH_EDITOR`). Это самый сильный аргумент раздела: у кода после этой границы **нет различающего входа**, и вопрос «ветвится ли он по происхождению» превращается из «мы не нашли ветвления» в «ветвиться нечем» | **нет** |
| **G10** *(найдено по ходу)* | delete-record как семантика, а не приоритет | `FindFileInPakFiles` (`:246-305`) позволяет pak с более высоким `ReadOrder` **скрыть** файл из pak с меньшим, но только внутри одного `PakchunkIndex` (`:268-269`). Правило симметрично для всех pak и от происхождения не зависит | **нет** |

### 6. Что подтверждено в образе и в данных установки

Артефакты: `research/evidence/SP-1/toc-global.json`, `toc-misery-windows.json`,
`image-probe-shipping.json`, `image-probe-development.json`, `image-probe-bootstrap.json`.

**M1. Какой образ вообще запускается.** Разделено на две записи по §10.3: первая половина —
чтение, вторая — вывод.

> 94 байта по смещению 417 284 в `<install>/MISERY.exe` равны `4d00490053004500520059005c00420069006e00610072006900650073005c00570069006e00360034005c004d00490053004500520059002d00570069006e00360034002d005300680069007000700069006e0067002e00650078006500`, и 80 байт по смещению 418 284 в том же файле равны `42006f006f007400730074007200610070005000610063006b006100670065006400470061006d0065002d00570069006e00360034002d005300680069007000700069006e0067002e00650078006500`. *(класс P, OBSERVED, confidence 0.99, oracle: binary-analysis; метод — точный поиск заданной последовательности байт по всему файлу командой `tools/static/loader_admission_probe.py image <path>`, перезапущен и результат воспроизведён: оба диапазона прочитаны дважды и совпали байт-в-байт, артефакт `research/evidence/SP-1/image-probe-bootstrap.json`)*

Интерпретирующая половина: в UTF-16LE это `MISERY\Binaries\Win64\MISERY-Win64-Shipping.exe` и
`BootstrapPackagedGame-Win64-Shipping.exe`, то есть корневой `MISERY.exe` (422 400 байт) — это
UE-шный bootstrap упакованной игры, и запускает он `MISERY-Win64-Shipping.exe`, а не 282-МБ
`MISERY/Binaries/Win64/MISERY.exe`. Значит «отгруженный образ» для этого вопроса —
Shipping-бинарник. *(класс I, INFERRED, confidence 0.90, oracle: binary-analysis + external-doc;
второй метод — контрольное измерение M5 ниже: две группы препроцессорных гейтов различают
конфигурации двух бинарников независимо от этой строки)*

**M2. Какую цепочку выбирают данные установки.** `global.utoc` — 623 байта, версия 6,
`toc_entry_count` = **1**, `container_flags` = `0x00` (ни `Compressed`, ни `Encrypted`, ни
`Signed`, ни `Indexed`), и единственный 12-байтовый chunk id по смещению 144 равен
`000000000000000000000005`. Это байт-в-байт `CreateIoChunkId(0, 0, EIoChunkType::ScriptObjects)`
(`Runtime/Core/Public/IO/IoChunkId.h:136`, тип 5 в байте 11). Следовательно предикат
`InitAsyncThread` (`AsyncPackageLoader.cpp:202`) в этой установке истинен и загрузчиком является
**`FAsyncLoadingThread2`**, а не legacy `FAsyncLoadingThread`.

**M3. Где лежит контент.** `MISERY-Windows.utoc`, версия 6, `container_flags` = `0x0a`
(`Encrypted`, `Indexed`), `toc_entry_count` = 19 510. Перепись типов по байту 11 каждого chunk
id: `ExportBundleData` **12 933**, `BulkData` 5 513, `ShaderCode` 1 061, `ShaderCodeLibrary` 2,
`ContainerHeader` **1**, `ScriptObjects` 0. То есть все 12 933 пакета игры приходят через
package store — ровно тем путём, что описан в §E-3a.3 — при том, что в `MISERY-Windows.pak`
cooked-ассетов **0** (CK-01). Контраст теперь измерен, а не предположен.

Чтение TOC не нарушает D-02: `FIoStoreTocResource::Read` (`IoStore.cpp:3145-3218`) читает
таблицу chunk id прямо из файла, без расшифровки, а флаг `Encrypted` относится к блокам
`.ucas`; `.ucas` не открывался ни разу.

**M4. Проверка образа строковыми зондами, с предсказаниями, объявленными до измерения.**
Таблица предсказаний живёт в `tools/static/loader_admission_probe.py` и делит зонды на
`ue_log` (формат-строки `UE_LOG`) и `literal` (операнды `Printf`/`FParse`/`FPaths`/`switch`).

*Первый прогон провалил 9 предсказаний из 16 сразу, и причина оказалась не в чтении
исходников.* `Runtime/Core/Public/Misc/Build.h:327-328` (ветка `#elif UE_BUILD_SHIPPING`,
открыта на `:308`; **исправлено 2026-08-23**, было ошибочно `:306` — та же ветка `#elif
UE_BUILD_TEST`, что и в LOG-0037, тело `#define` идентично, вывод не менялся) задаёт
`NO_LOGGING = !USE_LOGGING_IN_SHIPPING`, `Build.h:191-192` даёт `USE_LOGGING_IN_SHIPPING` значение 0 по
умолчанию, а под `NO_LOGGING` макрос `UE_LOG`
(`Runtime/Core/Public/Logging/LogMacros.h:146-158`) обращается к `Format` только внутри
`if constexpr`, ложного для всех verbosity кроме `Fatal`. В Shipping-образе не остаётся ни
одной не-`Fatal` формат-строки, то есть весь класс `ue_log` для этого вопроса **слеп, а не
отрицателен**. Строки оставлены в таблице именно поэтому: слепота зонда должна быть видна в
артефакте, а не удалена из него.

Результат в `MISERY-Win64-Shipping.exe`: 38 проверенных предсказаний, 12 провалов. Из них
**9 — все двенадцать зондов класса `ue_log`, у которых предсказывалось присутствие** (объяснение
выше), и **3 — контрольные литералы**: `ProcessExportBundles` и `DeferredPostLoadDone` из
`LexToString(EAsyncPackageLoadingState2)` и `Event_ProcessExportBundle`. Первые два — важный
результат про сам инструмент: эта функция вызывается только из `UE_LOG`, поэтому в
`NO_LOGGING`-образе она остаётся без ссылок и линкер уносит её целиком вместе со **всеми** её
плечами — и с контролем, и с тестом. Значит проверка `ALT2_ENABLE_LINKERLOAD_SUPPORT` через
`LexToString` в Shipping-образе **не отрицательна, а недействительна**; именно для этого контроль
и заводился, и именно поэтому в таблице есть второй, независимо размещённый тест того же макроса
(`IsTimeLimitExceeded`), у которого контроли выжили. Из 28 зондов класса `literal` присутствуют
15 и отсутствуют 13:

* **присутствуют** `_P.pak`, `.utoc`, `%sPaks/global.utoc`, `.ucas`, `_s%d`, `*.pak`, `Paks/`,
  `NoPak`, `SkipOptionalPakFiles`, `checkpak`, `-==--==--==--==-`, `/Script/CoreUObject` — то
  есть `FPakPlatformFile::Mount`, `FPakPlatformFile::Initialize`,
  `FFileIoStoreReader::Initialize` и путь native-регистрации в этот образ **слинкованы**;
* **отсутствуют** `-pakdir=`, `-paklist=`, `StartupPaksWildcard=`, `LookLooseFirst` — при том
  что три не-gated `FParse`-литерала из **тех же файлов** присутствуют. Это контролируемое
  измерение, и оно даёт `UE_BUILD_SHIPPING == 1` для `IPlatformFilePak.cpp` в этом образе;
* **присутствует** `Missing signature` — литерал, достижимый только когда `IsSigningEnabled()`
  может быть истинным, то есть под `UE_BUILD_SHIPPING`. В 282-МБ `MISERY.exe` он
  **отсутствует**, ровно как предсказывает `IoStore.cpp:61-68`. Контролируемая пара на двух
  образах из одного исходника;
* **отсутствуют** все три литерала-аргумента `IsTimeLimitExceeded` изнутри
  `#if ALT2_ENABLE_LINKERLOAD_SUPPORT` (`AsyncLoading2.cpp:5652`, `:5854`, `:5932`) при
  **двух из трёх** присутствующих контролях того же вида из того же файла
  (`:4514`, `:7746`; третий, `:6285`, отсутствует). Значит
  `ALT2_ENABLE_LINKERLOAD_SUPPORT == 0` и файловый fallback в этот образ не попал.

**M5. Контрольный образ, который делает измерение M4 читаемым.** Та же таблица на 282-МБ
`MISERY/Binaries/Win64/MISERY.exe`: **все** зонды `ue_log` присутствуют (то есть объяснение
через `NO_LOGGING` — не догадка), `-pakdir=`, `-paklist=`, `StartupPaksWildcard=`,
`LookLooseFirst` и строка проверки `DO_CHECK` из `AsyncLoading2.cpp:4940` присутствуют,
`Missing signature` отсутствует, а тест ALT2 проходит с **тремя из трёх** работающих контролей:
`ProcessExportBundles` и `DeferredPostLoadDone` из `LexToString(EAsyncPackageLoadingState2)`
есть, а соседние по switch `CreateLinkerLoadExports` и `WaitingForLinkerLoadDependencies`
изнутри `#if` — нет (`AsyncLoading2.cpp:2102`, `:2103`, `:2107`, `:2112`). Побочный результат:
гипотеза D-04 о конфигурации этого бинарника получает независимое подтверждение в части «не
Shipping» — двумя разными группами препроцессорных гейтов; сама оценка остаётся там, где она
записана, и этот документ её не повышает (§10.1).

**Почему G3 (подпись) закрыт.** Два независимых довода. Первый — измерение: `global.utoc`
несёт `container_flags = 0x00`, бита `Signed` (1 << 2) нет; `MISERY-Windows.utoc` несёт `0x0a`,
бита `Signed` тоже нет; `.sig` в установке нет ни одного. Второй — reductio на исходниках: если
бы `GetPakSigningKeysDelegate` был привязан, `IsSigningEnabled()` в Shipping-образе давал бы
`true`, и `IoStore.cpp:3275-3277` отверг бы **сам `global.utoc`** с «Missing signature»; тогда
чанк `ScriptObjects` не нашёлся бы, загрузчиком стал бы legacy `FAsyncLoadingThread`, а
cooked-ассетов для него в установке нет вовсе (CK-01: 0 из `.uasset .uexp .umap …`). Сборка,
которая не может прочитать свой собственный контент, не отгружается. Значит подпись выключена.

### 7. Вердикт по E-3a

**Q1 — ветвления по происхождению контейнера в цепочке нет.** Прочитаны все шаги от
`FPakPlatformFile::Mount` до `UObjectBase::AddObject` и до `StaticConstructObject_Internal`; все
найденные ветвления зависят от (а) содержимого запроса, (б) содержимого самого пакета,
(в) значений препроцессора, (г) числового `Order`. Сильнее того: `FPackageStoreEntry`
(`PackageStore.h:36-44`) в cooked-сборке несёт два поля, ни одно из которых не идентифицирует
контейнер, поэтому у кода после этой границы нет входа, по которому можно было бы ветвиться.
Native-регистрация (`UObjectBase::Register`) вообще не имеет контейнера среди своих входов: её
вход — строковые литералы образа. *(класс I, INFERRED, confidence 0.88, oracle: external-doc +
binary-analysis + container-metadata; два независимых метода — (1) прочтение цепочки в
первоисточнике на заявленном CL с цитатой файла и строки на каждом шаге и проверкой типа на
границе; (2) измерение образа и данных установки, показавшее, что именно эта цепочка
слинкована и именно она выбирается. Попытка опровержения — §E-3a.5, десять названных мест, из
которых один (G3) оказался настоящим шлюзом и был закрыт отдельным измерением)*

**Q2 — исправлено 2026-08-23 (адверсариальное ревью, LOG-0031j п. 2): смешанное утверждение
разделено на два, вместо одного неверного.** Прежняя формулировка («файлового обхода package
store нет») противоречила собственному §E-3a.3 п. B1 этого же документа: полный legacy-класс
`FAsyncLoadingThread` (`AsyncLoadingThread.h:233`) ничем не закрыт и безусловно линкуется в
Shipping, инстанцируется в `AsyncPackageLoader.cpp:219-222`. Разделение:

* *(наблюдение, подтверждённое)* При **текущем** содержимом `global.utoc` (чанк `ScriptObjects`
  присутствует) выбирается `FAsyncLoadingThread2`, и его **собственный внутренний** fallback на
  файловую систему (`TryGetPackagePathFromFileSystem`) вырезан препроцессором:
  `ALT2_ENABLE_LINKERLOAD_SUPPORT` (`AsyncLoading2.cpp:264`) равен `WITH_EDITOR`, то есть 0 в
  Shipping. *(класс I, INFERRED, confidence 0.90, oracle: container-metadata + binary-analysis +
  external-doc; два независимых метода — (1) чтение таблицы chunk id обоих контейнеров
  установки; (2) контролируемый строковый тест в двух образах, где литералы изнутри `#if`
  отсутствуют при присутствующих контролях из того же файла)*
* *(отдельно, не выводится из первого)* Полный legacy-загрузчик (`FAsyncLoadingThread` +
  `FLinkerLoad`, читающий `.uasset`/`.uexp`) **безусловно скомпилирован** в
  `MISERY-Win64-Shipping.exe` и достижим через runtime-ветку `AsyncPackageLoader.cpp:219-222`
  внутри той же функции `InitAsyncThread`, вызываемой безусловно из `UObjectBaseInit()`
  (`UObjectBase.cpp:1040-1041`). Он не выбран **при текущих байтах** `global.utoc`, а не
  исключён компиляцией — выбор загрузчика решается во время выполнения, а не во время сборки.
  *(класс I, INFERRED, confidence 0.85, oracle: external-doc + binary-analysis; два независимых
  метода — (1) чтение объявления класса и вызывающего кода в первоисточнике; (2) подтверждение,
  что `FAsyncLoadingThread`, `FLinkerLoad::CreateLinker` не находятся ни под одним `#if`, тем же
  структурным разбором препроцессорных гейтов, который нашёл ложное G2 в Q2 из §E-3a.5)*

**Почему это меняет практический вывод §8 п. 2.** «Путь, читающий `.uasset`, вырезан
препроцессором» — было неверно и удалено. Правильная формулировка: этот путь **скомпилирован и
достижим**, просто не активен при нынешнем содержимом `global.utoc`. Это оставляет открытым
более дешёвый маршрут, чем полная замена CT-05 на Zen-сериализатор: если можно заставить
загрузчик выбрать `FAsyncLoadingThread` без пересборки движка (командной строкой, консольной
переменной или ini), Tier B в исходной legacy-формулировке (`.uasset`+`.uexp`) остаётся
жизнеспособным. Существует ли такой способ — **не исследовано** (`NEW-13`).

**Q3 — шлюза, который отверг бы внешний контейнер, на цепочке нет.** Единственный настоящий
шлюз — проверка подписи IoStore (G3) — в этой сборке выключен. **Оценка исправлена 2026-08-23**
(адверсариальное ревью, LOG-0031j п. 3): второй «метод» ниже был reductio, построенным на той
же измеренной величине (`container_flags`) плюс отсылка к CK-01 — это цепочка рассуждения, а не
второй акт измерения, и правило проекта прямо называет такую цепочку недостаточной для полосы
confidence ≥ 0.80. Понижено **0.85 → 0.78**, пока не появится настоящий второй метод (`NEW-12`:
статический поиск точки привязки `FCoreDelegates::GetPakSigningKeysDelegate()` в образе). *(класс
I, INFERRED, confidence 0.78, oracle: container-metadata; один измеренный метод — флаги
контейнеров и отсутствие `.sig` в установке. Reductio ниже сохранён как рассуждение, а не как
второй метод: если бы подпись была включена, `IoStore.cpp:3275-3277` отверг бы сам
`global.utoc` с «Missing signature», чанк `ScriptObjects` не нашёлся бы, и активным стал бы
legacy-загрузчик — для которого в установке нет ни одного cooked-ассета (CK-01). Это усиливает
достоверность вывода по существу, но не считается вторым независимым измерением по правилу
проекта, поэтому не поднимает оценку)*

**Чего этот раздел НЕ доказывает, и это ограничение структурное, а не временное.** Матрица
§10.5 для утверждения «функция X делает Z» требует `binary-analysis` **плюс** подтверждение
наблюдением через `runtime-reflection`, а уровень 2 (in-process) в Phase 1 недопустим (§8.4,
условие 3 не выполнено: по Q-8.2 получен ограниченный ответ, а не «отсутствует»). Поэтому SP-1
**по построению** не может дать ≥0.95, которых §10.3 требует от публичного API, и не заменяет
E-3a. Он даёт то, для чего заведён: ожидаемый результат до траты на Tier C.

Отдельно: «код принял бы внешний контейнер» и «внешний контейнер будет смонтирован» — разные
утверждения. Второе остаётся за Tier A (CT-01..CT-03) и NEW-04.

### 8. Что это значит для мод-кита

1. **Мод, добавляющий пакет, обязан быть парой `.pak` + `.utoc`/`.ucas` с корректным
   `FIoContainerHeader`.** Не «или»: `.utoc` подхватывается только как файл-сосед
   смонтированного `.pak` (`IPlatformFilePak.cpp:8564`), а пакеты берутся только из package
   store. Одиночный `.pak` даёт файлы и ноль пакетов; одиночный `.utoc` не будет замечен вовсе.
2. **Tier B в нынешней формулировке (§14.7: «минимальный cooked package в legacy формате
   `.uasset` + `.uexp`») в этой сборке не загрузится.** Не из-за версии и не из-за защиты, а
   потому что путь, который читает `.uasset`, вырезан препроцессором, и загрузчик выбран другой.
   Диагностируемая ошибка, которую §14.7 объявляет валидным исходом Tier B, здесь известна
   заранее: `QueueMissingPackage`. Формулировку CT-05 надо менять: минимальный сериализатор
   должен производить **Zen-пакет и container header**, а не legacy-пару. Это существенно
   дороже, и это надо записать до, а не после.
3. **Что такое `MISERY-Windows.pak` и зачем он.** Файловый контейнер для loose-файлов движка:
   ICU (`.res` 3438), локализация (`.locres` 57, 61,2 МБ), `.png` 421, `.svg` 266,
   `.uplugin` 124, `.ini` 52, шрифты — и 0 cooked-ассетов (CK-01). Всё это читается через
   `IPlatformFile`, а не через загрузчик пакетов, что ровно соответствует его роли в цепочке A.
   Для мода он нужен не как носитель контента, а как **обязательный носитель имени**, к которому
   будет искаться `.utoc`-сосед. Заодно это снижает ставку NEW-04: даже если pak монтируется,
   пакетов он не даёт, так что «монтируется ли он» — вопрос про файлы.
4. **Перекрытие штатного пакета возможно и определяется приоритетом.** Штатный контейнер имеет
   `Order` 4 (`Content/Paks/MISERY-*`), а `_P.pak` даёт `+100 × ChunkVersion`, поэтому
   `MyMod_P.pak` в `Saved/Paks/` получает 101 и побеждает при совпадении `FPackageId`
   (§E-3a.5 G5). Это следует проверить экспериментом до того, как на этом что-то строить.
5. **В Shipping обнаружение ограничено тремя каталогами.** `-pakdir=` вырезан (M4), консольная
   команда монтирования вырезана (`IPlatformFilePak.cpp:8294`). Остаются
   `MISERY/Content/Paks/`, `MISERY/Saved/Paks/`, `Engine/Content/Paks/` при старте, плюс
   `FCoreDelegates::MountPak` изнутри игрового кода. Для §13 (bootstrap) это входное
   требование, а не деталь.
6. **Ключ шифрования моду не нужен, и подпись не мешает.** Нулевой `EncryptionKeyGuid`
   принимается (G8), подпись выключена (G3). D-02 при этом не затрагивается: речь о
   производстве **своего** незашифрованного контейнера, а не о чтении штатного.

### 9. Что осталось `UNKNOWN`, с названным способом закрытия

| Что | Чем закрывается |
|---|---|
| Загружается ли фактически пакет из внешнего IoStore-контейнера | E-3a, Tier C; статически закрыто быть не может (§E-3a.7) |
| Монтируется ли `MISERY-Windows.pak` в runtime (NEW-04) | I-14; на ответ этого раздела не влияет (§E-3a.8 п. 3) |
| Переопределяет ли проект `ALT2_ENABLE_LINKERLOAD_SUPPORT` способом, не оставляющим строк | косвенно закрыто M4/M5 (три литерала отсутствуют при работающих контролях); прямое закрытие — xref в Ghidra по `TryGetPackagePathFromFileSystem` |
| Реально ли `MyMod_P.pak` перекрывает штатный пакет по `FPackageId` | Tier A + E-3a; статически выведено, не наблюдалось |
| Какова цена Zen-сериализатора вместо legacy (новая формулировка CT-05) | оценка после SP-1, до Tier B |
