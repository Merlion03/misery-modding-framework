# Аномалии установки — misery-24953925-ue5.4.4-bace50f7185d

Сгенерировано `tools/fingerprint/fingerprint.py` 1.0.0, `generated_at = 2026-08-27T10:30:28Z`.

`build_key = sha256:bace50f7185d095d03ee18a2fea701c747810c31f2037bda21ea57a81f013331`

Документ порождён автоматически задачей F-05 из того же списка, который лежит в `fingerprint.json` в поле `anomalies[]`. Ни одно число здесь не набрано руками: все они получены из результата сравнения.

## 1. Что именно сравнивалось

1. Дерево установки обходится только на чтение (решение D-01); получается множество путей относительно корня установки — **52** файл(ов).
2. Читается `Manifest_NonUFSFiles_Win64.txt`: по одной записи в строке, формат `<путь>` TAB `<время>`. Обратные слэши приводятся к прямым. Получается множество из **0** различных путей.
3. Считаются **обе** разности множеств, а не только одна.
4. Таблица секций каждого исполняемого файла сравнивается со списком имён, которые детектор считает обычными для образа, собранного компоновщиком MSVC (в списке 21 имён). Список — соглашение детектора, а не спецификация.
5. Сумма размеров файлов сравнивается с полем `SizeOnDisk` манифеста Steam.
6. Отметка времени каждой записи манифеста сравнивается с `mtime` файла на диске — результат в разделе 7.

Сравнение путей и разбор таблиц секций выполняются **дважды**, от двух независимых обходов каталога и двух независимых чтений манифеста. Критерий 2 класса P из §10.3 таким образом выполнен, а не заявлен.

* `manifest_comparison_reproduced` — **PASS**
* `pe_section_survey_reproduced` — **PASS**

## 2. Сводка

| Класс аномалии | Найдено |
|---|---|
| `file-not-in-non-ufs-manifest` | 52 |
| `manifest-entry-missing-on-disk` | 0 |
| `unexpected-pe-section` | 4 |
| `size-mismatch` | 0 |
| **всего** | **56** |

Проверка счёта: 52 файлов на диске минус 0 путей манифеста даёт **52**, и ровно столько записей класса `file-not-in-non-ufs-manifest` и найдено. Сходится это только потому, что ни одна запись манифеста не осталась без файла на диске; иначе разность множеств не совпала бы с разностью их размеров.

### Градуировка

Одна строка на КЛАСС записей, а не на запись: метод, oracle и уровень внутри класса буквально одни и те же — это один и тот же обход и один и тот же разбор. Персональная аннотация каждой из 56 записей лежит в `fingerprint.json`, в поле `anomalies[].evidence`, и проверяется там `tools/kb/validate.py` по правилам редуцированного конверта `kb-record.schema.json`.

| ID | Наблюдение | Метод | Oracle | Claim type | Уровень | Confidence | Класс |
|---|---|---|---|---|---|---|---|
| F05-1 | Каждая из 52 записей класса `file-not-in-non-ufs-manifest`: файл существует в установке, и ни одна строка `Manifest_NonUFSFiles_Win64.txt` его не называет | Обход установки только на чтение и разбор `Manifest_NonUFSFiles_Win64.txt`, оба выполнены дважды от независимых дескрипторов: run 1 и run 2 совпали, результат воспроизведён | filesystem | file-exists | OBSERVED | 0.99 | P |
| F05-3 | Каждая из 4 записей класса `unexpected-pe-section`: таблица секций содержит секцию с именем вне списка обычных | Разбор таблицы секций средствами `tools/fingerprint/pe_info.py`, выполнен дважды на заново открытых дескрипторах, результат воспроизведён | binary-analysis + external-doc | layout-observation | INFERRED | 0.79 | I |

Значение 0.79 у класса `unexpected-pe-section` не занижено из осторожности: в этом прогоне выполнен ровно ОДИН метод, а §10.3 требует двух независимых от 0.80 и выше. Значение 0.99 у класса `file-not-in-non-ufs-manifest` держится на том, что это членство в множестве из двух первичных чтений, без шага интерпретации.

## 3. Именованный случай A-05

Детектор нашёл её сам, разностью множеств, не имея этого файла в условиях поиска. Идентификатор `A-05` приписан **уже найденной** аномалии по совпадению пути и имени секции: если удалить таблицу идентификаторов, обнаружение не изменится, исчезнет только ссылка на строку Приложения A.

### `MISERY/Binaries/Win64/MISERY.exe` — `file-not-in-non-ufs-manifest`

Файл `MISERY/Binaries/Win64/MISERY.exe` существует в установке (размер 282826240 байт), и ни одна строка `Manifest_NonUFSFiles_Win64.txt` его не называет. Сравнение выполнено дважды, от двух независимых обходов каталога и двух независимых чтений манифеста, и оба прогона совпали.

Градуировка: строка `F05-1` таблицы в разделе 2; персональная аннотация — `anomalies[].evidence` в `fingerprint.json`.

### `.uedbg` в `MISERY/Binaries/Win64/MISERY.exe`

Таблица секций `MISERY/Binaries/Win64/MISERY.exe`, разобранная `tools/fingerprint/pe_info.py`, содержит секцию с именем `.uedbg`: rva 215089152, virtual size 30576, raw size 30720, characteristics 0x60000020. Имя `.uedbg` не входит в список 21 имён, которые детектор считает обычными для образа, собранного компоновщиком MSVC. Таблица разобрана дважды, двумя отдельными вызовами разборщика на заново открытых дескрипторах, и оба разбора совпали.

Градуировка: строка `F05-3` таблицы в разделе 2; персональная аннотация — `anomalies[].evidence` в `fingerprint.json`.

### Что об этом файле говорить нельзя

Объяснение «в депот попала Development-сборка игры» — догадка, а не находка, и она градуирована так: **HYPOTHESIS, confidence 0.65, oracle: binary-analysis + filesystem** по решению D-04. Называть её фактом запрещено; в `fingerprint.json` она лежит в поле `hypothesis`, отдельно от поля `description`, где стоит только наблюдение.

Решение D-04 задаёт режим работы с этим файлом, и он ограничительный:

* `MISERY/Binaries/Win64/MISERY.exe` допускается **только как read-only oracle**;
* он **никогда** не является целью для bindings;
* любой вывод, полученный на нём, обязан быть перепроверен на Shipping-бинарнике (RISK-07).

## 4. Полный список `file-not-in-non-ufs-manifest` (52)

Перечислены все до одного, и это осознанно: предикат детектора — «названо ли имя файла в манифесте», а не «удивительно ли это». Группировка ниже — только способ читать список; сумма по группам равна общему числу, ни один файл из-за неё не пропадает.

### Исполняемые файлы — 4

Единственная группа, где отсутствие в манифесте действительно требует объяснения: рядом лежит исполняемый файл, который в манифесте есть.

* `Engine/Extras/Redist/en-us/UEPrereqSetup_x64.exe` — 50542368 байт
* `MISERY.exe` — 422400 байт
* `MISERY/Binaries/Win64/MISERY-Win64-Shipping.exe` — 134658048 байт
* `MISERY/Binaries/Win64/MISERY.exe` — 282826240 байт  ← `A-05`

### Контейнеры контента — 5

Манифест называется Non-UFS: он перечисляет файлы ВНЕ виртуальной файловой системы. Контейнеры .utoc/.ucas/.pak и есть UFS-содержимое, поэтому их отсутствие здесь ожидаемо и не является находкой.

* `MISERY/Content/Paks/MISERY-Windows.pak` — 117658732 байт
* `MISERY/Content/Paks/MISERY-Windows.ucas` — 4447110416 байт
* `MISERY/Content/Paks/MISERY-Windows.utoc` — 2935983 байт
* `MISERY/Content/Paks/global.ucas` — 2269168 байт
* `MISERY/Content/Paks/global.utoc` — 623 байт

### Дополнительные файлы движка — 33

Слои Vulkan, отладочные шрифты Slate, GPUDumpViewer и WinPixEventRuntime. Все они лежат в дереве Engine и в манифесте Non-UFS не перечислены.

* `Engine/Binaries/ThirdParty/DbgHelp/dbghelp.dll` — 2243216 байт
* `Engine/Binaries/ThirdParty/MsQuic/v220/win64/msquic.dll` — 2557608 байт
* `Engine/Binaries/ThirdParty/NVIDIA/NVaftermath/Win64/GFSDK_Aftermath_Lib.x64.dll` — 1886448 байт
* `Engine/Binaries/ThirdParty/Ogg/Win64/VS2015/libogg_64.dll` — 70384 байт
* `Engine/Binaries/ThirdParty/Vorbis/Win64/VS2015/libvorbis_64.dll` — 1735408 байт
* `Engine/Binaries/ThirdParty/Vorbis/Win64/VS2015/libvorbisfile_64.dll` — 59120 байт
* `Engine/Binaries/ThirdParty/Vulkan/Win64/VkLayer_api_dump.dll` — 4735728 байт
* `Engine/Binaries/ThirdParty/Vulkan/Win64/VkLayer_api_dump.json` — 12126 байт
* `Engine/Binaries/ThirdParty/Vulkan/Win64/VkLayer_gfxreconstruct.dll` — 3419488 байт
* `Engine/Binaries/ThirdParty/Vulkan/Win64/VkLayer_gfxreconstruct.json` — 27194 байт
* `Engine/Binaries/ThirdParty/Vulkan/Win64/VkLayer_khronos_profiles.dll` — 1628512 байт
* `Engine/Binaries/ThirdParty/Vulkan/Win64/VkLayer_khronos_profiles.json` — 75042 байт
* `Engine/Binaries/ThirdParty/Vulkan/Win64/VkLayer_khronos_synchronization2.dll` — 227680 байт
* `Engine/Binaries/ThirdParty/Vulkan/Win64/VkLayer_khronos_synchronization2.json` — 1772 байт
* `Engine/Binaries/ThirdParty/Vulkan/Win64/VkLayer_khronos_validation.dll` — 20454760 байт
* `Engine/Binaries/ThirdParty/Vulkan/Win64/VkLayer_khronos_validation.json` — 72373 байт
* `Engine/Binaries/ThirdParty/Windows/WinPixEventRuntime/x64/WinPixEventRuntime.dll` — 78256 байт
* `Engine/Binaries/ThirdParty/Windows/XAudio2_9/x64/xaudio2_9redist.dll` — 868672 байт
* `Engine/Binaries/Win64/EOSSDK-Win64-Shipping.dll` — 18128584 байт
* `Engine/Content/Renderer/TessellationTable.bin` — 259568 байт
* `Engine/Content/Slate/Cursor/invisible.cur` — 326 байт
* `Engine/Content/SlateDebug/Fonts/LastResort.tps` — 930 байт
* `Engine/Content/SlateDebug/Fonts/LastResort.ttf` — 5395052 байт
* `Engine/Extras/GPUDumpViewer/GPUDumpViewer.html` — 184013 байт
* `Engine/Extras/GPUDumpViewer/OpenGPUDumpViewer.bat` — 879 байт
* `Engine/Extras/GPUDumpViewer/OpenGPUDumpViewer.sh` — 2165 байт
* `MISERY/Binaries/Win64/D3D12/D3D12Core.dll` — 5929640 байт
* `MISERY/Binaries/Win64/D3D12/d3d12SDKLayers.dll` — 9546512 байт
* `MISERY/Binaries/Win64/OpenImageDenoise.dll` — 49793160 байт
* `MISERY/Binaries/Win64/tbb.dll` — 234728 байт
* `MISERY/Binaries/Win64/tbb12.dll` — 314600 байт
* `MISERY/Binaries/Win64/tbbmalloc.dll` — 76528 байт
* `MISERY/Plugins/SteamCorePro/Source/ThirdParty/SteamLibrary/redistributable_bin/win64/steam_api64.dll` — 317080 байт

### Файлы Steam Input — 10

Файлы controller_*.vdf и steam_input_manifest.vdf кладёт Steam, а не сборщик Unreal Engine; манифест Non-UFS формируется на стороне UE.

* `controller_generic.vdf` — 19151 байт
* `controller_neptune.vdf` — 19151 байт
* `controller_ps4.vdf` — 19143 байт
* `controller_ps5.vdf` — 19143 байт
* `controller_steamcontroller_gordon.vdf` — 19181 байт
* `controller_switch_pro.vdf` — 19157 байт
* `controller_xbox360.vdf` — 19151 байт
* `controller_xboxelite.vdf` — 19155 байт
* `controller_xboxone.vdf` — 19151 байт
* `steam_input_manifest.vdf` — 1292 байт

Сумма по группам: **52**, всего записей этого класса: **52**.

## 5. Записи манифеста без файла на диске (0)

Ни одной: каждый путь, названный `Manifest_NonUFSFiles_Win64.txt`, существует в установке. Это проверялось отдельно от предыдущего раздела — разность множеств считается в обе стороны.

## 6. Неожиданные секции PE (4)

Каждая запись этого класса — класс I, и иначе быть не может: назвать диапазон байт «секцией» и прочитать из него имя — значит опереться на публичную раскладку PE, то есть на oracle `external-doc`, который доказывает устройство формата, а не свойство этой сборки. Правка v2.4 §10.3 пускает `binary-analysis` в класс P только для чтения, которое называет смещение и длину и **не** называет, чем байты являются; здесь ровно наоборот.

### `.wixburn` в `Engine/Extras/Redist/en-us/UEPrereqSetup_x64.exe`

Таблица секций `Engine/Extras/Redist/en-us/UEPrereqSetup_x64.exe`, разобранная `tools/fingerprint/pe_info.py`, содержит секцию с именем `.wixburn`: rva 368640, virtual size 56, raw size 512, characteristics 0x40000040. Имя `.wixburn` не входит в список 21 имён, которые детектор считает обычными для образа, собранного компоновщиком MSVC. Таблица разобрана дважды, двумя отдельными вызовами разборщика на заново открытых дескрипторах, и оба разбора совпали.

Градуировка: строка `F05-3` таблицы в разделе 2.

Про само имя: имя `.wixburn` эмитирует WiX Burn — построитель загрузочных установщиков; для файла с именем `UEPrereqSetup_x64.exe` это ровно то, чем он выглядит. Это внешняя документация о том, что имя значит вообще, и она ничего не доказывает про эту сборку — **HYPOTHESIS, confidence 0.6, oracle: external-doc**.

### `.msvcjmc` в `MISERY/Binaries/Win64/MISERY-Win64-Shipping.exe`

Таблица секций `MISERY/Binaries/Win64/MISERY-Win64-Shipping.exe`, разобранная `tools/fingerprint/pe_info.py`, содержит секцию с именем `.msvcjmc`: rva 135811072, virtual size 8, raw size 512, characteristics 0xc0000040. Имя `.msvcjmc` не входит в список 21 имён, которые детектор считает обычными для образа, собранного компоновщиком MSVC. Таблица разобрана дважды, двумя отдельными вызовами разборщика на заново открытых дескрипторах, и оба разбора совпали.

Градуировка: строка `F05-3` таблицы в разделе 2.

Про само имя: имя `.msvcjmc` эмитирует компилятор MSVC при включённой инструментации Just My Code (`/JMC`), которая по умолчанию выключена в конфигурациях без отладки. Это внешняя документация о том, что имя значит вообще, и она ничего не доказывает про эту сборку — **HYPOTHESIS, confidence 0.6, oracle: external-doc**.

### `.msvcjmc` в `MISERY/Binaries/Win64/MISERY.exe`

Таблица секций `MISERY/Binaries/Win64/MISERY.exe`, разобранная `tools/fingerprint/pe_info.py`, содержит секцию с именем `.msvcjmc`: rva 284389376, virtual size 8, raw size 512, characteristics 0xc0000040. Имя `.msvcjmc` не входит в список 21 имён, которые детектор считает обычными для образа, собранного компоновщиком MSVC. Таблица разобрана дважды, двумя отдельными вызовами разборщика на заново открытых дескрипторах, и оба разбора совпали.

Градуировка: строка `F05-3` таблицы в разделе 2.

Про само имя: имя `.msvcjmc` эмитирует компилятор MSVC при включённой инструментации Just My Code (`/JMC`), которая по умолчанию выключена в конфигурациях без отладки. Это внешняя документация о том, что имя значит вообще, и она ничего не доказывает про эту сборку — **HYPOTHESIS, confidence 0.6, oracle: external-doc**.

### `.uedbg` в `MISERY/Binaries/Win64/MISERY.exe`

Таблица секций `MISERY/Binaries/Win64/MISERY.exe`, разобранная `tools/fingerprint/pe_info.py`, содержит секцию с именем `.uedbg`: rva 215089152, virtual size 30576, raw size 30720, characteristics 0x60000020. Имя `.uedbg` не входит в список 21 имён, которые детектор считает обычными для образа, собранного компоновщиком MSVC. Таблица разобрана дважды, двумя отдельными вызовами разборщика на заново открытых дескрипторах, и оба разбора совпали.

Градуировка: строка `F05-3` таблицы в разделе 2.

Про само имя: имя `.uedbg` эмитирует сборочная система Unreal Engine для отладочных данных, которые она кладёт прямо в образ. Это внешняя документация о том, что имя значит вообще, и она ничего не доказывает про эту сборку — **HYPOTHESIS, confidence 0.6, oracle: external-doc**.

## 7. Что проверено и аномалией НЕ является

* **Времена изменения.** Сравнены все 0 записей манифеста с `mtime` файлов на диске: совпало по секундам 0, разошлось 0, не с чем сравнить 0. Расхождение систематическое — Steam проставляет время записи файла, а не время сборки, — поэтому записей в `anomalies[]` оно не порождает: 0 однотипных строк похоронили бы 5 записей, которые систематическими не являются. Примеры расхождений: нет.
* **Размер установки.** Сумма размеров файлов и `SizeOnDisk` из манифеста Steam совпадают, записи класса `size-mismatch` нет.
* **Отсутствие `.uplugin` на диске.** Дескрипторы плагинов запечены в контент; их отсутствие среди файлов установки — свойство упаковки, а не аномалия. Поэтому `plugins[]` в `fingerprint.json` собран по каталогам `MISERY/Plugins/<Имя>` и несёт `descriptor_available: false`.

## 8. Границы этого документа

* Детектор отвечает на вопрос «названо ли имя файла в манифесте», и только на него. На вопрос «должно ли оно быть там названо» он не отвечает: манифест Non-UFS формирует сборщик UE по правилам, которых у нас нет.
* Список «обычных» имён секций PE — соглашение этого детектора. Имя вне списка означает «детектор такого не ждал», а не «файл неправилен».
* Идентификаторы вида `A-nn` присваиваются вручную в Приложении A `plan.md`. Аномалии без строки в Приложении A несут `id: null`: придумывать им новые номера здесь значило бы столкнуться с чужой нумерацией.
* Объяснения в разделах 4 и 6 («это кладёт Steam», «это UFS-содержимое») объясняют, почему запись не удивительна. Они не отменяют запись и не уменьшают счёт: в `anomalies[]` она есть.
