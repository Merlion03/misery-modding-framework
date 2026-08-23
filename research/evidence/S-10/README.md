# S-10 — сырые протоколы прогонов `tools/static/rtti_scan.py`

Каталог хранит неотредактированный вывод инструмента, на который ссылается
`docs/rtti-assessment.md`. Ничего здесь не правилось руками: файлы скопированы
из `workspace/rtti/` как есть.

`build_key = sha256:0eef3715244b467c830022c4260a0e2c29c7def1429cb34aa37fdf9b7e14a383`
— это sha256 файла `MISERY\Binaries\Win64\MISERY-Win64-Shipping.exe`
(134 658 048 байт), к которому относятся все файлы, кроме контрольных и
`oracle-d04.log`.

| Файл | Что это |
|---|---|
| `shipping-run1.log` | основная цель, прогон 1: `--vtable-census --ue-source-root "D:\Program Files\UE_5.4\Engine"` |
| `shipping-run2.log` | та же цель, прогон 2, без прохода по исходникам движка |
| `shipping-rtti.json` | полный машинный документ прогона 1: поверхность, все 628 дескрипторов, все 587 локаторов с иерархиями и vtable, 18 буквальных чтений класса P, четыре пробы на опровержение |
| `rtti.jsonl` | артефакт задачи S-10 по `plan.md` §7.3: 587 строк, по одной на класс |
| `whole-surface-run.log` | контрольный прогон по всем девяти секциям, включая `.text`, `.pdata`, `.rsrc`, `.reloc` |
| `control-positive-msvcp140.log` | положительный контроль: `C:\Windows\System32\MSVCP140.dll` |
| `control-negative-tbbmalloc.log` | отрицательный контроль: `MISERY\Binaries\Win64\tbbmalloc.dll` |
| `control-bootstrap-shim.log` | shim `MISERY\MISERY.exe`, 422 400 байт |
| `oracle-d04.log` | второй бинарник `MISERY\Binaries\Win64\MISERY.exe` — по решению D-04 только read-only oracle |

## Совпадение прогонов 1 и 2

`rtti.jsonl` обоих прогонов совпадает побайтно, sha256
`fa631b2e5235c5ba297d3e3e7770bf14e427db41c02a88c97f795d5abaf112a4`. Полные JSON
различаются ровно в тех полях, которые прогон 2 не запрашивал:
`ue_source_corroboration` (в прогоне 2 `null`) и производное от него
`attribution.ue_source_declaration` у 13 записей. Сам разбор бинарника
воспроизвёлся без единого расхождения.

## Команды

Приведены в `docs/rtti-assessment.md` §9.6. Интерпретатор —
`D:\Tools\venv-research\Scripts\python.exe`, рабочий каталог — корень
репозитория. Игровой файл открывался только на чтение (D-01), запись шла
только в `workspace\rtti\`.
