# БСУ ФТК — станция телеметрии

**БСУ ФТК (имитатор)** — пассивный Ethernet-сниффер.
Приложение не является адресатом наблюдаемого обмена и не отправляет
протокольные ответы. Оно показывает все кадры, поступившие в Npcap.

```text
Npcap / NDIS
    ↓
CaptureService              отдельный поток
    ↓
bounded SPSC PacketQueue
    ↓
DecoderService              отдельный поток
    ↓
bounded SPSC BatchQueue
    ↓
TelemetryTableModel         GUI thread
    ↓
QSortFilterProxyModel
    ↓
QTableView
```

## Что реализовано

### Захват

- Npcap/libpcap, L2 Ethernet capture;
- станция ничего не передаёт в контролируемую линию;
- promiscuous mode включён, BPF-фильтр по MAC/IP/UDP отсутствует;
- любой увиденный Ethernet-кадр попадает в независимый RAW-журнал до
  распознавания отправителя и декодирования;
- проверяется, что выбранный Npcap-интерфейс выдаёт Ethernet-кадры `DLT_EN10MB`;
- `snaplen = 2048`, capture buffer 4 MiB, immediate mode;
- timestamp берётся из pcap header до пользовательской обработки;
- отдельные счётчики Npcap drops, capture queue drops и interface drops.

### Разбор Ethernet

Поддерживается:

```text
Ethernet
802.1Q / 802.1ad VLAN
IPv4
UDP
```

Парсер:

- проверяет заявленную длину IPv4;
- проверяет UDP length;
- не принимает усечённые кадры;
- не пытается декодировать IPv4-фрагменты;
- передаёт protocol decoder только полный UDP payload.

### БЦВМ ↔ КАСУ ПП

Для рабочего протокола используются:

- БЦВМ → КАСУ ПП: payload 400 байт;
- КАСУ ПП → БЦВМ: payload 100 байт;
- версия протокола: 2;
- многобайтовые поля: big endian;
- CRC16: polynomial `0x1021`, init `0xFFFF`, xorout `0`, без reflection;
- CRC хранится big endian.

Из штатного 400-байтового пакета сейчас выводятся RAW-данные БЦВМ,
пиросредств, приводов, БСЭП, процессоров и шаг циклограммы.

Физические величины намеренно пока не вычисляются.

### ЯЛС / ЯАЗ

По исходникам YLS:

- ЯАЗ сам не участвует в Ethernet-обмене;
- ЯЛС принимает 32-байтовый ответ ЯАЗ;
- в Ethernet-пакет ЯЛС попадают первые 24 байта;
- фактический packed offset `yaz_data` — 223;
- `yaz_data[12][3][24]`;
- ожидаемый UDP payload ЯЛС — ровно 1432 байта.

Сейчас декодируются RAW-коды:

- `engine_revs1..5`;
- `tp_data*`;
- флаги давления/контроля;
- `time_ms`.

### GUI

Интерфейс построен на Qt Model/View:

- слева справочник внешних абонентов (ступень Б, ступень А, наземка, резерв);
- собственные адреса БСУ ФТК помечаются как адреса имитатора, но не
  отображаются отдельным внешним абонентом;
- справа вкладка «Весь трафик» — все кадры, в том числе неизвестные MAC,
  ARP, IPv6, TCP и недекодируемый payload;
- при выборе кадра — HEX/ASCII, время и захваченная/фактическая длина;
- отдельная вкладка «Телеметрия» — декодированные параметры;
- фильтры по абоненту/поисковой строке действуют только на отображение,
  а не на приём кадров;
- поиск по источнику, устройству и параметру;
- отображается RAW-код и возраст значения относительно самого свежего capture timestamp;
- абсолютный timestamp доступен через tooltip;
- отдельная индикация состояния приёма;
- counters: RX, drops, decoded, errors;
- низкоуровневая диагностика вынесена в нижнюю строку.

Capture и decoder не зависят от частоты перерисовки GUI.
Модель обновляется примерно 30 раз/с и схлопывает промежуточные обновления
одного параметра, сохраняя последнее значение за GUI-такт.

## Windows build

Проверенная пользовательская конфигурация проекта:

- Windows 10;
- Qt 6.8.0;
- llvm-mingw 64-bit;
- CMake + Ninja;
- Npcap runtime;
- Npcap SDK.

В Qt Creator нужно задать CMake variable:

```text
NPCAP_SDK_ROOT=C:/path/to/npcap-sdk
```

В каталоге SDK должны существовать:

```text
Include/pcap.h
Lib/x64/wpcap.lib
Lib/x64/Packet.lib
```

После изменения CMake cache при необходимости удалить build-каталог и
запустить Configure заново.

## Тесты

```bash
ctest --test-dir build --output-on-failure
```

Protocol tests проверяют:

- Ethernet/IPv4/UDP parsing;
- отказ на IPv4 fragments;
- отказ на truncated frames;
- CRC БЦВМ;
- CRC КАСУ ПП;
- точный размер YLS telemetry payload;
- базовый layout YAZ RAW record.

## Следующие этапы

1. Проверка на живой линии и сохранение контрольного PCAP/PCAPNG.
2. Replay backend для воспроизводимых тестов без стенда.
3. Уточнение перечня отображаемой ТМИ.
4. RAW → physical conversion после получения подтверждённых коэффициентов.
5. История и тренды параметров.
6. Адаптер/плагин для MilTechStation.


## Offline emulator

When the stand is unavailable, select **"Эмулятор (без сети)"** in the
application header and press **"Запустить"**.

This mode does not open Npcap and does not transmit anything through a Windows
network adapter. It generates complete synthetic Ethernet/IPv4/UDP frames and
feeds them into the same `PacketQueue` used by live capture.

One 10 ms simulation tick currently generates:

- BCVM -> KASU PP: current paged 1024-byte frame, page = `counter % 10 + 1`;
- KASU PP -> BCVM: current 64-byte normal response;
- YLS -> consumers: 1432-byte payload with `yaz_data[12][3][24]`;
- YNP -> BCVM: 512 bytes = 100-byte main packet + 412-byte diagnostic page.

The YNP simulator uses the current endpoint `192.168.17.240:200 -> 192.168.17.246:100`.
The first 100 bytes follow the YNP firmware wire layout. Diagnostics use the
18-page map. MNP A contains deterministic synthetic frames; MNP B is zero-filled
because the second receiver is not installed. Frame 3403 is also zero-filled
because its actual transmission has not been confirmed.

BCVM pages 1-5 are populated from the supplied protocol maps. Pages 6-10 contain
only common header fields and zero reserve until their wire layouts are supplied.

The decoder keeps compatibility with the deployed 400/100-byte BCVM/KASU
exchange so a later test on the old stand remains possible.


## Журнал Ethernet

Обработка не отбрасывает кадры до журнала:

```text
Npcap → PacketQueue → DecoderService
                          ├── PacketJournalQueue → PacketJournalModel → Весь трафик / HEX
                          └── ProtocolDecoders → BatchQueue → TelemetryTableModel
```

Очередь журнала ограничена 4095 кадрами. Экран сохраняет последние 4000;
переполнение очереди учитывается отдельным счётчиком `journalDrops`.
Это **оперативный кольцевой журнал в памяти, не долговременный архив PCAP**.
Все физически захваченные кадры поступают в очередь журнала, пока очередь
не заполнена. Сохранение неограниченного потока на диск пока не реализовано.

Справочник из 32 MAC сохраняет 2 собственных адреса БСУ ФТК только для
узнавания кадров, но исключает их из дерева внешних абонентов.
Неизвестный отправитель всё равно виден по фактическому MAC.

Режим внутренней симуляции проверяет очередь, parser, декодер и GUI, но
**не проверяет работу Npcap/драйвера или физическую видимость чужого unicast**.
На обычном коммутаторе нужны SPAN/mirror-порт или Ethernet TAP; promiscuous
mode сам по себе не обеспечивает получение кадров с других портов.
Для одновременного наблюдения двух независимых физических сетей потребуются
две точки захвата/два NIC (в текущей версии запускается один интерфейс).

Тест `packet_journal_tests` проверяет, что известные, неизвестные,
ARP и усечённые кадры поступают в RAW-журнал без изменения байтов
и с сохранением порядка.
