# БСУ ФТК — станция телеметрии (MVP)

Первый рабочий каркас пассивной станции телеметрии:

`Npcap L2 capture -> bounded SPSC queue -> decoder thread -> batch queue -> Qt Model/View`.

## Сейчас реализовано

- пассивный Ethernet capture через Npcap/libpcap;
- BPF: только L2 broadcast от известных MAC БЦВМ / КАСУПП / ЯЛС;
- capture timestamp берётся из pcap header, а не из GUI/user processing time;
- immediate mode + 4 MiB capture buffer;
- отдельный capture thread и decoder thread;
- bounded очереди и счётчики переполнения;
- Ethernet + VLAN + IPv4 + UDP parser;
- RAW decoder БЦВМ -> КАСУПП (400 byte payload);
- RAW decoder КАСУПП -> БЦВМ (100 byte payload);
- RAW decoder `yaz_data[12][3][24]` из пакета ЯЛС;
- `QAbstractTableModel + QSortFilterProxyModel + QTableView`;
- GUI обновляется ~30 Hz, независимо от частоты приёма 100 Hz;
- отображение capture/drop/decode counters.

## YLS / YAZ

По исходникам `YLS-main`:

- ЯЛС получает от каждого ЯАЗ 32 байта;
- в Ethernet копируются байты `0..23`;
- в packed `YLSToYVData` фактический offset `yaz_data` равен `223`;
- структура: `12 BKD x 3 YAZ x 24 bytes`;
- текущий `ethernet.c` отправляет UDP payload длиной 1432 байта.

Физический пересчёт пока намеренно отсутствует: UI показывает RAW-коды.

## Windows build

Нужны:

- CMake >= 3.21
- C++20 compiler (MSVC 2022)
- Qt 5 или Qt 6 Widgets
- установленный Npcap runtime
- Npcap SDK

Пример:

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" `
  -DNPCAP_SDK_ROOT=C:/SDK/npcap-sdk
cmake --build build --config Release
```

Запускать с правами, позволяющими открыть Npcap adapter.

## Следующий шаг

1. Проверить на реальном `.pcap/.pcapng` или живой линии фактические MAC/UDP payload sizes.
2. Зафиксировать конкретные ЯЛС, которые несут интересующий ЯАЗ.
3. Добавить replay backend для воспроизводимого тестирования.
4. После получения коэффициентов добавить RAW -> physical conversion без изменения GUI model/view.
