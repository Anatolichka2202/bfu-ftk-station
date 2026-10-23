cmake_minimum_required(VERSION 3.21)
project(BsuFtkTelemetry VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_AUTOMOC ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Core Widgets)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Core Widgets)

add_library(telemetry_core STATIC
    src/common/bounded_spsc_queue.h
    src/common/raw_packet.h
    src/common/telemetry_types.h
    src/protocol/crc16.h
    src/protocol/crc16.cpp
    src/protocol/ethernet_udp_parser.h
    src/protocol/ethernet_udp_parser.cpp
    src/protocol/source_registry.h
    src/protocol/source_registry.cpp
    src/protocol/kasupp_decoder.h
    src/protocol/kasupp_decoder.cpp
    src/protocol/yls_yaz_decoder.h
    src/protocol/yls_yaz_decoder.cpp
    src/protocol/ynp_decoder.h
    src/protocol/ynp_decoder.cpp
    src/simulation/simulated_packets.h
    src/simulation/simulated_packets.cpp
    src/simulation/simulation_service.h
    src/simulation/simulation_service.cpp
    src/telemetry/decoder_service.h
    src/telemetry/decoder_service.cpp
)
target_include_directories(telemetry_core PUBLIC src)


add_library(capture_backend STATIC
    src/capture/capture_service.h
    src/capture/capture_service.cpp
)
target_include_directories(capture_backend PUBLIC src)
target_link_libraries(capture_backend PUBLIC telemetry_core)

if(WIN32)
    set(NPCAP_SDK_ROOT "" CACHE PATH "Npcap SDK root (contains Include/ and Lib/)")
    find_path(NPCAP_INCLUDE_DIR pcap.h
        HINTS "${NPCAP_SDK_ROOT}/Include"
        REQUIRED)
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(NPCAP_LIB_HINT "${NPCAP_SDK_ROOT}/Lib/x64")
    else()
        set(NPCAP_LIB_HINT "${NPCAP_SDK_ROOT}/Lib")
    endif()
    find_library(WPCAP_LIBRARY NAMES wpcap HINTS "${NPCAP_LIB_HINT}" REQUIRED)
    find_library(PACKET_LIBRARY NAMES Packet HINTS "${NPCAP_LIB_HINT}" REQUIRED)
    target_include_directories(capture_backend PRIVATE "${NPCAP_INCLUDE_DIR}")
    target_link_libraries(capture_backend PRIVATE "${WPCAP_LIBRARY}" "${PACKET_LIBRARY}" Ws2_32)
    target_compile_definitions(capture_backend PRIVATE BSU_FTK_HAS_PCAP=1)
else()
    find_path(PCAP_INCLUDE_DIR pcap.h)
    find_library(PCAP_LIBRARY pcap)
    if(PCAP_INCLUDE_DIR AND PCAP_LIBRARY)
        target_include_directories(capture_backend PRIVATE "${PCAP_INCLUDE_DIR}")
        target_link_libraries(capture_backend PRIVATE "${PCAP_LIBRARY}")
        target_compile_definitions(capture_backend PRIVATE BSU_FTK_HAS_PCAP=1)
    endif()
endif()

add_executable(bsu_ftk_telemetry
    src/main.cpp
    src/model/telemetry_table_model.h
    src/model/telemetry_table_model.cpp
    src/model/packet_journal_model.h
    src/model/packet_journal_model.cpp
    src/gui/main_window.h
    src/gui/main_window.cpp
)
target_include_directories(bsu_ftk_telemetry PRIVATE src)
target_link_libraries(bsu_ftk_telemetry PRIVATE
    telemetry_core
    capture_backend
    Qt${QT_VERSION_MAJOR}::Core
    Qt${QT_VERSION_MAJOR}::Widgets
)

include(CTest)
if(BUILD_TESTING)
    add_executable(protocol_tests
        tests/protocol_tests.cpp
        src/protocol/crc16.cpp
        src/protocol/ethernet_udp_parser.cpp
        src/protocol/source_registry.cpp
        src/protocol/kasupp_decoder.cpp
        src/protocol/yls_yaz_decoder.cpp
        src/protocol/ynp_decoder.cpp
        src/simulation/simulated_packets.cpp
    )
    target_include_directories(protocol_tests PRIVATE src)
    add_test(NAME protocol_tests COMMAND protocol_tests)
    add_executable(packet_journal_tests
        tests/packet_journal_tests.cpp
    )
    target_include_directories(packet_journal_tests PRIVATE src)
    target_link_libraries(packet_journal_tests PRIVATE telemetry_core)
    add_test(NAME packet_journal_tests COMMAND packet_journal_tests)
endif()
