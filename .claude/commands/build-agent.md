---
Compile the C++ EDR agent for SentinelUZ.

Build directory: edr_client/build2
Source directory: edr_client/

Steps:
1. Configure if needed:
   PATH="/c/msys64/ucrt64/bin:$PATH" cmake -G "MinGW Makefiles" -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -S edr_client -B edr_client/build2

2. Compile:
   PATH="/c/msys64/ucrt64/bin:$PATH" mingw32-make -C edr_client/build2

3. If compilation errors occur: fix them automatically and recompile.

4. If successful: confirm edr_client/build2/edr_client.exe exists.

Key files:
- edr_client/src/main.cpp — entry point
- edr_client/src/process_scanner.cpp — process collection
- edr_client/src/network_client.cpp — HTTP to Django
- edr_client/src/config_reader.cpp — config.ini parser
- edr_client/src/behavior_monitor.cpp — suspicious detection
- edr_client/src/port_scanner.cpp — network connections
- edr_client/CMakeLists.txt — build config
- edr_client/config.ini — runtime config (server URL, token)

Common issues:
- PATH conflict between Git mingw64 and MSYS2 ucrt64 — always prefix PATH
- Missing bcrypt/iphlpapi — check target_link_libraries in CMakeLists.txt
- wstring/string conversion — use WideCharToMultiByte
---
