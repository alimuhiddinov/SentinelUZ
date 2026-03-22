# C++ Agent Skill — SentinelUZ

## Existing files (DO NOT recreate from scratch, only extend)
edr_client/src/main.cpp              ← entry point, main loop exists
edr_client/src/process_scanner.cpp  ← ProcessScanner class exists
edr_client/src/port_scanner.cpp     ← PortScanner class exists
edr_client/src/behavior_monitor.cpp ← BehaviorMonitor class exists
edr_client/src/network_client.cpp   ← NetworkClient class exists
edr_client/include/                 ← all .h header files exist

## What to ADD to ProcessInfo struct (process_info.h)
int parent_pid;
std::wstring parent_name;
std::string sha256_hash;
bool is_lolbin;
bool is_suspicious_chain;

## Parent PID collection
PROCESSENTRY32W already has th32ParentProcessID field
Use it in the existing snapshot loop — no new API needed

## SHA256 hashing (add to process_scanner.cpp)
#include <bcrypt.h>  // link: -lbcrypt in CMakeLists.txt
BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0)
BCryptCreateHash → BCryptHashData → BCryptFinishHash
BCryptCloseAlgorithmProvider / BCryptDestroyHash
Always use RAII wrapper for hAlg and hHash handles

## LOLBin detection (add to process_scanner.cpp)
const std::set<std::wstring> LOLBINS = {
  L"cmd.exe", L"powershell.exe", L"pwsh.exe", L"wscript.exe",
  L"cscript.exe", L"mshta.exe", L"regsvr32.exe", L"rundll32.exe",
  L"certutil.exe", L"msiexec.exe", L"wmic.exe", L"bitsadmin.exe",
  L"vssadmin.exe",    // ransomware: deletes shadow copies
  L"wbadmin.exe",     // ransomware: deletes Windows backups
  L"bcdedit.exe",     // ransomware: disables boot recovery
  L"cipher.exe",      // ransomware: file encryption utility
  L"diskshadow.exe"   // ransomware: shadow copy manipulation
};
const std::set<std::wstring> SUSPICIOUS_PARENTS = {
  L"WINWORD.EXE", L"EXCEL.EXE", L"POWERPNT.EXE",
  L"chrome.exe", L"firefox.exe", L"msedge.exe",
  L"iexplore.exe", L"outlook.exe"
};
is_lolbin = LOLBINS.count(lowercase_name) > 0;
is_suspicious_chain = is_lolbin &&
  SUSPICIOUS_PARENTS.count(uppercase_parent) > 0;

## Ransomware pre-encryption indicators
These are in LOLBINS list above but treated as CRITICAL
on server side when detected. The C++ agent flags them
as is_lolbin=true and sends parent_name for context.
Server-side match_iocs() handles RANSOMWARE_PRECURSOR
alert generation based on process name.

## Network connections via GetExtendedTcpTable
#include <iphlpapi.h>  // link: -liphlpapi in CMakeLists.txt
GetExtendedTcpTable(pTable, &size, TRUE, AF_INET,
  TCP_TABLE_OWNER_PID_ALL, 0)
Captures: local_ip, local_port, remote_ip, remote_port,
  state, owning_pid, owning_process_name

## config.ini reader (NEW file: config_reader.cpp)
Simple line-by-line parser, no external library needed
[server] section: url, token, port
[agent] section: interval_seconds, hostname

## config.ini format
[server]
url=http://192.168.1.100:8000
token=your_api_token_here
port=8000
[agent]
interval_seconds=30
hostname=auto

## Auth token in HTTP headers (add to network_client.cpp)
Current: sends no auth header
ADD: "Authorization: Token " + config.token
Read config at NetworkClient constructor, not hardcoded

## Updated JSON payload (add new fields to sendData())
Current: processes (pid, name), ports, alerts
ADD to each process object:
  "parent_pid": 1234,
  "parent_name": "WINWORD.EXE",
  "sha256": "abc123...",
  "is_lolbin": true,
  "is_suspicious_chain": true

## CMakeLists.txt additions
target_link_libraries(edr_client
  ... existing ...
  bcrypt
  iphlpapi
  winhttp
)




## Key rules
- RAII for ALL Windows handles — CloseHandle in destructor or finally
- Check ALL API return values
- Never use raw pointers for handle ownership
- Keep all strings as std::wstring internally,
  convert to std::string only for JSON output