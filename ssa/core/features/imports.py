from dataclasses import dataclass, field
from typing import Dict, List, Set

import pefile


PRIV_ESC_APIS: Set[str] = {
    "AdjustTokenPrivileges",
    "OpenProcessToken",
    "LookupPrivilegeValueA",
    "LookupPrivilegeValueW",
    "SetTokenInformation",
    "CreateProcessAsUserA",
    "CreateProcessAsUserW",
    "ImpersonateLoggedOnUser",
    "SeDebugPrivilege",
}


ANTI_DEBUG_APIS: Set[str] = {
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "OutputDebugStringA",
    "OutputDebugStringW",
    "NtQueryInformationProcess",
}


NETWORK_APIS: Set[str] = {
    "InternetOpenA",
    "InternetOpenW",
    "InternetConnectA",
    "InternetConnectW",
    "WinHttpOpen",
    "WinHttpConnect",
    "socket",
    "connect",
}


FILE_APIS: Set[str] = {
    "CreateFileA",
    "CreateFileW",
    "WriteFile",
    "ReadFile",
    "DeleteFileA",
    "DeleteFileW",
}


REGISTRY_APIS: Set[str] = {
    "RegOpenKeyExA",
    "RegOpenKeyExW",
    "RegSetValueExA",
    "RegSetValueExW",
    "RegCreateKeyExA",
    "RegCreateKeyExW",
}


@dataclass
class ImportFeatureSummary:
    total_imports: int
    unique_apis: int
    privilege_apis: List[str] = field(default_factory=list)
    anti_debug_apis: List[str] = field(default_factory=list)
    network_apis: List[str] = field(default_factory=list)
    file_apis: List[str] = field(default_factory=list)
    registry_apis: List[str] = field(default_factory=list)
    by_dll: Dict[str, List[str]] = field(default_factory=dict)


def analyze_imports(pe: pefile.PE) -> ImportFeatureSummary:
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return ImportFeatureSummary(total_imports=0, unique_apis=0)
    all_apis: List[str] = []
    by_dll: Dict[str, List[str]] = {}
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode(errors="ignore").lower()
        names: List[str] = []
        for imp in entry.imports:
            if not imp.name:
                continue
            api_name = imp.name.decode(errors="ignore")
            all_apis.append(api_name)
            names.append(api_name)
        if names:
            by_dll[dll_name] = names
    unique = set(all_apis)
    privilege = sorted(api for api in unique if api in PRIV_ESC_APIS)
    anti_debug = sorted(api for api in unique if api in ANTI_DEBUG_APIS)
    network = sorted(api for api in unique if api in NETWORK_APIS)
    file_calls = sorted(api for api in unique if api in FILE_APIS)
    registry = sorted(api for api in unique if api in REGISTRY_APIS)
    return ImportFeatureSummary(
        total_imports=len(all_apis),
        unique_apis=len(unique),
        privilege_apis=privilege,
        anti_debug_apis=anti_debug,
        network_apis=network,
        file_apis=file_calls,
        registry_apis=registry,
        by_dll=by_dll,
    )

