#include <Windows.h>
#include <MinHook.h>
#include <string>
#include <Shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

typedef HANDLE(WINAPI* CreateFileW_t)(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
);

CreateFileW_t oCreateFileW = nullptr;

HANDLE WINAPI hkCreateFileW(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
)
{
    if (lpFileName != nullptr) {
        std::wstring path(lpFileName);

        if (StrStrIW(path.c_str(), L"\Windows\Prefetch\Payload.pf")) {
            // Bloqueia a criação retornando INVALID_HANDLE_VALUE
            SetLastError(ERROR_ACCESS_DENIED);
            return INVALID_HANDLE_VALUE;
        }
    }

    return oCreateFileW(
        lpFileName,
        dwDesiredAccess,
        dwShareMode,
        lpSecurityAttributes,
        dwCreationDisposition,
        dwFlagsAndAttributes,
        hTemplateFile
    );
}

DWORD WINAPI InitHook(LPVOID)
{
    if (MH_Initialize() != MH_OK)
        return 1;

    if (MH_CreateHook(&CreateFileW, &hkCreateFileW, reinterpret_cast<LPVOID*>(&oCreateFileW)) != MH_OK)
        return 1;

    if (MH_EnableHook(&CreateFileW) != MH_OK)
        return 1;

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        CreateThread(nullptr, 0, InitHook, nullptr, 0, nullptr);
    }
    return TRUE;
}
