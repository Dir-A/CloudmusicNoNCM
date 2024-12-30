#include <Windows.h>
#include <ZxHook/Mem.h>
#include <ZxHook/Inject.h>
#include <ZxHook/SHooker.h>

static HMODULE sg_hDll{};

// Inject SubProcess
static auto CreateProcessW_Hook(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) -> BOOL
{
    if (::wcsstr(lpCommandLine, L"cloudmusic.exe"))
    {
        char dll_path[MAX_PATH];
        ::GetModuleFileNameA(sg_hDll, dll_path, MAX_PATH);
        return ZQF::ZxLoader::ZxCreateProcess(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation, ZQF::ZxHook::SHooker<CreateProcessW_Hook>::FnRaw, { dll_path });
    }
    
    return ZQF::ZxHook::SHooker<CreateProcessW_Hook>::FnRaw(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}

// Restore File Name
// static auto MoveMediaFile_Hook(Std_WString* pSrc, Std_WString* pDst) -> void

// Patch cloudmusic.dll
static auto LoadLibraryExW_Hook(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) -> HMODULE
{
    const auto lib_file_path_chars = ::wcslen(lpLibFileName);
    if (lib_file_path_chars >= 14)
    {
        if (::wcscmp(lpLibFileName + (lib_file_path_chars - 14), L"cloudmusic.dll") == 0)
        {
            // Build 203152 | Patch Cryptor Checker
            const ZQF::ZxHook::VirtualAddress cloud_music_dll_handle = ZQF::ZxHook::SHooker<LoadLibraryExW_Hook>::FnRaw(lpLibFileName, hFile, dwFlags);
            ZQF::ZxHook::VirtualProtector::Set(cloud_music_dll_handle.VA() + 0xDA6066, ZQF::ZxHook::VirtualProperty::ReadWriteExecute, 8);
            if (cloud_music_dll_handle.Get<std::uint64_t>(0xDA6066) == 0x880000025485B60F)
            {
                cloud_music_dll_handle.Put<std::uint64_t>(0xDA6066, 0x8800000000C0C748);
            }
        }
    }
    return ZQF::ZxHook::SHooker<LoadLibraryExW_Hook>::FnRaw(lpLibFileName, hFile, dwFlags);
}

static auto StartHook(HMODULE hModule) -> void
{
    sg_hDll = hModule;
    ZQF::ZxHook::SHookerDetour::AfterWith();
    ZQF::ZxHook::SHooker<CreateProcessW_Hook>::Commit(::CreateProcessW);
    ZQF::ZxHook::SHooker<LoadLibraryExW_Hook>::Commit(::LoadLibraryExW);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID /* lpReserved */)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        ::DisableThreadLibraryCalls(hModule);
        ::StartHook(hModule);
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

extern "C" VOID __declspec(dllexport) Dir_A() {}
