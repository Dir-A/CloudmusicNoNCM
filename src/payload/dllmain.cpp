#include <Windows.h>
#include <ZxHook/Mem.h>
#include <ZxHook/Inject.h>
#include <ZxHook/SHooker.h>
#include <string_view>

static HMODULE sg_ImageBase;


class std_string
{
public:
    union
    {
        char* m_pStr{};
        char m_aStr[16];
    };
    size_t m_nBytes{};
    size_t m_nCapacity{ 15 };

public:
    auto c_str() const -> const char*
    {
        return (this->size() >= 8) ? m_pStr : m_aStr;
    }

    auto size() const -> size_t
    {
        return this->m_nBytes;
    }
};

class std_wstring
{
public:
    union
    {
        wchar_t* m_pStr{};
        wchar_t m_aStr[8];
    };
    size_t m_nChars{};
    size_t m_nCapacity{ 7 };

public:
    auto c_str() const -> const wchar_t*
    {
        return (this->size() >= 8) ? m_pStr : m_aStr;
    }

    auto data() -> wchar_t*
    {
        return (this->size() >= 8) ? m_pStr : m_aStr;
    }

    auto size() const -> size_t
    {
        return this->m_nChars;
    }
};

struct NCM_AddID3_Content_Parame
{
    std_wstring org_path;
    std_wstring pic_path;
    std_string info_json;
    void* un_obj;
    size_t un_0;
    bool encrypt_flag;
    bool decrypt_flag;
    uint32_t un_1;
    std_wstring save_path;
    std_wstring save_dir;
    std_wstring un_str;
};

static auto PathGetFileName(const std::wstring_view msPath) -> std::wstring_view
{
    const auto pos = msPath.rfind(L'\\');
    return pos != std::wstring_view::npos ? msPath.substr(pos + 1) : msPath;
}

static auto __fastcall NCM_Storage_AddID3_Content_Hook(const std_string* pIDStr, NCM_AddID3_Content_Parame* pParam) -> void
{
    if (pParam->encrypt_flag)
    {
        const std::wstring_view org_path{ pParam->org_path.c_str(),pParam->org_path.size() };
        const auto org_file_name = PathGetFileName(org_path);

        const std::wstring_view save_path{ pParam->save_path.c_str(),pParam->save_path.size() };
        if ((pParam->save_dir.size() + org_file_name.size() + 2) <= pParam->save_path.m_nCapacity)
        {
            pParam->encrypt_flag = false;

            std::memcpy(pParam->save_path.data(), pParam->save_dir.c_str(), pParam->save_dir.size() * 2);
            pParam->save_path.data()[pParam->save_dir.size()] = L'\\';
            pParam->save_path.m_nChars = pParam->save_dir.size() + 1;

            std::memcpy(pParam->save_path.data() + pParam->save_path.size(), org_file_name.data(), org_file_name.size() * 2);
            pParam->save_path.m_nChars += org_file_name.size();
            pParam->save_path.data()[pParam->save_path.size()] = {};
        }
    }

    ZQF::ZxHook::SHooker<NCM_Storage_AddID3_Content_Hook>::FnRaw(pIDStr, pParam);
}

static auto __fastcall CreateProcessW_Hook(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) -> BOOL
{
    if (::wcsstr(lpCommandLine, L"cloudmusic.exe"))
    {
        char dll_path[MAX_PATH];
        ::GetModuleFileNameA(sg_ImageBase, dll_path, MAX_PATH);
        return ZQF::ZxLoader::ZxCreateProcess(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation, ZQF::ZxHook::SHooker<CreateProcessW_Hook>::FnRaw, { dll_path });
    }
    
    return ZQF::ZxHook::SHooker<CreateProcessW_Hook>::FnRaw(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}

static auto __fastcall LoadLibraryExW_Hook(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) -> HMODULE
{
    const auto lib_file_path_chars = ::wcslen(lpLibFileName);
    if (lib_file_path_chars >= 14)
    {
        if (::wcscmp(lpLibFileName + (lib_file_path_chars - 14), L"cloudmusic.dll") == 0)
        {
            const ZQF::ZxHook::VirtualAddress cloud_music_dll_handle = ZQF::ZxHook::SHooker<LoadLibraryExW_Hook>::FnRaw(lpLibFileName, hFile, dwFlags);
            ZQF::ZxHook::SHooker<NCM_Storage_AddID3_Content_Hook>::Commit(cloud_music_dll_handle.VA(), 0xDFA610); // build 203580
            return cloud_music_dll_handle.Ptr<HMODULE>();
        }
    }
    return ZQF::ZxHook::SHooker<LoadLibraryExW_Hook>::FnRaw(lpLibFileName, hFile, dwFlags);
}

static auto StartHook() -> void
{
    ZQF::ZxHook::SHookerDetour::AfterWith();
    ZQF::ZxHook::SHooker<CreateProcessW_Hook>::Commit(::CreateProcessW);
    ZQF::ZxHook::SHooker<LoadLibraryExW_Hook>::Commit(::LoadLibraryExW);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID /* lpReserved */)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        sg_ImageBase = hModule;
        ::DisableThreadLibraryCalls(hModule);
        ::StartHook();
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
