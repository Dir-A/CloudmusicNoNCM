#include <Windows.h>
#include <ZxHook/Inject.h>


INT APIENTRY wWinMain(_In_ HINSTANCE /* hInstance */, _In_opt_ HINSTANCE /* hPrevInstance */, _In_ LPWSTR /* lpCmdLine */, _In_ INT /* nShowCmd */)
{
    ZQF::ZxLoader::ZxCreateProcess(LR"(C:\Program Files\NetEase\CloudMusic\cloudmusic.exe)", { "CloudmusicNoNCM_Payload.dll" });
}
