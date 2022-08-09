// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "gen.h"


DWORD WINAPI MAIN(HMODULE hModule)
{
    TCHAR buf[1024] = { 0 };
    DWORD bufsize = sizeof(buf);
    HANDLE token = 0;
    char* base = {};
    const char* dest = "\\Room2004";
    const char* name = "\\sigpwnie.exe";
    char location[1024];
    char path[1024] = { 0 };
    DWORD pathsize = sizeof(path);
    int res = 0;
    char input[57] = "IS7WXGC726Z9JZMFPOKWQVMEPJCSU2FIMAC5N2VYIPGFJPCZPROPMYNL";
    unsigned char output[56] = {};
    size_t outputsize = sizeof(output);
    char* flag[56] = {};


    // 1. Get UserProfile
    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token);
    GetUserProfileDirectory(token, buf, &bufsize);
    CloseHandle(token);

    _bstr_t buf_c(buf);
    base = buf_c;

    // 2. Concatenate directory name and filename
    strcpy_s(location, base);
    strcat_s(location, dest);
    strcat_s(location, name);

    // 3. Get the current path
    GetModuleFileNameA(0, path, pathsize);

    // 4. compare
    res = strncmp(location, path, pathsize);

    //5. Return flag
    if (!res)
    {

        decode(input, output);
        _memccpy(flag, output, 125, outputsize);
        return MessageBoxA(0, (LPCSTR)flag, "Success", 0);
    }
    else {
        printf("Failed!\n");
    }

    system("pause");

    FreeLibraryAndExitThread(hModule, 0);
    return res;
}


BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CloseHandle(CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)MAIN, hModule, 0, nullptr));
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

