// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <tchar.h>
BOOL hook_iat(LPCSTR szDllName, LPTHREAD_START_ROUTINE pfnOrg, PROC pfnNew);
int _stdcall mymsgbox(_In_opt_ HWND hWnd,
    _In_opt_ LPCSTR lpText,
    _In_opt_ LPCSTR lpCaption,
    _In_ UINT uType);   //定义hook函数，为了保持栈平衡参数尽量一样
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        LPTHREAD_START_ROUTINE g_pOrgFunc = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"user32.dll"), "MessageBoxA");//获取模块函数地址
        hook_iat("user32.dll", g_pOrgFunc, (PROC)mymsgbox);//iat hook
    }
        break;
       
    case DLL_PROCESS_DETACH:
    {
        LPTHREAD_START_ROUTINE g_pOrgFunc = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"user32.dll"), "MessageBoxA");
        hook_iat("user32.dll", (LPTHREAD_START_ROUTINE)mymsgbox, (PROC)g_pOrgFunc);
    }
        break;
    }
    return TRUE;
}

int _stdcall mymsgbox(_In_opt_ HWND hWnd,
    _In_opt_ LPCSTR lpText,
    _In_opt_ LPCSTR lpCaption,
    _In_ UINT uType)
{
    MessageBoxA(hWnd, "hooked_by_psb", lpCaption, uType);
    return 0;
}
BOOL hook_iat(LPCSTR szDllName, LPTHREAD_START_ROUTINE pfnOrg, PROC pfnNew)
{
    HMODULE hMod;
    LPCSTR szLibName;
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc;
    PIMAGE_THUNK_DATA pThunk;
    DWORD dwOldProtect, dwRVA;
    PBYTE pAddr;
    hMod = GetModuleHandle(NULL);
    pAddr = (PBYTE)hMod;
    pAddr += *((DWORD*)&pAddr[0x3C]);
    dwRVA = *((DWORD*)&pAddr[0x80]);
    pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)hMod + dwRVA);
    for (; pImportDesc->Name; pImportDesc++)
    {
        szLibName = (LPCSTR)((DWORD)hMod + pImportDesc->Name);
        if (!_stricmp(szLibName, szDllName))//对比导入表libname是否相同
        {
            pThunk = (PIMAGE_THUNK_DATA)((DWORD)hMod + pImportDesc->FirstThunk);
            for (; pThunk->u1.Function; pThunk++)//遍历函数
            {
                if (pThunk->u1.Function == (DWORD)pfnOrg)
                {
                    VirtualProtect((LPVOID)&pThunk->u1.Function, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READWRITE, &dwOldProtect);
                    pThunk->u1.Function = (DWORD)pfnNew;//hook
                    VirtualProtect((LPVOID)&pThunk->u1.Function, PAGE_EXECUTE_READWRITE, dwOldProtect, &dwOldProtect);
                    return TRUE;
                }
            }
        }
    }

    return FALSE;
}