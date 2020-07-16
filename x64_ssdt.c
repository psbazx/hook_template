#include <ntddk.h>
#include <intrin.h>

NTKERNELAPI UCHAR* PsGetProcessImageFileName(PEPROCESS EProcess);
NTKERNELAPI UCHAR* PsLookupProcessByProcessId(IN ULONG ulProcId, OUT PEPROCESS* pEProcess);
typedef unsigned long       DWORD;
//定义ssdt结构
typedef struct _SERVICES_DESCRIPTOR_TABLE {     
    PVOID ServiceTableBase;									// The Base of SSDT
    PVOID ServiceCounterTableBase;
    ULONGLONG ServiceCount;									// The Count of SSDT Function 
    PVOID ParamTableBase;
}SERVICES_DESCRIPTOR_TABLE, * PSERVICES_DESCRIPTOR_TABLE;

typedef NTSTATUS(NTAPI* NTOPENPROCESS)(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PCLIENT_ID ClientId
    );

NTOPENPROCESS originNtOpenProcess = NULL;//用来保存openprocess地址
ULONG originAddress[1000];
//UCHAR origincode[20];
VOID wpOff();//关闭
VOID wpOn();//写保护函数，主要是修改cr0寄存器，但是有一定风险比如核切换。。。所以测试时虚拟机分配单核
UINT64 getKeServiceDescirptorTable();//获取ssdt
UINT64 getSsdtFunctionAddress(UINT32 index);//获取函数地址
VOID initinlinehook(UINT32 index);//inline hook 跳板函数
VOID ssdtHook(UINT32 index);
UINT64 getFunctionCount();//获取ssdt中函数偏移个数
VOID ssdtUnhook(UINT32 index);
NTSTATUS NTAPI myNtOpenProcess(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PCLIENT_ID ClientId);


VOID Unload(IN PDRIVER_OBJECT pDriverObject)
{
    ssdtUnhook(0x26);
    DbgPrint("drive unload");
	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT  pDriverObject, IN PUNICODE_STRING  RegistryPath) 
{
    int nCount = getFunctionCount();
    PSERVICES_DESCRIPTOR_TABLE p = (PSERVICES_DESCRIPTOR_TABLE)getKeServiceDescirptorTable();
    PULONG ssdt = (PULONG)p->ServiceTableBase;
    wpOff();
    for (int i = 0; i < nCount; i++)
    {
        originAddress[i] = ssdt[i];
    }
    wpOn();
    DbgPrint("start_hook");
    ssdtHook(0x69);
    DbgPrint("done!!!");
	pDriverObject->DriverUnload = Unload;
	return STATUS_SUCCESS;

}

VOID wpOff()
{

#ifdef _WIN64
    __writecr0(__readcr0() & (~(0x10000)));

#else
    __asm
    {
        push  eax
        mov    eax, CR0
        and eax, not 0x10000
        mov    CR0, eax
        pop    eax
    }
#endif

}

VOID wpOn()
{

#ifdef _WIN64
    __writecr0(__readcr0() | 0x10000);

#else
    __asm
    {
        push  eax
        mov    eax, CR0
        or eax, 0x10000
        mov    CR0, eax
        pop    eax
    }
#endif

}

NTSTATUS NTAPI myNtOpenProcess(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PCLIENT_ID ClientId)
{
    PEPROCESS process = 0;
    if (STATUS_SUCCESS == PsLookupProcessByProcessId(ClientId->UniqueProcess, &process))
    {
        if (strcmp(PsGetProcessImageFileName(process), "notepad.exe") == 0)
        {
            return STATUS_PNP_INVALID_ID;
        }
    }
    return originNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}
UINT64 getKeServiceDescirptorTable()
{
    UINT64 KeServiceDescirptorTable = 0;
    PUCHAR addrStartSearch = (PUCHAR)__readmsr((ULONG)(0xC0000082)); //KiSystemCall64Shadow or KiSystemCall64
    PUCHAR addrEndSearch = 0;
    if (*(addrStartSearch + 0x9) == 0x00)
    {
        addrEndSearch = addrStartSearch + 0x500;
    }
    else if (*(addrStartSearch + 0x9) == 0x70)//这边可能不同版本有区别比如2004就是0x90
    {
        PUCHAR pKiSystemCall64Shadow = addrStartSearch;
        PUCHAR EndSearchAddress = pKiSystemCall64Shadow + 0x500;
        PUCHAR i = NULL;
        INT Temp = 0;
        for (i = pKiSystemCall64Shadow; i < EndSearchAddress; i++)
        {
            if (MmIsAddressValid(i) && MmIsAddressValid(i + 5))
            {
                if (*i == 0xe9 && *(i + 5) == 0xc3)
                {
                    memcpy(&Temp, i + 1, 4);
                    addrStartSearch = Temp + (i + 5); 
                    addrEndSearch = addrStartSearch + 0x500;
                }
            }
        }
    }
    ULONG tmpAddress = 0;
    int j = 0;
    for (PUCHAR i = addrStartSearch; i < addrEndSearch; i++, j++)
    {
        if (MmIsAddressValid(i) && MmIsAddressValid(i + 1) && MmIsAddressValid(i + 2))
        {
            if (addrStartSearch[j] == 0x4c &&
                addrStartSearch[j + 1] == 0x8d &&
                addrStartSearch[j + 2] == 0x15)
            {
                RtlCopyMemory(&tmpAddress, i + 3, 4);  
                KeServiceDescirptorTable = tmpAddress + (INT64)i + 7;
            }
        }
    }
    return KeServiceDescirptorTable;
}
UINT64 getSsdtFunctionAddress(UINT32 index)
{
    INT64 address = 0;
    PSERVICES_DESCRIPTOR_TABLE pServiceDescriptorTable = (PSERVICES_DESCRIPTOR_TABLE)getKeServiceDescirptorTable();
    PULONG ssdt = (PULONG)pServiceDescriptorTable->ServiceTableBase;
    ULONG  dwOffset = ssdt[index];
    dwOffset >>= 4;           
    address = (UINT64)ssdt + dwOffset; 
    //DbgPrint("0x%llX\n", address);
    return address;
}
VOID initinlinehook(UINT32 index)
{
    UCHAR jmpCode[13] = "\x48\xB8\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00\xFF\xE0";
    UINT64 proxyFunction;
    UINT64 AAA = getSsdtFunctionAddress(index);
    proxyFunction = (UINT64)myNtOpenProcess;  
    RtlCopyMemory(jmpCode + 2, &proxyFunction, 8);
    wpOff();  
    memset(AAA, 0x90, 15);  
    RtlCopyMemory(AAA, jmpCode, 12); 
    wpOn();    
    return;
}


VOID ssdtHook(UINT32 index)
{
    PSERVICES_DESCRIPTOR_TABLE pKeServiceDescriptorTable = (PSERVICES_DESCRIPTOR_TABLE)getKeServiceDescirptorTable();
    PULONG pSsdt = (PULONG)pKeServiceDescriptorTable->ServiceTableBase;
    originNtOpenProcess = (NTOPENPROCESS)getSsdtFunctionAddress(0x26);
    initinlinehook(index);
    wpOff();
    pSsdt[0x26] = pSsdt[index];  // SSDT HOOK
    wpOn();
    return;
}
UINT64 getFunctionCount()
{
    PSERVICES_DESCRIPTOR_TABLE pKeServiceDescriptorTable;
    pKeServiceDescriptorTable = (PSERVICES_DESCRIPTOR_TABLE)getKeServiceDescirptorTable();
    return (UINT64)(pKeServiceDescriptorTable->ServiceCount);

}
VOID ssdtUnhook(UINT32 index)
{
    int nCount = getFunctionCount();
    PSERVICES_DESCRIPTOR_TABLE p = (PSERVICES_DESCRIPTOR_TABLE)getKeServiceDescirptorTable();
    PULONG ssdt = (PULONG)p->ServiceTableBase;
    wpOff();
    for (int i = 0; i < nCount; i++)
    {
        ssdt[i] = originAddress[i];
    }
    wpOn();
}
