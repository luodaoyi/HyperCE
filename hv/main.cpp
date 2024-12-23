#include "hv.h"

#include <ntddk.h>
#include <ia32.hpp>

extern "C" NTSTATUS ObpReferenceObjectByHandleWithTagHookTrampoline(HANDLE Handle, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode,
    ULONG Tag, PVOID* Object, POBJECT_HANDLE_INFORMATION HandleInformation, __int64 a0);

extern "C" uint8_t* g_ObpReferenceObjectByHandle = nullptr;

extern "C" char* PsGetProcessImageFileName(PEPROCESS Process);

uint8_t* find_bytepatch_address() {
    auto const pObReferenceObjectByHandleWithTag = reinterpret_cast<uint8_t*>(ObReferenceObjectByHandleWithTag);

    for (size_t offset = 0; offset < 0x100; ++offset) {
        auto const curr = pObReferenceObjectByHandleWithTag + offset;

        if (*curr == 0xE8)
        {
            return curr + 5 + *(int*)(curr + 1);
        }
    }

    return nullptr;
}

NTSTATUS ObpReferenceObjectByHandleWithTagHook(HANDLE Handle, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode,
    ULONG Tag, PVOID* Object, POBJECT_HANDLE_INFORMATION HandleInformation, __int64 a0)
{
    char* process_name = PsGetProcessImageFileName(PsGetCurrentProcess());
    if (strstr(process_name, "cheatengine") || strstr(process_name, "HyperCE"))
    {
        //DbgPrintEx(0, 0, "process_name %s\n", process_name);
        return ObpReferenceObjectByHandleWithTagHookTrampoline(Handle, 0, ObjectType, KernelMode, Tag, Object, HandleInformation, a0);
    }
    return ObpReferenceObjectByHandleWithTagHookTrampoline(Handle, DesiredAccess, ObjectType, AccessMode, Tag, Object, HandleInformation, a0);
}


typedef struct _SYSTEM_PROCESS_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize; // since VISTA
    ULONG HardFaultCount; // since WIN7
    ULONG NumberOfThreadsHighWatermark; // since WIN7
    ULONGLONG CycleTime; // since WIN7
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey; // since VISTA (requires SystemExtendedProcessInformation)
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation, // q: SYSTEM_BASIC_INFORMATION
    SystemProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
    SystemPerformanceInformation, // q: SYSTEM_PERFORMANCE_INFORMATION
    SystemTimeOfDayInformation, // q: SYSTEM_TIMEOFDAY_INFORMATION
    SystemPathInformation, // not implemented
    SystemProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
} SYSTEM_INFORMATION_CLASS;

extern "C" uint8_t* g_NtQuerySystemInformation = nullptr;

extern "C" NTSTATUS NtQuerySystemInformationHookTrampoline(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

NTSTATUS NtQuerySystemInformationHook(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
    NTSTATUS stat = NtQuerySystemInformationHookTrampoline(
        SystemInformationClass,
        SystemInformation,
        SystemInformationLength,
        ReturnLength);


    if (NT_SUCCESS(stat) && SystemInformationClass == SystemProcessInformation)
    {
        PSYSTEM_PROCESS_INFORMATION prev = PSYSTEM_PROCESS_INFORMATION(SystemInformation);
        PSYSTEM_PROCESS_INFORMATION curr = PSYSTEM_PROCESS_INFORMATION((PUCHAR)prev + prev->NextEntryOffset);

        while (prev->NextEntryOffset != NULL) {
            auto buffer = curr->ImageName.Buffer;
            if (buffer && (wcsstr(buffer, L"cheatengine") || wcsstr(buffer, L"HyperCE"))) {
                if (curr->NextEntryOffset == 0) {
                    prev->NextEntryOffset = 0;
                }
                else {
                    prev->NextEntryOffset += curr->NextEntryOffset;
                }
                curr = prev;
            }
            prev = curr;
            curr = PSYSTEM_PROCESS_INFORMATION((PUCHAR)curr + curr->NextEntryOffset);
        }
    }
    return stat;
}

// simple hypercall wrappers
static uint64_t ping() {
  hv::hypercall_input input;
  input.code = hv::hypercall_ping;
  input.key  = hv::hypercall_key;
  return hv::vmx_vmcall(input);
}

void driver_unload(PDRIVER_OBJECT) {
  hv::stop();

  DbgPrint("[hv] Devirtualized the system.\n"); 
  DbgPrint("[hv] Driver unloaded.\n");
}

NTSTATUS driver_entry(PDRIVER_OBJECT const driver, PUNICODE_STRING) {
  DbgPrint("[hv] Driver loaded.\n");

  if (driver)
    driver->DriverUnload = driver_unload;

  if (!hv::start()) {
    DbgPrint("[hv] Failed to virtualize system.\n");
    return STATUS_HV_OPERATION_FAILED;
  }

  if (ping() == hv::hypervisor_signature)
      DbgPrint("[client] Hypervisor signature matches.\n");
  else
      DbgPrint("[client] Failed to ping hypervisor!\n");


  {
      g_ObpReferenceObjectByHandle = find_bytepatch_address();
      DbgPrint("g_ObpReferenceObjectByHandle address: 0x%p.\n", g_ObpReferenceObjectByHandle);
      uint8_t new_bytes[0xe] = {
        0x48, 0xB8, 0x78, 0x56, 0x34, 0x12, 0x78, 0x56, 0x34, 0x12,
        0xFF, 0xE0,
        0x90,
        0x90,
      };

      *reinterpret_cast<void**>(new_bytes + 2) = ObpReferenceObjectByHandleWithTagHook;

      auto const exec_page = (uint8_t*)ExAllocatePoolWithTag(NonPagedPool, 0x1000, 'pepe');

      // install our hook
      memcpy(exec_page, reinterpret_cast<void*>(reinterpret_cast<uint64_t>(g_ObpReferenceObjectByHandle) & ~0xFFFull), 0x1000);

      memcpy(exec_page + ((uint64_t)g_ObpReferenceObjectByHandle & 0xFFF), new_bytes, sizeof(new_bytes));

      for (size_t i = 0; i < KeQueryActiveProcessorCount(nullptr); ++i) {
          auto const orig_affinity = KeSetSystemAffinityThreadEx(1ull << i);

          hv::hypercall_input input;
          input.code = hv::hypercall_install_ept_hook;
          input.key = hv::hypercall_key;
          auto patch_phy = MmGetPhysicalAddress(g_ObpReferenceObjectByHandle).QuadPart >> 12;
          input.args[0] = patch_phy;
          auto exec_page_phy = MmGetPhysicalAddress(exec_page).QuadPart >> 12;
          input.args[1] = exec_page_phy;
          hv::vmx_vmcall(input);

          KeRevertToUserAffinityThreadEx(orig_affinity);
      }
  }


  {
      UNICODE_STRING routineName;
      RtlInitUnicodeString(&routineName, L"NtQuerySystemInformation");
      g_NtQuerySystemInformation = (uint8_t*)MmGetSystemRoutineAddress(&routineName);
      DbgPrint("g_NtQuerySystemInformation address: 0x%p.\n", g_NtQuerySystemInformation);
      uint8_t new_bytes[0xc] = {
        0x48, 0xB8, 0x78, 0x56, 0x34, 0x12, 0x78, 0x56, 0x34, 0x12,
        0xFF, 0xE0,
      };

      *reinterpret_cast<void**>(new_bytes + 2) = NtQuerySystemInformationHook;

      auto const exec_page = (uint8_t*)ExAllocatePoolWithTag(NonPagedPool, 0x1000, 'pepe');

      // install our hook
      memcpy(exec_page, reinterpret_cast<void*>(reinterpret_cast<uint64_t>(g_NtQuerySystemInformation) & ~0xFFFull), 0x1000);

      memcpy(exec_page + ((uint64_t)g_NtQuerySystemInformation & 0xFFF), new_bytes, sizeof(new_bytes));

      for (size_t i = 0; i < KeQueryActiveProcessorCount(nullptr); ++i) {
          auto const orig_affinity = KeSetSystemAffinityThreadEx(1ull << i);

          hv::hypercall_input input;
          input.code = hv::hypercall_install_ept_hook;
          input.key = hv::hypercall_key;
          auto patch_phy = MmGetPhysicalAddress(g_NtQuerySystemInformation).QuadPart >> 12;
          input.args[0] = patch_phy;
          auto exec_page_phy = MmGetPhysicalAddress(exec_page).QuadPart >> 12;
          input.args[1] = exec_page_phy;
          hv::vmx_vmcall(input);

          KeRevertToUserAffinityThreadEx(orig_affinity);
      }
  }
  

  for (int i = 0; i < 12; ++i)
      DbgPrint("%.2X ", g_ObpReferenceObjectByHandle[i]);

  return STATUS_SUCCESS;
}

