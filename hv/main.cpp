#include "hv.h"

#include <ntddk.h>
#include <ia32.hpp>

extern "C" NTSTATUS ObReferenceObjectByHandleWithTagHookTrampoline(HANDLE Handle, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode,
    ULONG Tag, PVOID* Object, POBJECT_HANDLE_INFORMATION HandleInformation);

extern "C" uint8_t* g_bytepatch_addr = nullptr;

static uint8_t g_orig_bytes[12];

extern "C" char* PsGetProcessImageFileName(PEPROCESS Process);

NTSTATUS ObReferenceObjectByHandleWithTagHook(HANDLE Handle, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode,
    ULONG Tag, PVOID* Object, POBJECT_HANDLE_INFORMATION HandleInformation) 
{
    char* process_name = PsGetProcessImageFileName(PsGetCurrentProcess());
    if (strstr(process_name, "cheatengine") || strstr(process_name, "HyperCE"))
    {
        //DbgPrintEx(0, 0, "process_name %s\n", process_name);
        return ObReferenceObjectByHandleWithTagHookTrampoline(Handle, 0, ObjectType, KernelMode, Tag, Object, HandleInformation);
    }
    return ObReferenceObjectByHandleWithTagHookTrampoline(Handle, DesiredAccess, ObjectType, AccessMode, Tag, Object, HandleInformation);
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

  g_bytepatch_addr = (uint8_t*)ObReferenceObjectByHandleWithTag;
  DbgPrint("Bytepatch address: 0x%p.\n", g_bytepatch_addr);

  // copy the original bytes so we can restore them later
  memcpy(g_orig_bytes, g_bytepatch_addr, sizeof(g_orig_bytes));

  uint8_t new_bytes[12] = {
    0x48, 0xB8, 0x78, 0x56, 0x34, 0x12, 0x78, 0x56, 0x34, 0x12,
    0xFF, 0xE0,
  };

  *reinterpret_cast<void**>(new_bytes + 2) = ObReferenceObjectByHandleWithTagHook;

  auto const exec_page = (uint8_t*)ExAllocatePoolWithTag(NonPagedPool, 0x1000, 'pepe');

  // install our hook
  memcpy(exec_page, reinterpret_cast<void*>(reinterpret_cast<uint64_t>(g_bytepatch_addr) & ~0xFFFull), 0x1000);

  memcpy(exec_page + ((uint64_t)g_bytepatch_addr & 0xFFF), new_bytes, sizeof(new_bytes));

  for (size_t i = 0; i < KeQueryActiveProcessorCount(nullptr); ++i) {
      auto const orig_affinity = KeSetSystemAffinityThreadEx(1ull << i);

      hv::hypercall_input input;
      input.code = hv::hypercall_install_ept_hook;
      input.key = hv::hypercall_key;
      auto patch_phy = MmGetPhysicalAddress(g_bytepatch_addr).QuadPart >> 12;
      input.args[0] = patch_phy;
      auto exec_page_phy = MmGetPhysicalAddress(exec_page).QuadPart >> 12;
      input.args[1] = exec_page_phy;
      hv::vmx_vmcall(input);

      KeRevertToUserAffinityThreadEx(orig_affinity);
  }

  for (int i = 0; i < 12; ++i)
      DbgPrint("%.2X ", g_bytepatch_addr[i]);

  return STATUS_SUCCESS;
}

