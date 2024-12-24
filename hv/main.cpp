#include "hv.h"

#include <ntddk.h>
#include <ia32.hpp>

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

using fnObpReferenceObjectByHandleWithTag = NTSTATUS(__stdcall*)(HANDLE Handle, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode,
	ULONG Tag, PVOID* Object, POBJECT_HANDLE_INFORMATION HandleInformation, __int64 a0);
fnObpReferenceObjectByHandleWithTag old_ObpReferenceObjectByHandleWithTag = nullptr;

using fnNtQuerySystemInformation = NTSTATUS(__stdcall*)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
fnNtQuerySystemInformation old_NtQuerySystemInformation = nullptr;

extern "C" char* PsGetProcessImageFileName(PEPROCESS Process);


uint8_t* FindObpReferenceObjectByHandleWithTag() {
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
	//DbgPrintEx(0, 0, "[hv] process_name %s\n", process_name);
	if (strstr(process_name, "cheatengine") || strstr(process_name, "HyperCE"))
	{
		//DbgPrintEx(0, 0, "process_name %s\n", process_name);
		//return ObReferenceObjectByHandleWithTagHookTrampoline(Handle, 0, ObjectType, KernelMode, Tag, Object, HandleInformation);
		return old_ObpReferenceObjectByHandleWithTag(Handle, 0, ObjectType, KernelMode, Tag, Object, HandleInformation, a0);
	}
	//return ObReferenceObjectByHandleWithTagHookTrampoline(Handle, DesiredAccess, ObjectType, AccessMode, Tag, Object, HandleInformation);
	return old_ObpReferenceObjectByHandleWithTag(Handle, DesiredAccess, ObjectType, AccessMode, Tag, Object, HandleInformation, a0);
}

NTSTATUS NtQuerySystemInformationHook(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
	//DbgPrint("[hv] NtQuerySystemInformation hook called.\n");
	NTSTATUS stat = old_NtQuerySystemInformation(
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
	input.key = hv::hypercall_key;
	return hv::vmx_vmcall(input);
}

void driver_unload(PDRIVER_OBJECT) {
	UnInstallEptHook(ObReferenceObjectByHandleWithTag);

	UNICODE_STRING routineName;
	RtlInitUnicodeString(&routineName, L"NtQuerySystemInformation");
	const auto g_NtQuerySystemInformation = (uint8_t*)MmGetSystemRoutineAddress(&routineName);
	UnInstallEptHook(g_NtQuerySystemInformation);

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

	auto result = InstallEptHook(FindObpReferenceObjectByHandleWithTag(), ObpReferenceObjectByHandleWithTagHook, (void**)&old_ObpReferenceObjectByHandleWithTag);
	DbgPrint("[hv] ObReferenceObjectByHandleWithTag hook installed: %s.\n", result ? "success\n" : "failure\n");

	UNICODE_STRING routineName;
	RtlInitUnicodeString(&routineName, L"NtQuerySystemInformation");
	const auto g_NtQuerySystemInformation = (uint8_t*)MmGetSystemRoutineAddress(&routineName);
	result = InstallEptHook(g_NtQuerySystemInformation, NtQuerySystemInformationHook, (void**)&old_NtQuerySystemInformation);
	DbgPrint("[hv] NtQuerySystemInformation hook installed: %s.\n", result ? "success\n" : "failure\n");

	return STATUS_SUCCESS;
}

