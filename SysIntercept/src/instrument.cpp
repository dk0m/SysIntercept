#include "./headers/tls.h"
#include "./headers/ntapi.h"
#include "./headers/instrument.h"
#include<iostream>

#define PROCESS_INFO_CLASS_INSTRUMENTATION 40

extern "C" void Callback(PCONTEXT ctx);
extern "C" void bridge();

PVOID syscallRetAddr;
char patchSyscallArray[2] = { 0xCC, 0x90 };
char patchSyscallRetArray[3] = { 0x0f, 0x05, 0xc3 };

void patchSyscall(PVOID syscallInstr) {
	DWORD oldPro;
	VirtualProtect(syscallInstr, 2, PAGE_EXECUTE_READWRITE, &oldPro);

	memcpy(syscallInstr, &patchSyscallArray[0], 2);

	VirtualProtect(syscallInstr, 2, oldPro, &oldPro);
}

LONG exceptionHandler(PEXCEPTION_POINTERS pExceptionInfo) {

	if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) {

		// https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/windows-x64-calling-convention-stack-frame
	
		DWORD ssn = pExceptionInfo->ContextRecord->Rax;

		printf("Breakpoint Hit!\n");
		printf("Syscall SSN: %d\n", ssn);
		printf("First Argument (RCX): %ld\n", (DWORD)pExceptionInfo->ContextRecord->Rcx);

		pExceptionInfo->ContextRecord->Rip = (DWORD64)syscallRetAddr;

		return EXCEPTION_CONTINUE_EXECUTION;
	}
	else {
		return EXCEPTION_CONTINUE_SEARCH;
	}
}


void Callback(PCONTEXT ctx) {
	uint64_t currentTeb = (uint64_t)NtCurrentTeb();

	ctx->Rip = *(uint64_t*)(currentTeb + 0x02d8);
	ctx->Rsp = *(uint64_t*)(currentTeb + 0x02e0);
	ctx->Rcx = ctx->R10;


	if (tls::isThreadHandlingSyscall()) {
		RtlRestoreContext(ctx, nullptr);
	}

	if (!tls::setThreadHandlingSyscall(true)) {
		RtlRestoreContext(ctx, nullptr);
	}

	PVOID returnAddress = (PVOID)ctx->Rip;
	DWORD returnValue = (DWORD)ctx->Rax;

	DWORD_PTR returnAddr = (DWORD_PTR)returnAddress;
	WORD offset = 0;

	PVOID syscallInstr = NULL;
	DWORD ssn = 0;

	while (true) {

		if (*(PBYTE)(returnAddr + -offset) == 0x0f && *(PBYTE)(returnAddr + -(offset - 1)) == 0x05) {
			syscallInstr = (PVOID)(returnAddr + -offset);

			// accessing our stub (that we allocated) which isn't what we want
			if (syscallInstr == syscallRetAddr) {
				goto exit;
			}

		}

		// keep searching for mov eax, <ssn>
		if (*(PBYTE)(returnAddr + -offset) == 0xB8) {
			ssn = *(PDWORD)(returnAddr + -(offset - 1));
			break;
		}
		offset++;
	}

	// NtClose SSN, not the best approach for the sake of simplicity, better approach is to do a reverse search with the SSN to get the NTAPI function name and check that instead.
	if (ssn == 0xF) {
		patchSyscall(syscallInstr);
		printf("Patched (0x%p) An NtClose Syscall Stub, Next Time Its Called, VEH Handler Will Run With Code (EXCEPTION_BREAKPOINT).\n", syscallInstr);
	}

exit:
	tls::setThreadHandlingSyscall(false);
	RtlRestoreContext(ctx, nullptr);
}

bool allocateRedirectStub() {
	syscallRetAddr = VirtualAlloc(NULL, 3, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	memcpy(syscallRetAddr, &patchSyscallRetArray[0], 3);

	return syscallRetAddr != NULL;
}
bool instrument::run() {

	if (!allocateRedirectStub()) {
		printf("Failed To Allocate Redirect Stub.\n");
		return false;
	}

	AddVectoredExceptionHandler(1, exceptionHandler);

	tls::tlsValue = TlsAlloc();

	PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION nirvana;

	nirvana.Callback = (PVOID)(ULONG_PTR)bridge;
	nirvana.Reserved = 0;
	nirvana.Version = 0;

	NTSTATUS setIcStatus = NtSetInformationProcess(
		GetCurrentProcess(),
		(PROCESSINFOCLASS)PROCESS_INFO_CLASS_INSTRUMENTATION,
		&nirvana,
		sizeof(nirvana));

	if (NT_SUCCESS(setIcStatus)) {
		printf("Set Instrumention Callback Successfully.\n");
		return true;
	}
	else {
		printf("Failed To Set Instrumention Callback.\n");
		return false;
	}
}