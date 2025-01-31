#include "./headers/tls.h"
#include<windows.h>


bool* tls::getThreadDataPointer() {
	void* thread_data = nullptr;
	bool* data_pointer = nullptr;

	thread_data = TlsGetValue(tlsValue);

	if (thread_data == nullptr) {
		thread_data = reinterpret_cast<void*>(LocalAlloc(LPTR, 256));

		if (thread_data == nullptr) {
			return nullptr;
		}

		RtlZeroMemory(thread_data, 256);


		if (!TlsSetValue(tlsValue, thread_data)) {
			return nullptr;
		}
	}

	data_pointer = reinterpret_cast<bool*>(thread_data);

	return data_pointer;
}

bool tls::setThreadHandlingSyscall(bool value) {
	if (auto data_pointer = getThreadDataPointer()) {
		*data_pointer = value;
		return true;
	}

	return false;
}

bool tls::isThreadHandlingSyscall() {
	if (auto data_pointer = getThreadDataPointer()) {
		return *data_pointer;
	}

	return false;
}