#pragma once

namespace tls {
	static unsigned long tlsValue;
	bool* getThreadDataPointer();
	bool setThreadHandlingSyscall(bool value);
	bool isThreadHandlingSyscall();
}