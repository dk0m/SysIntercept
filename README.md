
# SysIntercept

Intercepting & Hooking Direct System Calls With Instrumention Callbacks and Breakpoints.

## Explanation
Direct system calls have been used to evade many security solutions' detection mechanisms, Due to their inability to hook and intercept them using normal trampolines. Instrumention Callbacks were introduced to detect transitions from kernel mode to user mode which was very useful for detecting direct system calls, However this did not permit access to the arguments passed but just only the return value and return address which restricted detecting possibly malicious behaviour and made it hard for people to reverse evasive software. SysIntercept utilizes Instrumention Callbacks, Breakpoints and Vectored Exception Handlers to detect system calls, Searches for the ``syscall`` instruction and the syscall service number (``ssn``), Patches the syscall instruction with a breakpoint (``int3``), Registers a VEH that will detect breakpoint exceptions which will allow us to manipulate the arguments and the return value of the intercepted syscall and then sets the next instruction to be ``syscall, ret`` which will allow the syscall to be finally called after all of that interception.

## What It Can Be Useful For
This can be especially useful for reverse engineers and malware analysts trying to understand the logic behind an evasive piece of software.

## Showcase

![SysIntercept](https://i.imgur.com/27q6YZu.png)
