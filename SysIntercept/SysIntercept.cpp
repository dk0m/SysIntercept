#include <iostream>
#include "./src/headers/instrument.h"
#include<Windows.h>


int main()
{   
    // this example will demonstrate intercepting NtClose syscalls
    if (!instrument::run()) {
        printf("Failed To Set Up IC and VEH.\n");
        return -1;
    }
        
    printf("Successfully Set Up IC and VEH.\n");

    getchar();
    
    CloseHandle((HANDLE)-2); // wont be intercepted.

    getchar();

    CloseHandle((HANDLE)-2); // will be intercepted, and RCX will be -2

    getchar();

    return 0;
}
