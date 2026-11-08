#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

extern int chained_probe(int mode, int (*callback)(void));
extern int tail_probe(int mode);
static int throw_from_chain;
__declspec(noinline) static int trace_callback(void) {
    void* frames[32] = {0};
    if (throw_from_chain) RaiseException(0xE1234567, 0, 0, NULL);
    return CaptureStackBackTrace(0, 32, frames, NULL) >= 3 ? 77 : -1;
}
__declspec(dllexport) __declspec(noinline) int seh_chain(int mode) {
    int answer;
    __try { answer = chained_probe(mode, trace_callback); }
    __except (EXCEPTION_EXECUTE_HANDLER) { answer = 333; }
    return answer;
}

__declspec(noinline) static int filtered(unsigned long code) {
    return code == 0xE1234567 || code == EXCEPTION_ACCESS_VIOLATION;
}

__declspec(noinline) static void fault(int mode) {
    if (mode == 1) RaiseException(0xE1234567, 0, 0, NULL);
    if (mode == 2) *(volatile int*)0 = 17;
}

__declspec(dllexport) __declspec(noinline) int seh_probe(int mode) {
    volatile int answer = 10;
    __try {
        answer += 3;
        fault(mode);
        answer += 5;
    } __except (filtered(GetExceptionCode())) {
        answer += 100;
    }
    return answer;
}

__declspec(dllexport) __declspec(noinline) int seh_nested(int mode) {
    volatile int value = 1;
    __try {
        __try {
            fault(mode);
            value += 3;
        } __finally {
            value += AbnormalTermination() ? 10 : 20;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        value += 100;
    }
    return value;
}

int main(int argc, char** argv) {
    int mode = argc > 1 ? atoi(argv[1]) : 0;
    throw_from_chain = mode == 3;
    printf("%d %d %d %d\n", seh_probe(mode), seh_nested(mode), seh_chain(mode), tail_probe(mode));
    return 0;
}
