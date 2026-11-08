#include <windows.h>
#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <thread>
#include <vector>

extern "C" __declspec(dllexport) __declspec(noinline) int compute(int n) {
    int total = 0;
    for (int i = 0; i < n; ++i) {
        if (i % 3 == 0) total += i;
        else if (i % 3 == 1) total -= i;
        else total += 2 * i;
    }
    return total;
}

__declspec(noinline) int dispatch(int n) {
    switch (n) {
        case 0: return 11; case 1: return 31; case 2: return 7;
        case 3: return 29; case 4: return 13; case 5: return 41;
        default: return -1;
    }
}

struct Cleanup {
    int& count;
    ~Cleanup() { ++count; }
};

__declspec(noinline) int exceptions() {
    int count = 0;
    try {
        Cleanup outer{count};
        try {
            Cleanup inner{count};
            throw std::runtime_error("expected");
        } catch (const std::exception&) {
            ++count;
            throw;
        }
    } catch (const std::exception&) {
        ++count;
    }
    return count;
}

__declspec(noinline) bool capture() {
    void* addresses[32] = {};
    return CaptureStackBackTrace(0, 32, addresses, nullptr) >= 4;
}

extern "C" __declspec(dllexport) __declspec(noinline) bool walk(int depth) {
    if (depth > 0) { bool ok = walk(depth - 1); return ok && depth < 32; }
    const bool ok = capture();
    return ok && depth == 0;
}

int main(int argc, char** argv) {
    const char* mode = argc > 1 ? argv[1] : "";
    if (std::strcmp(mode, "compute") == 0) std::printf("%d\n", compute(100));
    else if (std::strcmp(mode, "exceptions") == 0) std::printf("%d\n", exceptions());
    else if (std::strcmp(mode, "callback") == 0) {
        int (*volatile callback)(int) = compute;
        std::printf("%d\n", callback(100));
    } else if (std::strcmp(mode, "switch") == 0) {
        int sum = 0; for (int i = 0; i < 8; ++i) sum += dispatch(i);
        std::printf("%d\n", sum);
    } else if (std::strcmp(mode, "sort") == 0) {
        std::vector<int> v{9, -1, 5, 5, 3};
        std::stable_sort(v.begin(), v.end());
        for (auto n : v) std::printf("%d ", n);
        std::puts("");
    } else if (std::strcmp(mode, "threads") == 0) {
        std::atomic<int> count{0};
        std::thread a([&] { for (int i = 0; i < 1000; ++i) ++count; });
        std::thread b([&] { for (int i = 0; i < 1000; ++i) ++count; });
        a.join(); b.join(); std::printf("%d\n", count.load());
    } else if (std::strcmp(mode, "stackwalk") == 0) {
        std::printf("%s\n", walk(5) ? "ok" : "failed");
    } else {
        std::fputs("unknown command\n", stderr); return 2;
    }
    return 0;
}

#ifdef NATIVE_DLL
extern "C" __declspec(dllexport) int run_case(const char* mode) {
    char program[] = "native_dll";
    char* args[] = {program, const_cast<char*>(mode)};
    const int result = main(2, args);
    std::fflush(nullptr);
    return result;
}
#endif
