// libFuzzer supplies main; Rust supplies the target callback. These COFF section
// bounds register Rust's SanitizerCoverage arrays without requiring ASan.
// LLVM emits counters in .SCOV$CM and PC pairs in .SCOVP$M, between these bounds.
#include <cstdint>
#pragma section(".SCOV$CA", read, write)
#pragma section(".SCOV$CZ", read, write)
#pragma section(".SCOVP$A", read)
#pragma section(".SCOVP$Z", read)
extern "C" {
__declspec(allocate(".SCOV$CA")) uint64_t __start___sancov_cntrs = 0;
__declspec(allocate(".SCOV$CZ")) uint8_t __stop___sancov_cntrs = 0;
__declspec(allocate(".SCOVP$A")) extern const uintptr_t __start___sancov_pcs = 0;
__declspec(allocate(".SCOVP$Z")) extern const uintptr_t __stop___sancov_pcs = 0;
}
