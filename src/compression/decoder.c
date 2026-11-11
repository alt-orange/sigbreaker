// Windows x64 TLS callback for the optional compressed .sbrk section.
// Rebuild the embedded machine code with scripts/build_section_decoder.py.
#define Z7_LZMA_SIZE_OPT
#include "lzma_sdk/LzmaDec.c"

typedef struct {
    char magic[8];
    UInt32 target_rva;
    UInt32 target_size;
    UInt32 packed_rva;
    UInt32 packed_size;
    UInt32 protect_iat;
    UInt32 flush_iat;
    UInt32 alloc_iat;
    UInt32 free_iat;
    UInt32 fixups_rva;
    UInt32 fixups_count;
    UInt64 preferred_base;
} SectionConfig;

static const volatile SectionConfig config = {{'S','B','I','N','I','T','0','1'}};

typedef int (*Protect)(void *, SizeT, UInt32, UInt32 *);
typedef int (*Flush)(void *, const void *, SizeT);
typedef void *(*Allocate)(void *, SizeT, UInt32, UInt32);
typedef int (*Release)(void *, SizeT, UInt32);

typedef struct {
    ISzAlloc callbacks;
    Allocate allocate;
    Release release;
} DecoderAllocator;

void *memcpy(void *destination, const void *source, SizeT length) {
    Byte *out = (Byte *)destination;
    const Byte *in = (const Byte *)source;
    for (SizeT i = 0; i < length; ++i) out[i] = in[i];
    return destination;
}

void *memset(void *destination, int value, SizeT length) {
    Byte *out = (Byte *)destination;
    for (SizeT i = 0; i < length; ++i) out[i] = (Byte)value;
    return destination;
}

static void *allocate_probs(ISzAllocPtr allocator, SizeT length) {
    const DecoderAllocator *context = (const DecoderAllocator *)allocator;
    return context->allocate(0, length, 0x3000, 4); // reserve and commit read/write
}

static void release_probs(ISzAllocPtr allocator, void *allocation) {
    const DecoderAllocator *context = (const DecoderAllocator *)allocator;
    if (allocation) context->release(allocation, 0, 0x8000);
}

static void fail(void) {
    __fastfail(7);
}

void section_init(Byte *image, UInt32 reason, void *reserved) {
    (void)reserved;
    if (reason != 1) return; // DLL_PROCESS_ATTACH precedes original callbacks

    Protect protect = *(Protect *)(image + config.protect_iat);
    Flush flush = *(Flush *)(image + config.flush_iat);
    DecoderAllocator allocator = {
        {allocate_probs, release_probs},
        *(Allocate *)(image + config.alloc_iat),
        *(Release *)(image + config.free_iat)
    };
    Byte *destination = image + config.target_rva;
    const Byte *source = image + config.packed_rva;
    UInt32 original_protection, temporary_protection;
    if (!protect(destination, config.target_size, 4, &original_protection)) fail();

    CLzmaDec state;
    LzmaDec_Construct(&state);
    if (config.packed_size < 13 ||
        LzmaDec_AllocateProbs(&state, source, 5, &allocator.callbacks) != SZ_OK) fail();
    state.dic = destination;
    state.dicBufSize = config.target_size;
    LzmaDec_Init(&state);
    SizeT input_size = config.packed_size - 13;
    ELzmaStatus status;
    SRes result = LzmaDec_DecodeToDic(&state, config.target_size, source + 13,
                                    &input_size, LZMA_FINISH_END, &status);
    LzmaDec_FreeProbs(&state, &allocator.callbacks);
    if (result != SZ_OK || state.dicPos != config.target_size ||
        (status != LZMA_STATUS_FINISHED_WITH_MARK &&
         status != LZMA_STATUS_MAYBE_FINISHED_WITHOUT_MARK)) fail();

    // The Windows loader handles the remaining image's base relocations.
    // Apply .sbrk relocations after restoring its initialized bytes.
    UInt64 delta = (UInt64)image - config.preferred_base;
    const UInt32 *fixups = (const UInt32 *)(image + config.fixups_rva);
    for (UInt32 i = 0; i < config.fixups_count; ++i) {
        Byte *field = image + fixups[2 * i];
        if (fixups[2 * i + 1] == 10) *(UInt64 *)field += delta;
        else if (fixups[2 * i + 1] == 3) *(UInt32 *)field += (UInt32)delta;
        else fail();
    }
    if (!protect(destination, config.target_size, original_protection, &temporary_protection)) fail();
    if (!flush((void *)(SizeT)-1, destination, config.target_size)) fail();
}
