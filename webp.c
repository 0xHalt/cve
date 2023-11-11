#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <assert.h>
#include <malloc.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>

// Original authors: github.com/catgirlasn

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

typedef uint64_t vp8l_accumulator_t;
typedef uint32_t vp8l_word_t;
#define HostToLE32(x) (x)
#define WordSwap HostToLE32
#define VP8L_WRITER_UNIT_SIZE    4   // sizeof(vp8l_word_t)
#define VP8L_WRITER_BIT_WIDTH    32  // 8 * sizeof(vp8l_word_t)
#define VP8L_WRITER_MAX_BITS     64  // 8 * sizeof(vp8l_accumulator_t)
#define MIN_EXTRA_BUFFER_SIZE    (32768ULL)

#define MAX_CODE_LENGTH_ALLOWED  15

#define SafeMalloc calloc // Simplified
#define SafeFree free // Simplified

typedef struct {
    size_t capacity;
    size_t used;
    uint8_t *buffer;
} MemoryArena;

MemoryArena temp_arena = {0};

void initialize_memory_arena(MemoryArena *arena, uint8_t *buffer, size_t capacity) {
    memset(arena, 0, sizeof(*arena));
    arena->capacity = capacity;
    arena->buffer = buffer;
}

void reset_memory_arena(MemoryArena *arena) {
    arena->used = 0;
}

void *allocate_memory(MemoryArena *arena, size_t size) {
    size_t remaining = arena->capacity - arena->used;
    assert(size <= remaining);
    uint8_t *result = &arena->buffer[arena->used];
    memset(result, 0, size);
    arena->used += size;
    return result;
}

void *allocate_array(MemoryArena *arena, size_t count, size_t type_size) {
    size_t size = count * type_size; // Integer overflow!
    void *result = allocate_memory(arena, size);
    return result;
}

#define allocate_array_type(arena, count, type) (type*) allocate_array(arena, count, sizeof(type))

typedef struct {
    vp8l_accumulator_t bits_;  // Bit accumulator
    int                used_;  // Number of bits used in accumulator
    uint8_t*           buf_;   // Start of buffer
    uint8_t*           cur_;   // Current write position
    uint8_t*           end_;   // End of buffer
    int                error_; // Error flag
} VP8LBitWriter;

int check_size_overflow(uint64_t size) {
    return size == (size_t)size;
}

uint32_t ByteSwap32(uint32_t x) {
    return (x >> 24) | ((x >> 8) & 0xff00) | ((x << 8) & 0xff0000) | (x << 24);
}

static int VP8LBitWriterResize(VP8LBitWriter* bw, size_t extra_size) {
    uint8_t* allocated_buf;
    size_t allocated_size;
    const size_t max_bytes = bw->end_ - bw->buf_;
    const size_t current_size = bw->cur_ - bw->buf_;
    const uint64_t size_required_64b = (uint64_t)current_size + extra_size;
    const size_t size_required = (size_t)size_required_64b;
    if (size_required != size_required_64b) {
        bw->error_ = 1;
        return 0;
    }
    if (max_bytes > 0 && size_required <= max_bytes) return 1;
    allocated_size = (3 * max_bytes) >> 1;
    if (allocated_size < size_required) allocated_size = size_required;
    // Make allocated size a multiple of 1k
    allocated_size = (((allocated_size >> 10) + 1) << 10);
    allocated_buf = (uint8_t*)SafeMalloc(1ULL, allocated_size);
    if (allocated_buf == NULL) {
        bw->error_ = 1;
        return 0;
    }
    if (current_size > 0) {
        memcpy(allocated_buf, bw->buf_, current_size);
    }
    SafeFree(bw->buf_);
    bw->buf_ = allocated_buf;
    bw->cur_ = bw->buf_ + current_size;
    bw->end_ = bw->buf_ + allocated_size;
    return 1;
}

int VP8LBitWriterInit(VP8LBitWriter* bw, size_t expected_size) {
    memset(bw, 0, sizeof(*bw));
    return VP8LBitWriterResize(bw, expected_size);
}

void VP8LPutBitsFlushBits(VP8LBitWriter* bw) {
    // Flush bits if needed
    if (bw->cur_ + VP8L_WRITER_UNIT_SIZE > bw->end_) {
        const uint64_t extra_size = (bw->end_ - bw->buf_) + MIN_EXTRA_BUFFER_SIZE;
        if (!check_size_overflow(extra_size) ||
                !VP8LBitWriterResize(bw, (size_t)extra_size)) {
            bw->cur_ = bw->buf_;
            bw->error_ = 1;
            return;
        }
    }
    *(vp8l_word_t*)bw->cur_ = (vp8l_word_t)WordSwap((vp8l_word_t)bw->bits_);
    bw->cur_ += VP8L_WRITER_UNIT_SIZE;
    bw->bits_ >>= VP8L_WRITER_BIT_WIDTH;
    bw->used_ -= VP8L_WRITER_BIT_WIDTH;
}

void VP8LPutBits(VP8LBitWriter* bw, uint32_t bits, int n_bits) {
    if (n_bits > 0) {
        if (bw->used_ >= 32) {
            VP8LPutBitsFlushBits(bw);
        }
        bw->bits_ |= (vp8l_accumulator_t)bits << bw->used_;
        bw->used_ += n_bits;
    }
}

uint8_t* VP8LBitWriterFinish(VP8LBitWriter* bw) {
    // Flush leftover bits
    if (VP8LBitWriterResize(bw, (bw->used_ + 7) >> 3)) {
        while (bw->used_ > 0) {
            *bw->cur_++ = (uint8_t)bw->bits_;
            bw->bits_ >>= 8;
            bw->used_ -= 8;
        }
        bw->used_ = 0;
    }
    return bw->buf_;
}

size_t VP8LBitWriterNumBytes(VP8LBitWriter* bw) {
    return (bw->cur_ - bw->buf_) + ((bw->used_ + 7) >> 3);
}

#pragma pack(push, 1)

typedef struct { 
    uint8_t riff_magic[4];
    uint32_t riff_size;
    uint8_t webp_magic[4];
    uint8_t vp8l_magic[4];
    uint32_t vp8l_size;
} RiffHeader;
#pragma pack(pop)

RiffHeader make_riff_header(size_t riff_size, size_t vp8l_size) {
    RiffHeader result = {0};
    result.riff_size = riff_size;
    result.vp8l_size = vp8l_size;
    
    memcpy(&result.riff_magic, "RIFF", 4);
    memcpy(&result.webp_magic, "WEBP", 4);
    memcpy(&result.vp8l_magic, "VP8L", 4);

    return result;
}


static const uint8_t kReversedBits[16] = {
    0x0, 0x8, 0x4, 0xc, 0x2, 0xa, 0x6, 0xe,
    0x1, 0x9, 0x5, 0xd, 0x3, 0xb, 0x7, 0xf
};

static uint32_t ReverseBits(int num_bits, uint32_t bits) {
    uint32_t retval = 0;
    int i = 0;
    while (i < num_bits) {
        i += 4;
        retval |= kReversedBits[bits & 0xf] << (MAX_CODE_LENGTH_ALLOWED + 1 - i);
        bits >>= 4;
    }
    retval >>= (MAX_CODE_LENGTH_ALLOWED + 1 - num_bits);
    return retval;
}

static void ConvertBitDepthsToSymbols(uint32_t* code_lengths, int len, uint32_t *codes) {
    uint32_t next_code[MAX_CODE_LENGTH_ALLOWED + 1] = {0};
    int depth_count[MAX_CODE_LENGTH_ALLOWED + 1] = {0};

    for (int i = 0; i < len; ++i) {
        ++depth_count[code_lengths[i]];
    }
    next_code[0] = 0;
    uint32_t code = 0;
    for (int i = 1; i <= MAX_CODE_LENGTH_ALLOWED; ++i) {
        code = (code + depth_count[i - 1]) << 1;
        next_code[i] = code;
    }
    for (int i = 0; i < len; ++i) {
        if (code_lengths[i] != 0) {
            codes[i] = ReverseBits(code_lengths[i], next_code[code_lengths[i]]++);
        }
    }
}

void CalculateCodeLengths(uint32_t* histogram, uint32_t count) {
    if (count < 2) {
        for (uint32_t i = 0; i < count; ++i) {
            histogram[i] = count - 1;
        }
        return;
    }


}

// [Additional functions for image crafting, including write_symbol, write_code_lengths, write_header, and craft_webp]

int main(int argc, char **argv) {
    char *filename = NULL;
    if (argc == 2) {
        filename = argv[1];
    } else {
        printf("USAGE: craft_webp <filename>\n");
        return 0;
    }
    
    size_t temp_buffer_size = 0x10000;
    uint8_t* temp_buffer = (uint8_t*)malloc(temp_buffer_size);
    assert(temp_buffer != NULL);
    
    initialize_memory_arena(&temp_arena, temp_buffer, temp_buffer_size);
    
    craft_webp(filename);
    
    free(temp_buffer);
    return 0;
}

