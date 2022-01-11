// modified from https://git.musl-libc.org/cgit/musl/tree/include/endian.h
#ifndef _ENDIAN_H
#define _ENDIAN_H

static __inline uint16_t __bswap16(uint16_t __x) { return __x << 8 | __x >> 8; }

static __inline uint32_t __bswap32(uint32_t __x) {
  return __x >> 24 | ((__x >> 8) & 0xff00) | ((__x << 8) & 0xff0000) |
         __x << 24;
}

static __inline uint64_t __bswap64(uint64_t __x) {
  return (__bswap32(__x) + 0ULL) << 32 | __bswap32(__x >> 32);
}

#define htobe16(x) __bswap16(x)
#define be16toh(x) __bswap16(x)
#define htobe32(x) __bswap32(x)
#define be32toh(x) __bswap32(x)
#define htobe64(x) __bswap64(x)
#define be64toh(x) __bswap64(x)
#define htole16(x) (uint16_t)(x)
#define le16toh(x) (uint16_t)(x)
#define htole32(x) (uint32_t)(x)
#define le32toh(x) (uint32_t)(x)
#define htole64(x) (uint64_t)(x)
#define le64toh(x) (uint64_t)(x)

#define betoh16(x) __bswap16(x)
#define betoh32(x) __bswap32(x)
#define betoh64(x) __bswap64(x)
#define letoh16(x) (uint16_t)(x)
#define letoh32(x) (uint32_t)(x)
#define letoh64(x) (uint64_t)(x)

#endif


