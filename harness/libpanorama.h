#ifndef _PANORAMA_H
#define _PANORAMA_H

#include <err.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/io.h>

#define PANORAMA_MAGICK 0x10410150666UL
#define PANORAMA_PORT 34
#define xstr(__a) str(__a)
#define str(__a) #__a

typedef struct {
	uint8_t* data;
	uint64_t len;
} panorama_payload_t;

typedef enum {
	PANORAMA_INIT = 0,
	PANORAMA_SET_PAYLOAD = 1,
	PANORAMA_SNAPSHOT = 2,
	PANORAMA_RESTORE = 3,
} hypercall_t;

static inline uint64_t panorama_hypercall2(
	uint64_t hc,
	uint64_t p1,
	uint64_t p2
) {
	uint64_t ret = 0;

	asm volatile (
		"out " xstr(PANORAMA_PORT) ", al"
		: "=a" (ret)
		: "a"(hc), "b"(p1), "c"(p2));
	return ret;
}

static inline uint64_t panorama_hypercall1(uint64_t hc, uint64_t p1) {
	return panorama_hypercall2(hc, p1, 0);
}

static inline uint64_t panorama_hypercall0(uint64_t hc) {
	return panorama_hypercall2(hc, 0, 0);
}

static inline uint64_t panorama_init() {
	if (ioperm(PANORAMA_PORT, 3, 3) < 0)
		err(EXIT_FAILURE, "ioperm");
	return panorama_hypercall0(PANORAMA_INIT) == PANORAMA_MAGICK;
}

static inline uint64_t panorama_set_payload(panorama_payload_t* payload) {
	return panorama_hypercall1(PANORAMA_SET_PAYLOAD, (uint64_t)payload);
}

static inline uint64_t panorama_snapshot() {
	return panorama_hypercall0(PANORAMA_SNAPSHOT);
}

static inline uint64_t panorama_restore(uint64_t keep) {
	return panorama_hypercall1(PANORAMA_RESTORE, keep);
}

#endif
