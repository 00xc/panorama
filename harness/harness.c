#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <nftables/nftables/libnftables.h>

#include "libpanorama.h"

#define PAGE_SIZE (0x1000UL)
#define MAX_BUF_LEN (PAGE_SIZE * 4)

typedef uint64_t u64;

void* mmap_anon(size_t len) {
	void* ptr = mmap(
		NULL,
		len,
		PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS,
		-1,
		0
	);
	if (ptr == MAP_FAILED)
		err(EXIT_FAILURE, "mmap");
	return ptr;
}

panorama_payload_t* create_payload() {
	panorama_payload_t* payload;

	payload = (panorama_payload_t*)mmap_anon(PAGE_SIZE);
	payload->len = MAX_BUF_LEN - 1;
	payload->data = (uint8_t*)mmap_anon(MAX_BUF_LEN);
	return payload;
}

void free_payload(panorama_payload_t* payload) {
	if (munlock(payload->data, payload->len) != 0)
		warn("munlock");
	if (munmap(payload->data, MAX_BUF_LEN) != 0)
		warn("munmap");
	if (munmap(payload, PAGE_SIZE) != 0)
		warn("munmap");
}

struct nft_ctx* new_ctx() {
	struct nft_ctx *ctx;

	ctx = nft_ctx_new(NFT_CTX_DEFAULT);
	if (!ctx)
		err(EXIT_FAILURE, "nft_ctx_new");
	nft_ctx_output_set_flags(ctx, NFT_CTX_OUTPUT_JSON);
	nft_ctx_output_set_debug(ctx, 0);

	return ctx;
}

u64 virt2phys(volatile void* p) {
	int fd;
	u64 offset;
	u64 virt = (u64)p;
	u64 phys;

	// Assert page alignment
	assert((virt & 0xfff) == 0);

	fd = open("/proc/self/pagemap", O_RDONLY);
	if (fd == -1)
		err(EXIT_FAILURE, "open");

	offset = (virt / 0x1000) * 8;
	lseek(fd, offset, SEEK_SET);

	if (read(fd, &phys, 8) != 8)
		err(EXIT_FAILURE, "read");
	close(fd);

	// Assert page present
	assert(phys & (1ULL << 63));

	phys = (phys & ((1ULL << 54) - 1)) * 0x1000;
	return phys;
}

void disable_buffering() {
	if (setvbuf(stdout, NULL, _IONBF, 0) != 0)
		err(EXIT_FAILURE, "setvbuf");
	if (setvbuf(stderr, NULL, _IONBF, 0) != 0)
		err(EXIT_FAILURE, "setvbuf");
}

void wait_for_init() {
	sync();
	warnx("Waiting 2s for system init\n");
	sleep(4);
}

void setup_sched() {
	int prio;
	struct sched_param param;

	errno = 0;
	if (nice(-20) == -1 && errno != 0)
		err(EXIT_FAILURE, "nice");

	prio = sched_get_priority_max(SCHED_FIFO);
	if (prio == -1)
		err(EXIT_FAILURE, "sched_get_priority_max");

	param.sched_priority = prio;
	if (sched_setscheduler(getpid(), SCHED_FIFO, &param) != 0)
		err(EXIT_FAILURE, "sched_setscheduler");
}

void segfault(int signum) {
	(void)signum;
	if (panorama_restore(2) == 0)
		errx(EXIT_FAILURE, "could not restore");
}

int main(int argc, const char* argv[]) {
	panorama_payload_t* payload;
	//char* json = NULL;
	struct nft_ctx* ctx;
	size_t input_len;
	int ret = 1;
	FILE* devnull = NULL;

	if (signal(SIGSEGV, segfault) != 0)
		err(EXIT_FAILURE, "signal");

	(void)argc;
	(void)argv;
	disable_buffering();

	ctx = new_ctx();
	devnull = fopen("/dev/null", "w");
	if (devnull == NULL)
		err(EXIT_FAILURE, "fopen");
	nft_ctx_set_error(ctx, devnull);

	payload = create_payload();
	warnx("PAYLOAD vaddr=%p, paddr=0x%lx\n",
		(void*)payload, virt2phys(payload));

	if (panorama_init() == 0)
		errx(EXIT_FAILURE, "could not init");

	setup_sched();

	if (mlockall(MCL_CURRENT) != 0)
		err(EXIT_FAILURE, "mlockall");

	if (panorama_set_payload(payload) == 0)
		errx(EXIT_FAILURE, "could not set payload");

	wait_for_init();

	input_len = panorama_snapshot();
	if (input_len == 0)
		errx(EXIT_FAILURE, "could not snapshot: %lu\n", input_len);

	ret = nft_run_cmd_from_buffer(ctx, (const char*)payload->data);
	if (panorama_restore(ret == 0) == 0)
		errx(EXIT_FAILURE, "could not restore");

	/* Should never be reached, but just in case */
	free_payload(payload);
	nft_ctx_free(ctx);

	return EXIT_SUCCESS;
}
