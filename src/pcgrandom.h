#ifndef PCGRANDOM_H
#define PCGRANDOM_H

/* PCG Random Number Generation
 * Adapted from http://www.pcg-random.org
 *
 * To get the implementation, define PCGRANDOM_IMPLEMENTATION.
 * Optionally define PCGRANDOM_API to control the API's visibility
 * and/or linkage (static, __attribute__, __declspec).
 */

#include <inttypes.h>

#ifndef PCGRANDOM_API
#define PCGRANDOM_API
#endif

struct pcgstate {
    uint64_t state;
    uint64_t inc;
};

/* Initialize generator. */
PCGRANDOM_API
void pcg_seed(struct pcgstate *rng, uint64_t initstate, uint64_t initseq);

/* Initialize generator by reading entropy on /dev/urandom.
 * Return false on error. */
PCGRANDOM_API
int pcg_entropy(struct pcgstate *rng);

/* Generate a uniformly distributed 32-bit random number. */
PCGRANDOM_API
uint32_t pcg_rand(struct pcgstate *rng);

/* Generate a uniformly distributed number r, where 0 <= r < bound */
PCGRANDOM_API
uint32_t pcg_boundedrand(struct pcgstate *rng, uint32_t bound);

/* Implementation. */
#ifdef PCGRANDOM_IMPLEMENTATION

#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>

PCGRANDOM_API
void
pcg_seed(struct pcgstate *rng, uint64_t initstate, uint64_t initseq)
{
    rng->state = 0U;
    rng->inc = (initseq << 1u) | 1u;
    pcg_rand(rng);
    rng->state += initstate;
    pcg_rand(rng);
}

PCGRANDOM_API
int
pcg_entropy(struct pcgstate *rng)
{
    int fd, sz;
    uint64_t seeds[2];

    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
        return 0;

    sz = read(fd, (void*)seeds, sizeof(seeds));
    pcg_seed(rng, seeds[0], seeds[1]);
    return (close(fd) == 0) && (sz == sizeof(seeds));
}

PCGRANDOM_API
uint32_t
pcg_rand(struct pcgstate *rng)
{
    uint64_t oldstate;
    uint32_t xorshifted, rot;

    oldstate = rng->state;
    rng->state = oldstate * 6364136223846793005ULL + rng->inc;
    xorshifted = ((oldstate >> 18u) ^ oldstate) >> 27u;
    rot = oldstate >> 59u;
    return (xorshifted >> rot) | (xorshifted << ((-rot) & 31));
}

PCGRANDOM_API
uint32_t
pcg_boundedrand(struct pcgstate *rng, uint32_t bound)
{
    uint32_t r, threshold = -bound % bound;

    /* Uniformity garantees that we end the loop! */
    for (;;) {
        r = pcg_rand(rng);
        if (r >= threshold)
            return r % bound;
    }
}

#endif /* PCGRANDOM_IMPLEMENTATION */
#endif /* PCGRANDOM_H */
