/* Encrypt streams with the Handycipher. Read the reference document:
 *   Handycipher: a Low-tech, Randomized, Symmetric-key Cryptosystem
 * by Bruce Kallick.
 */

#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <sys/errno.h>

#define PCGRANDOM_IMPLEMENTATION
#define PCGRANDOM_API static
#include "pcgrandom.h"

#define SHA256_IMPLEMENTATION
#include "sha256.h"

extern void fatal(const char *fmt, ...);
extern void warning(const char *fmt, ...);

/* The indexes  of the 20 directions in a 5x5 torus-matrix:
 * columns 0-4, rows 5-9, right diagonals 10-14, left diagonal 15-19. */
static const int directions[20][5] = {
    {0,5,10,15,20},{1,6,11,16,21},{2,7,12,17,22},{3,8,13,18,23},{4,9,14,19,24},
    {0,1,2,3,4},{5,6,7,8,9},{10,11,12,13,14},{15,16,17,18,19},{20,21,22,23,24},
    {0,6,12,18,24},{1,7,13,19,20},{2,8,14,15,21},{3,9,10,16,22},{4,5,11,17,23},
    {0,9,13,17,21},{1,5,14,18,22},{2,6,10,19,23},{3,7,11,15,24},{4,8,12,16,20}
};

/* The indexes of the non-colinear slots in a 5x5 torus-matrix:
 * from starting slot 0-24, we can knight-jump to 8 others. */
static const int knightjumps[25][8] = {
    {7,8,11,14,16,19,22,23},{8,9,10,12,15,17,23,24},{5,9,11,13,16,18,20,24},
    {5,6,12,14,17,19,20,21},{6,7,10,13,15,18,21,22},{2,3,12,13,16,19,21,24},
    {3,4,13,14,15,17,20,22},{0,4,10,14,16,18,21,23},{0,1,10,11,17,19,22,24},
    {1,2,11,12,15,18,20,23},{1,4,7,8,17,18,21,24},{0,2,8,9,18,19,20,22},
    {1,3,5,9,15,19,21,23},{2,4,5,6,15,16,22,24},{0,3,6,7,16,17,20,23},
    {1,4,6,9,12,13,22,23},{0,2,5,7,13,14,23,24},{1,3,6,8,10,14,20,24},
    {2,4,7,9,10,11,20,21},{0,3,5,8,11,12,21,22},{2,3,6,9,11,14,17,18},
    {3,4,5,7,10,12,18,19},{0,4,6,8,11,13,15,19},{0,1,7,9,12,14,15,16},
    {1,2,5,8,10,13,16,17}
};

/* The cipher main structure. */
struct handy {
    char key[51];
    char subkey[31];
    char code_mat[25];
    char null_mat[25];
    struct pcgstate random[1];
    int core;

    /* Context needed to encode a character */
    int prev_code;
    int prev_last;
    int prev_dir;
    int parity;
};

#define Key        cipher->key
#define Subkey     cipher->subkey
#define Code_mat   cipher->code_mat
#define Null_mat   cipher->null_mat
#define Random     cipher->random
#define Core       cipher->core
#define Prev_code  cipher->prev_code
#define Prev_last  cipher->prev_last
#define Prev_dir   cipher->prev_dir
#define Parity     cipher->parity

/* Maximum length of one encoded character:
 * (5 codes) + (4 noises) + (23 nulls) = 32. */
#define MAX_ENCODED_LEN  32

/* Input chunk size. */
#define CHUNK_SIZE  (MAX_ENCODED_LEN*1024)

/* A trace flag for the cipher. */
static int handy_trace = 0;

/* Return true if character C belongs to direction DIR. */
static int
has_direction(struct handy *cipher, int c, int dir)
{
    int i;

    for (i = 0; i < 5; i++)
        if (Code_mat[directions[dir][i]] == c)
            return 1;
    return 0;
}

/* Return the direction defined by characters A and B or -1 if not colinear. */
static int
get_direction(struct handy *cipher, int a, int b)
{
    int i, j, c, found;

    for (i = 0; i < 20; i++) {
        for (found = 0, j = 0; j < 5 && found < 2; j++) {
            c = Code_mat[directions[i][j]];
            if (c == a || c == b)
                found++;
        }
        if (found == 2)
            return i;
    }
    return -1;
}
/* Return true if characters A and B are colinear. */
static int
colinear(struct handy *cipher, int a, int b)
{
    int i, j;

    for (i = 0; i < 25; i++)
        if (Code_mat[i] == a)
            break;
    for (j = 0; j < 8; j++)
        if (Code_mat[knightjumps[i][j]] == b)
            return 0;
    return 1;
}

/* Return the column-direction that contains character C or -1 if not found. */
static int
get_column(struct handy *cipher, int c)
{
    int i, j;

    for (i = 0; i < 5; i++)
        for (j = i; j < i + 21; j += 5)
            if (Code_mat[j] == c)
                return i;
    return -1;
}

/* Return the code (1-31) of character C or 0 if not found. */
static int
get_code(struct handy *cipher, int c)
{
    int i;

    for (i = 0; i < sizeof(Subkey); i++)
        if (c == Subkey[i])
            return i + 1;
    fatal(isprint(c) ? "%s -- '%c'" : "%s -- %#04x",
            "cannot code character", c);
    return 0;
}

/* Return true if CODE (1-31) is a power of 2. */
static int
pow2(int code)
{
    return code == 1 || code == 2 || code == 4 || code == 8 || code == 16;
}

/* Shuffle a SET of N characters (modern Fisher-Yates). */
static void
shuffle(char *set, int n, struct pcgstate *rnd)
{
    int i, j;
    char tmp;

    for (i = n - 1; i > 0; i--) {
        j = (int) pcg_boundedrand(rnd, i + 1);
        if (i != j) {
            tmp = set[i];
            set[i] = set[j];
            set[j] = tmp;
        }
    }
}

/* Trace CIPHER on stdout. */
static void
trace_cipher(struct handy *cipher)
{
    int i, j;

    printf("Subkey: ");
    for (i = 0; i < sizeof(Subkey); i++)
        putchar(Subkey[i]);
    putchar('\n');
    for (i = 0; i < 25; i += 5) {
        for(j = 0; j < 5; j++) {
            putchar(Code_mat[i + j]);
            putchar(' ');
        }
        putchar ('|');
        for(j = 0; j < 5; j++) {
            putchar(' ');
            putchar(Null_mat[i + j]);
        }
        putchar('\n');
    }
    putchar('\n');
}

/* Trace direction DIR on stdout. */
static void
trace_direction(int dir)
{
    if (dir < 5)
        printf("C%-2d", dir + 1);
    else if (dir >= 5 && dir < 10)
        printf("R%-2d", dir - 4);
    else
        printf("D%-2d", dir - 9);
    putchar(' ');
}

/* Trace binary value of CODE (5 bits) on stdout. */
static void
trace_bcode(int code)
{
    int i;

    for (i = 16; i; i >>= 1)
        printf("%d", code & i ? 1 : 0);
    putchar(' ');
}

/* Initialize a new cipher. */
static void
init_cipher(struct handy *cipher, char *key, int core)
{
    char *p;
    int c, i, j;

    if (handy_trace) {
        printf("Key: ");
        for (i = 0; i < 51; i++)
            putchar(key[i]);
        putchar('\n');
    }
    memset(Key, 0, sizeof(Key));
    for (i = 0; i < sizeof(Key); i++) {
        c = key[i];
        if (c >= 'A' && c <= 'Y')
            j = c - 'A';
        else if (c >= 'a' && c <= 'y')
            j = c - 'a' + 25;
        else if (c == '^')
            j = 50;
        else
            fatal(isprint(c) ? "%s -- '%c'" : "%s -- %#04x",
                    "invalid character in key", c);
        if (Key[j])
            fatal("repeated character in key -- '%c'", c);
        Key[j]++;
    }
    memcpy(Key, key, sizeof(Key));

    for (p = Code_mat, i = 0, j = 0; i < sizeof(Key); i++) {
        if (key[i] == '^')
            continue;
        p[j++] = key[i];
        if (j % 5 == 0) {
            if (p == Code_mat) {
                p = Null_mat;
                j -= 5;
            }
            else
                p = Code_mat;
        }
    }

    for (i = 0, j = 0; j < sizeof(Subkey); i++) {
        c = key[i];
        if (c >= 'f' && c <= 'y')
            continue;
        switch (c) {
        case 'a':
            c = 'Z';
            break;
        case 'b':
            c = '.';
            break;
        case 'c':
            c = ',';
            break;
        case 'd':
            c = '?';
            break;
        case 'e':
            c = '-';
            break;
        }
        Subkey[j++] = c;
    }

    if (!pcg_entropy(Random))
        fatal("cannot initialize random source");

    Prev_code = 0;
    Prev_last = 0;
    Prev_dir = -1;
    Parity = 0;
    Core = core;

    if (handy_trace)
        trace_cipher(cipher);
}

/* Fill BUFFER of size CHUNK_SIZE with next chunk of characters from stream IN.
 * The [START;END[ interval contains not yet used characters and is moved to
 * the beginning of BUFFER.
 * Filter spaces, update END and return true if it was the last chunk. */
static int
readchunk(FILE *in, char *buffer, int start, int *end)
{
    int i, n, last = 0;

    if (start) {
        for (i = 0; i < *end - start; i++)
            buffer[i] = buffer[start + i];
        start = i;
    }
    n = fread(buffer + start, 1, CHUNK_SIZE - start, in);
    if (n != CHUNK_SIZE - start) {
        if (ferror(in))
            fatal("cannot read input -- %s", strerror(errno));
        last = 1;
    }
    *end = start + n;
    for (n = start, i = start; i < *end; i++)
        if (!isspace(buffer[i])) {
            if (n < i)
                buffer[n] = buffer[i];
            n++;
        }
    *end = start + n;
    return last;
}

/* Write LEN characters of BUFFER to stream FILE.
 * Characters are grouped by 5, with 12 groups by line. */
static void
foutput(char *buffer, int len, FILE *file)
{
    static int n = 0; /* number of non-space chars in current line */
    int i;

    for (i = 0; i < len; i++) {
        if (n == 60) {
            putc('\n', file);
            n = 0;
        }
        putc(buffer[i], file);
        n++;
        if (n % 5 == 0)
            putc(' ', file);
    }
}

/* Fill RESULT by salting LEN characters of BUFFER with null characters.
 * Return the length of RESULT (<= MAX_ENCODED_LEN). */
static int
set_salt(struct handy *cipher, char *result, char *buf, int len)
{
    int i, l;

    for (i = 0, l = 0; i < len; i++) {
        while (pcg_boundedrand(Random, 2)
                && l < MAX_ENCODED_LEN - len + i)
            result[l++] = Null_mat[pcg_boundedrand(Random, 25)];
        result[l++] = buf[i];
    }
    if (i < len) {
        warning("salt buffer full -- randomizer may lack uniformity");
        for (; i < len; i++)
            result[l++] = buf[i];
    }

    if (handy_trace)
        for (i = 0; i < l; i++)
            putchar(result[i]);
    return l;
}

/* Fill RESULT with BUFF and noise characters.
 * Return the length of RESULT (<= 9). */
static int
set_noise(struct handy *cipher, char *result, char *buf, int len)
{
    int i, j, k, l;

    result[0] = buf[0];
    for (i = 1, l = 1; i < len; i++) {
        result[l++] = buf[i];
        if (pcg_boundedrand(Random, 2)) {
            for (j = 0; j < sizeof(Code_mat); j++)
                if (Code_mat[j] == buf[i])
                    break;
            k = (int) pcg_boundedrand(Random, 8);
            result[l++] = Code_mat[knightjumps[j][k]];
        }
    }
    if (handy_trace) {
        for (i = 0; i < l; i++)
            putchar(result[i]);
        for (; i < 10; i++)
            putchar(' ');
    }
    return l;
}

/* Encode the character C of code CODE in buffer RESULT.
 * NEXT_CODE is the code of the character following C or 0.
 * Return the length of the result (<= MAX_ENCODED_LEN). */
static int
encode_char(struct handy *cipher, int c, int code, int next_code, char *result)
{
    static char lines[20] = { 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                             10, 11, 12, 13, 14, 15, 16, 17, 18, 19 };
    char ranks[120], r;

    int dir, len, i, j, k, l;
    char raw[5], permuted[5];

    if (handy_trace)
        trace_bcode(code);

    Parity = 1 - Parity;

    /* DIR loops on all directions in random order */
    shuffle(lines, 20, Random);
    for (i = 0; i < sizeof(lines); i++) {
        dir = lines[i];
        if ((pow2(code) && dir >= 5)
            ||
            (dir >= 5 && dir < 10
             &&
             ((!Parity && next_code == 1 << (9 - dir))
              ||
              (Parity && next_code == 1 << (dir - 5)))))
            continue;

        /* Encode one input character into 1 to 5 characters */
        for (j = 0, len = 0, r = 1; j < sizeof(raw); j++)
            if (code & (1 << (4 - j))) {
                raw[len++] = Code_mat[directions[dir][Parity ? j : 4 - j]];
                r *= len;
            }

        /* J loops on all r = len! permutation ranks in random order.
         * See 'Ranking and unranking permutations in linear time'
         * by Wendy Myrvold and Frank Ruskey */
        for (j = 0; j < r; j++)
            ranks[j] = j;
        shuffle(ranks, r, Random);
        for (j = 0; j < r; j++) {
            for (k = 0; k < len; k++)
                permuted[k] = raw[k];
            for (k = ranks[j], l = len; l > 0; l--) {
                char tmp;

                tmp = permuted[l - 1];
                permuted[l - 1] = permuted[k % l];
                permuted[k % l] = tmp;
                k /= l;
            }
            /* At this point PERMUTED contains a random transposition of RAW.
             * We can now check the encoding sequence validity. */
            if (!Prev_code
                ||
                (!has_direction(cipher, permuted[0], Prev_dir)
                 &&
                 (colinear(cipher, permuted[0], Prev_last) ?
                    !pow2(Prev_code) : pow2(Prev_code))))
                goto found;
        }
    }
    /* Not reached */
    fatal("no encoding direction found -- this should not happen!");

found:
    if (handy_trace) {
        trace_direction(dir);
        for (i = 0; i < len; i++)
            putchar(permuted[i]);
        for (; i < sizeof(permuted) + 1; i++)
            putchar(' ');
    }

    Prev_code = code;
    Prev_dir = dir;
    Prev_last = permuted[len - 1];

    /* Add noises and nulls characters. */
    if (Core)
        len = set_noise(cipher, result, permuted, len);
    else {
        char noise[9];

        len = set_noise(cipher, noise, permuted, len);
        len = set_salt(cipher, result, noise, len);
    }

    if (handy_trace)
        putchar('\n');
    return len;
}

/* Encode the character C in buffer RESULT into at most 2*MAX_ENCODED_LEN
 * characters. NEXT is the character following C or EOF.
 * If hyphenation is required, encode the two characters '-' and C.
 * Return the length of the result. */
static int
encode(struct handy *cipher, int c, int next, char *result)
{
    int len, code, next_code;

    len = 0;
    code = get_code(cipher, c);

    if (Prev_code * code == 16) { /* hyphenation is required */
        next_code = code;
        code = get_code(cipher, '-');
        if (Prev_code * code == 16)
            fatal("cannot hyphenate character -- %c", c);
        if (handy_trace)
            printf("!- %2d ", code);
        len = encode_char(cipher, '-', code, next_code, result);
        code = next_code;
    }

    if (handy_trace)
        printf(" %c %2d ", c, code);
    next_code = next == EOF ? 0 : get_code(cipher, next);
    len += encode_char(cipher, c, code, next_code, result + len);
    return len;
}

/* Output to stream TO a formatted encryption of stream FROM.
 * The CORE flag is set for core encryption algorithm only.
 * The TRACE flag traces the encoding process on stdout. */
void
handy_encrypt(FILE *from, FILE *to, char *key, int core, int trace)
{
    int current, next, len;
    char result[2*MAX_ENCODED_LEN];
    struct handy cipher[1];

    int start = 0, end = 0, last = 0;
    char input[CHUNK_SIZE];

    handy_trace = trace;
    init_cipher(cipher, key, core);

    for (;;) {
        /* Fill input buffer with at least 2 characters */
        while (!last && end - start < 2) {
            last = readchunk(from, input, start, &end);
            start = 0;
        }

        /* Are we done? */
        if (end - start == 0)
            break;

        current = input[start++];
        next = end - start == 0 ? EOF : input[start];

        len = encode(cipher, current, next, result);

        if (to != stdout || !handy_trace) /* do not mix trace and output */
            foutput(result, len, to);
    }

    if (to != stdout || !handy_trace)
        putc('\n', to); /* ensure final '\n' */
}

/* Return true if character C is a null character. Abort if it is invalid. */
static int
is_salt(struct handy *cipher, int c)
{
    int i;

    for (i = 0; i < sizeof(Null_mat); i++)
        if (c == Null_mat[i])
            break;
    if (i == sizeof(Null_mat)) {
        if (Core || ((c < 'A' || c > 'Y') && (c < 'a' || c > 'y')))
            fatal(isprint(c) ? "%s -- '%c'" : "%s -- %#04x",
                    "invalid input character", c);
        else
            return 0;
    }
    return 1;
}

/* Decode in RESULT one character from a BUFFER of LEN characters.
 * RESULT is set to 0 if all characters were nulls.
 * Return the number of used characters in buffer (<= MAX_ENCODED_LEN). */
static int
decode(struct handy *cipher, char *buffer, int len, int *result)
{
    int i, j, used, code, pos, dir, noise;
    char raw[5];

    *result = 0;
    for (pos = 0, used = 0; used < len; used++) {
        code = buffer[used];
        if (is_salt(cipher, code))
            continue;
        switch (pos) {
        case 0:
            raw[pos++] = code;
            break;
        case 1:
            dir = get_direction(cipher, code, raw[0]);
            if (dir < 0) {
                dir = get_column(cipher, raw[0]);
                goto end_sequence;
            }
            raw[pos++] = code;
            noise = 0;
            break;
        case 2:
        case 3:
            if (has_direction(cipher, code, dir)) {
                raw[pos++] = code;
                noise = 0;
            }
            else {
                if (colinear(cipher, raw[pos - 1], code))
                    goto end_sequence;
                else if (noise)
                    fatal("invalid sequence -- bad noise in position %d", pos);
                else
                    noise = 1;
            }
            break;
        case 4:
            if (has_direction(cipher, code, dir))
                fatal("invalid sequence -- too many characters");
            if (colinear(cipher, raw[pos - 1], code))
                goto end_sequence;
            if (noise)
                fatal("invalid sequence -- bad noise in position 4");
            else
                noise = 1;
            break;
        }
    }
    if (!pos) /* only null characters */
        return used;
    if (pos == 1) /* only one non null character */
        dir = get_column(cipher, raw[0]);

end_sequence:
    Parity = 1 - Parity;
    for (code = 0, i = 0; i < 5; i++)
        for (j = 0; j < pos; j++)
            if (Code_mat[directions[dir][i]] == raw[j]) {
                if (Parity)
                    code |= 16 >> i;
                else
                    code |= 1 << i;
            }
    *result = Subkey[code - 1];

    if (handy_trace) {
        for (i = 0; i < used; i++)
            putchar(buffer[i]);
        for (i = 0; i < MAX_ENCODED_LEN + 1 - used; i++)
            putchar(' ');
        for (i = 0; i < pos; i++)
            putchar(raw[i]);
        for (; i < sizeof(raw) + 1; i++)
            putchar(' ');
        trace_direction(dir);
        trace_bcode(code);
        printf("%2d %c\n", code, *result);
    }
    return used;
}

/* Output to stream TO a decryption of stream FROM.
 * The CORE flag is set for core decryption algorithm only.
 * The TRACE flag traces the decoding process on stdout. */
void
handy_decrypt(FILE *from, FILE *to, char *key, int core, int trace)
{
    struct handy cipher[1];
    int c;

    char input[CHUNK_SIZE];
    int start = 0, end = 0, last = 0;

    handy_trace = trace;
    init_cipher(cipher, key, core);

    for (;;) {
        /* Fill input buffer with at least 2 sequences if possible */
        while (!last && end - start < 2*MAX_ENCODED_LEN) {
            last = readchunk(from, input, start, &end);
            start = 0;
        }

        /* Are we done? */
        if (end - start == 0)
            break;

        /* Decode next char */
        start += decode(cipher, input + start, end - start, &c);
        if (to != stdout || !handy_trace)
            putc(c, to);
    }

    if (to == stdout && !handy_trace)
        putchar('\n'); /* ensure final '\n' on stdout */
}

/* Generate a KEY from a PASSWORD string. */
void
handy_keygen(char *password, char *key)
{
    static const char *keyset =
        "ABCDEFGHIJKLMNOPQRSTUVWXYabcdefghijklmnopqrstuvwxy^";

    struct pcgstate random[1];
    uint8_t hash[32];
    SHA256_CTX sha[1];

    sha256_init(sha);
    sha256_update(sha, (uint8_t *) password, strlen(password));
    sha256_final(sha, hash);

    pcg_seed(random, *((uint64_t *) hash),
                     *((uint64_t *) (hash + 8)) & 0x7FFFFFFFFFFFFFFF);

    memcpy(key, keyset, 51);
    shuffle(key, 51, random);
}
