#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/errno.h>

#include "../config.h"
#include "docs.h"

extern void handy_encrypt(FILE *f, FILE *t, char *key, int core, int trace);
extern void handy_decrypt(FILE *f, FILE *t, char *key, int core, int trace);

#define OPTPARSE_IMPLEMENTATION
#define OPTPARSE_API static
#include "optparse.h"

static FILE *cleanup_fd = 0;
static char *cleanup_file = 0;

/* Print a message and exit the program with a failure code. */
void
fatal(const char *fmt, ...)
{
    va_list ap;

    if (cleanup_fd == stdout)
        putchar('\n'); /* restore a decent prompt */
    else if (cleanup_fd)
       fclose(cleanup_fd);
    if (cleanup_file)
       remove(cleanup_file);

    va_start(ap, fmt);
    fprintf(stderr, "handy: ");
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);

    exit(EXIT_FAILURE);
}

/* Print a non-fatal warning message. */
void
warning(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "warning: ");
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

/* Load the KEY stored in file KEYFILE. */
static void
load_key(char *keyfile, char *key)
{
    FILE *in;
    size_t sz;

    if (!(in = fopen(keyfile, "r")))
        fatal("could not open key file '%s' -- %s",
                keyfile, strerror(errno));
    if ((sz = fread(key, 1, 51, in)) != 51)
        fatal("could not read key in keyfile -- %s", keyfile);
    fclose(in);
}

int
main(int argc, char **argv)
{
    static const struct optparse_name global[] = {
        {"version", 'V', OPTPARSE_NONE},
        {"output",  'o', OPTPARSE_REQUIRED},
        {"decrypt", 'd', OPTPARSE_NONE},
        {"encrypt", 'e', OPTPARSE_NONE},
        {"key",     'k', OPTPARSE_REQUIRED},
        {"help",    256, OPTPARSE_NONE},
        {"trace",   257, OPTPARSE_NONE},
        {"core",    258, OPTPARSE_NONE},
        {0, 0, 0}
    };
    int option, crypt = 1, trace = 0, core = 0;
    char *infile, *outfile = 0, *keyfile = 0;
    struct optparse options[1];

    FILE *in = stdin, *out = stdout;
    char key[51];

    optparse_init(options, argv);
    while ((option = optparse(options, global)) != OPTPARSE_DONE) {
        switch (option) {
        case 'd':
            crypt = 0;
            break;
        case 'e':
            crypt = 1;
            break;
        case 'k':
            keyfile = options->optarg;
            break;
        case 'o':
            outfile = options->optarg;
            break;
        case 257:
            trace = 1;
            break;
        case 258:
            core = 1;
            break;
        case 'V':
            puts("handy " STR(HANDY_VERSION));
            exit(EXIT_SUCCESS);
        case 256:
            puts(docs_usage);
            printf("\n%s\n", docs_summary);
            exit(EXIT_SUCCESS);
        case OPTPARSE_ERROR:
        default:
            fprintf(stderr, "%s\n", options->errmsg);
            fprintf(stderr, "%s\n", docs_usage);
            exit(EXIT_FAILURE);
        }
    }
    infile = optparse_arg(options);

    if (!keyfile) {
        fprintf(stderr, "missing key file\n");
        fprintf(stderr, "%s\n", docs_usage);
        exit(EXIT_FAILURE);
    }
    load_key(keyfile, key);

    if (infile && !(in = fopen(infile, "r")))
        fatal("could not open input file '%s' -- %s",
                infile, strerror(errno));

    if (outfile) {
        if (!(out = fopen(outfile, "w")))
            fatal("could not open output file '%s' -- %s",
                    outfile, strerror(errno));
        cleanup_file = outfile;
    }
    cleanup_fd = out;

    if (crypt)
        handy_encrypt(in, out, key, core, trace);
    else
        handy_decrypt(in, out, key, core, trace);

    if (infile)
        fclose(in);
    if (outfile)
        fclose(out);
    return 0;
}
