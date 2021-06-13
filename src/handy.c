#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>
#include <sys/errno.h>

#include "../config.h"
#include "docs.h"

extern void handy_encrypt(FILE *f, FILE *t, char *key, int core, int trace);
extern void handy_decrypt(FILE *f, FILE *t, char *key, int core, int trace);
extern void handy_keygen(char *password, char *key);

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
        putchar('\n'); /* try forcing a decent prompt */
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

/* Fallback method to get a password from terminal. */
static void
get_password_dumb(char *buf, size_t len, char *prompt)
{
    size_t passlen;
    warning("reading password from stdin with echo");
    fputs(prompt, stderr);
    fflush(stderr);
    if (!fgets(buf, len, stdin))
        fatal("could not read password");
    passlen = strlen(buf);
    if (buf[passlen - 1] < ' ')
        buf[passlen - 1] = 0;
}

/* Read a password string from terminal. */
static void
get_password(char *buf, size_t len, char *prompt)
{
    int tty;
    char newline = '\n';
    size_t i;
    struct termios old, new;

    tty = open("/dev/tty", O_RDWR);
    if (tty == -1)
        get_password_dumb(buf, len, prompt);
    else {
        if (write(tty, prompt, strlen(prompt)) == -1)
            fatal("error writing password prompt");
        tcgetattr(tty, &old);
        new = old;
        new.c_lflag &= ~ECHO;
        tcsetattr(tty, TCSANOW, &new);
        errno = 0;
        for (i = 0; i < len - 1 && read(tty, buf + i, 1) == 1; i++)
            if (buf[i] == '\n' || buf[i] == '\r')
                break;
        buf[i] = 0;
        tcsetattr(tty, TCSANOW, &old);
        if (write(tty, &newline, 1) == -1)
            fatal("error asking for password");
        close(tty);
        if (errno)
            fatal("could not read password from /dev/tty");
    }
}
/* Load the KEY stored in file KEYFILE. If KEYFILE is null, read a password
 * from terminal and generate a key. */
static void
load_key(char *keyfile, char *key)
{
    FILE *in;
    size_t sz;
    char password[HANDY_PASSWORD_MAX];

    if (keyfile) {
        if (!(in = fopen(keyfile, "r")))
            fatal("could not open key file '%s' -- %s",
                    keyfile, strerror(errno));
        if ((sz = fread(key, 1, 51, in)) != 51)
            fatal("could not read key in keyfile -- %s", keyfile);
        fclose(in);
    }
    else {
        get_password(password, HANDY_PASSWORD_MAX, "password: ");
        if (!*password)
            fatal("password has length zero");
        handy_keygen(password, key);
    }
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
