.POSIX:
.SUFFIXES:
CC      = cc
CFLAGS  = -ansi -Wall -O3
LDFLAGS =
LDLIBS  =
PREFIX  = ${HOME}/.local

sources = src/handy.c src/cipher.c
objects = $(sources:.c=.o)

handy: $(objects)
	$(CC) $(LDFLAGS) -o $@ $(objects) $(LDLIBS)

src/handy.o: config.h src/docs.h src/optparse.h
src/cipher.o: src/pcgrandom.h

clean:
	rm -f handy $(objects)

install: handy handy.1
	mkdir -p $(PREFIX)/bin
	mkdir -p $(PREFIX)/share/man/man1
	install -m 755 handy $(PREFIX)/bin
	gzip < handy.1 > $(PREFIX)/share/man/man1/handy.1.gz

uninstall:
	rm -f $(PREFIX)/bin/handy
	rm -f $(PREFIX)/share/man/man1/handy.1.gz

.SUFFIXES: .c .o
.c.o:
	$(CC) -c $(CFLAGS) -o $@ $<
