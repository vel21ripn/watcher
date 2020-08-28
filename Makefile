
# pkg-config fuse --cflags --libs
CCFLAGS=-g -O0 -D_REENTRANT -D_FILE_OFFSET_BITS=64 -I/usr/include/fuse -Wall -pedantic -pedantic-errors
LDFLAGS=-pthread -lfuse -lyaml -lrt -lpcre

watcher: watcher.o yaml-parser.o reader.o
	gcc -o $@ $^ $(LDFLAGS)

watcher.o: watcher.c
	gcc $(CCFLAGS) -c -o $@ $<

reader.o: reader.c reader.h
	gcc $(CCFLAGS) -c -o $@ $<

yaml-parser.o: yaml-parser.c yaml-parser.h
	gcc $(CCFLAGS) -c  -o $@ $<

reader: reader.c reader.h yaml-parser.o
	gcc $(CCFLAGS) -g -O0 -DMAIN_TESTING=1 -o $@ $< yaml-parser.o -pthread -lrt -lyaml

yaml-parser: yaml-parser.c yaml-parser.h
	gcc -g $(CCFLAGS) -DMAIN_TESTING=1 -o $@ $< -lyaml

clean::
	rm -f *.o watcher yaml-parser reader
