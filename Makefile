

all: pi

pi: pi.c librtrace.a
	gcc  -static pi.c librtrace.a -lc

librtrace.a: ristmain.o
	ar rcs librtrace.a ristmain.o

ristmain.o: main.c ptxed.c
	gcc main.c ptxed.c -o ristmain.o -pthread -lipt
