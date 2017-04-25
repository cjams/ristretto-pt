

all: pi

pi: pi.c librtrace.a
	gcc  -static pi.c librtrace.a -lc

librtrace.a: ristmain.o
	ar rcs librtrace.a ristmain.o

ristmain.o: main.c
	gcc -c main.c -o ristmain.o
