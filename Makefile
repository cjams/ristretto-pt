

all: pi

pi: pi.c librtrace.a
	gcc pi.c librtrace.a

librtrace.a: ristmain.o
	ar rcs librtrace.a ristmain.o

ristmain.o: main.c
	gcc -c main.c -o ristmain.o
