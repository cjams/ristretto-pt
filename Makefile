
IPT:=libipt.a
RIS:=libristretto.a
XED:=libxed.a
SRC:=main.c processor-trace/ptxed/src/libptxed.c monitor.c
OBJ:=main.o libptxed.o monitor.o
CFLAGS:=-I/home/srdavos/build/kits/xed-install-base-2017-04-20-lin-x86-64/include/xed -I/home/srdavos/ristretto-pt/processor-trace/libipt/internal/include -I/home/srdavos/ristretto-pt/processor-trace/ptxed/src -static -v
LDFLAGS:=

all: pi

pi: pi.c $(RIS)
	$(CC) $(CFLAGS) pi.c $(RIS) $(IPT) $(XED) -o pi -lpthread -lc

$(RIS): $(OBJ)
	ar -cq $@ $(OBJ)

$(OBJ): $(SRC) rtrace.h
	$(CC) $(CFLAGS) -c $(SRC)

clean:
	rm -f $(OBJ) $(RIS) pi
