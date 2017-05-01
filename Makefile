
INCLUDE=-Ixed/prefix/include/xed -Iinclude
INCLUDE+=-Iprocessor-trace/build/libipt/include
INCLUDE+=-Iprocessor-trace/libipt/internal/include
INCLUDE+=-Iprocessor-trace/ptxed/src

LIBRIS:=lib/libristretto.a
LIBIPT:=lib/libipt.a
LIBXED:=lib/libxed.a

LIBS:=$(LIBRIS) $(LIBIPT) $(LIBXED)

SRC:=main.c processor-trace/ptxed/src/ris_ptxed.c monitor.c
OBJ:=main.o ris_ptxed.o monitor.o

CFLAGS=$(INCLUDE) -static -v

ifeq ($(RISTRETTO_DEBUG),1)
	CFLAGS+=-DRISTRETTO_DEBUG
endif

all: pi

pi: pi.c $(LIBRIS)
	$(CC) $(CFLAGS) pi.c $(LIBS) -o $@ -lpthread -lc

$(LIBRIS): $(OBJ)
	ar -cq $@ $(OBJ)

$(OBJ): $(SRC) include/rtrace.h
	$(CC) $(CFLAGS) -c $(SRC)

clean:
	rm -f $(OBJ) $(LIBRIS) pi

distclean:
	rm -rf $(OBJ) $(LIBS) lib pi
