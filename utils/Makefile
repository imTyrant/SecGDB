ROOT_PATH = ..
OBLIV_C_PATH = $(ROOT_PATH)/obliv-c
LABHE_PATH = $(ROOT_PATH)/labhe

CC = gcc
GXX = g++
OBLIVCC = $(OBLIV_C_PATH)/bin/oblivcc

OBLIV_RUNTIME = $(OBLIV_C_PATH)/_build/libobliv.a
LABHE_S_LIB = $(LABHE_PATH)/build/liblabhe.a

CFLAG = -g -W

CFLAG_FOR_OBLIVC = -D _Float128=double

INCLUDE_PATH = -I $(ROOT_PATH)/include 
LABHE_INCLUDE_PATH = -I $(LABHE_PATH)/include
OBLIV_C_HEAD_PATH = -I $(OBLIV_C_PATH)/src/ext/oblivc

LIBS = -lgmpxx -lgmp -lcrypto
LIBS_FOR_OBLIVC = -lgcrypt -pthread

.PHONY : all
all : crypto_stuff.o ggm.o graph.o compare.o sec_compare.o

.PHONY : test_crypto
test_crypto : crypto_stuff.cpp
	$(GXX) $(CFLAG) $(LABHE_S_LIB) $(INCLUDE_PATH) $(LABHE_INCLUDE_PATH) $(LIBS) -D SEC_GDB_DBG_CRYPTO $<


crypto_stuff.o: crypto_stuff.cpp
	$(GXX) -c $(CFLAG) $(INCLUDE_PATH) $(LABHE_INCLUDE_PATH) $<

ggm.o: ggm.c
	$(CC) -c $(CFLAG) $(INCLUDE_PATH) $<

graph.o: graph.cpp
	$(GXX) -c $(CFLAG) $(INCLUDE_PATH) $<

compare.o : compare.oc
	$(OBLIVCC) -c $(CFLAG) $(INCLUDE_PATH) $(CFLAG_FOR_OBLIVC) $(OBLIV_C_HEAD_PATH) $<

sec_compare.o : sec_compare.cpp
	$(GXX) -c $(CFLAG) $(INCLUDE_PATH) $(OBLIV_C_HEAD_PATH) $<

.PHONY : clean
clean :
	-rm -rfv *.o a.out