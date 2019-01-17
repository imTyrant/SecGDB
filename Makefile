ROOT_PATH = .
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

OBJS = main.o client.o server.o ./util/ggm.o ./util/graph.o ./util/crypto_stuff.o \
		./util/compare.o ./util/sec_compare.o

.PHONY : all
all : main.o client.o server.o utils
	$(GXX)  $(OBJS) $(OBLIV_RUNTIME) $(LABHE_S_LIB) $(LIBS) $(LIBS_FOR_OBLIVC)

.PHONY : test_client
test_client : client.o utils
	$(GXX) $(CFLAG) $(LABHE_S_LIB) $(LIBS) $(INCLUDE_PATH) $(LABHE_INCLUDE_PATH)

.PHONY : test_compare
test_compare : main.o client.o utils
	$(GXX) $(LABHE_S_LIB) $(LIBS) $(OBLIV_RUNTIME) $(LIBS_FOR_OBLIVC)


.PHONY : utils
utils :
	$(MAKE) -C ./util all

# graph.o sec_compare.o compare.o ggm.o crypto_stuff.o : utils

test_crypto : 
	$(MAKE) -C ./util test_crypto


client.o: client.cpp
	$(GXX) -c $(CFLAG) $(INCLUDE_PATH) $(LABHE_INCLUDE_PATH) $<

server.o: server.cpp
	$(GXX) -c $(CFLAG) $(INCLUDE_PATH) $(LABHE_INCLUDE_PATH) $<

main.o: main.cpp
	$(GXX) -c $(CFLAG) $(INCLUDE_PATH) $(LABHE_INCLUDE_PATH) $<

.PHONY : clean
clean :
	$(MAKE) -C ./util clean
	-rm -rfv *.o a.out 