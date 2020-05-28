OBLIVPATH=../../depends/obliv-c
OBLIVCC=$(OBLIVPATH)/bin/oblivcc
OBLIV_C_HEAD_PATH = -I $(OBLIVPATH)/src/ext/oblivc
RUNTIME=$(OBLIVPATH)/_build/libobliv.a

REMOTE_HOST=localhost
PORT=1234

CILPATH=$(OBLIVPATH)
CFLAG=-g -Wall -D _Float128=double
LOADLIBES=-lm

TESTNAME=add

.PHONY : all
all : main.o compare.o
	g++ main.o compare.o $(RUNTIME) -lgcrypt -pthread -ldl

main.o : main.cc
	g++ -c -g main.cc $(OBLIV_C_HEAD_PATH) -I ../../depends/cxxopts/include

compare.o : compare.oc
	$(OBLIVCC) $(CFLAG) -g -c -I . compare.oc

# compare.o: compare.oc main.cpp $(RUNTIME)
# 	$(OBLIVCC) $(CFLAG) -c -I . compare.oc $(LOADLIBES)

.PHONY : clean
clean:
	-rm -rfv a.out *.o
	# rm -f test $(TESTNAME).oc.cil.i $(TESTNAME).oc.i $(TESTNAME).oc.cil.c