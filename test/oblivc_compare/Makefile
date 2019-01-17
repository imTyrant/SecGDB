OBLIVPATH=../../obliv-c
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
	g++ main.o compare.o $(RUNTIME) -lgcrypt -pthread

main.o : main.cpp
	g++ -c -g main.cpp $(OBLIV_C_HEAD_PATH)

compare.o : compare.oc
	$(OBLIVCC) $(CFLAG) -c -I . compare.oc

# compare.o: compare.oc main.cpp $(RUNTIME)
# 	$(OBLIVCC) $(CFLAG) -c -I . compare.oc $(LOADLIBES)

.PHONY : clean
clean:
	-rm -rfv a.out *.o
	# rm -f test $(TESTNAME).oc.cil.i $(TESTNAME).oc.i $(TESTNAME).oc.cil.c