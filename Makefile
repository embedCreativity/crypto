#SHARED_LIB := libcrypto.so
#LIBVERSION := 1.0.1

# build helloworld executable when user executes "make"
CFLAGS += -Wall -g
#LDFLAGS += -L.
#LIBRARY += -lcrypto

#testCrypto: testCrypto.o libCrypto
testCrypto: testCrypto.o crypto.o
    #	$(CC) $(CFLAGS) $(LDFLAGS) testCrypto.o $(LIBRARY) -o testCrypto $(LIBS)
	$(CC) $(CFLAGS) testCrypto.o crypto.o -o testCrypto

testCrypto.o: testCrypto.c
	$(CC) $(CFLAGS) -c testCrypto.c

crypto.o: crypto.c
	#$(CC) -fPIC -g -c -Wall crypto.c
	$(CC) $(CFLAGS) -c crypto.c

#libCrypto: crypto.o
	#$(CC) -shared -Wl,-soname,$(SHARED_LIB) -o $(SHARED_LIB).$(LIBVERSION) crypto.o -lc
	#sudo mv $(SHARED_LIB).$(LIBVERSION) /usr/lib/
	#sudo cp --preserve=timestamps crypto.h /usr/include/
	#sudo chmod 644 /usr/include/crypto.h
	#sudo ldconfig -n /usr/lib

all: $(TestCrypto) $(Crypto)
# remove object files and executable when user executes "make clean"
clean:
	#rm -f *.o testCrypto $(SHARED_LIB)*
	rm -f *.o testCrypto


