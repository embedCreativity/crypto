CFLAGS += -Wall -g
LDFLAGS += -L.
LIBRARY += -lsimplecrypto

testCrypto: testCrypto.o libsimplecrypto.a
testCrypto: testCrypto.o crypto.o
	$(CC) $(CFLAGS) $(LDFLAGS) testCrypto.o $(LIBRARY) -o testCrypto $(LIBS)

testCrypto.o: testCrypto.c
	$(CC) $(CFLAGS) -c testCrypto.c

crypto.o: crypto.c
	#$(CC) -fPIC -g -c -Wall crypto.c
	$(CC) $(CFLAGS) -c crypto.c

libsimplecrypto.a: crypto.o
	ar rcs libsimplecrypto.a crypto.o

all: libsimplecrypto.a testCrypto
# remove object files and executable when user executes "make clean"

clean:
	rm -f *.o testCrypto libsimplecrypto.a


