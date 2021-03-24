CFLAGS += -Wall -g
LDFLAGS += -L.
LIBRARY += -lcrypto

testCrypto: testCrypto.o libcrypto.a
testCrypto: testCrypto.o crypto.o
	$(CC) $(CFLAGS) $(LDFLAGS) testCrypto.o $(LIBRARY) -o testCrypto $(LIBS)

testCrypto.o: testCrypto.c
	$(CC) $(CFLAGS) -c testCrypto.c

crypto.o: crypto.c
	#$(CC) -fPIC -g -c -Wall crypto.c
	$(CC) $(CFLAGS) -c crypto.c

libcrypto.a: crypto.o
	ar rcs libcrypto.a crypto.o

all: libcrypto.a testCrypto
# remove object files and executable when user executes "make clean"

clean:
	rm -f *.o testCrypto libcrypto.a


