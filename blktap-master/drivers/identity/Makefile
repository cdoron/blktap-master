all: libidentity.so

libidentity.so: identity.o
	cc identity.o -shared -o libidentity.so

identity.o: identity.c
	cc -c identity.c -fPIC

clean:
	rm -f identity.o libidentity.so
