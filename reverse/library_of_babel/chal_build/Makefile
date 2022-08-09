all: library_of_babel

library_of_babel: main.c babel.c
	gcc main.c babel.c -O3 -lgmp -o library_of_babel

clean:
	rm -f library_of_babel
