#include <stdlib.h>
#include <signal.h>
#include <unistd.h>


int main(int argc, char *argv[]) {
	write(2, "qwerty\n", 7);
	return 0;
}