#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

int main(int argc, char *argv[]) {
	write(1, "abcdef\n", 7);
	exit(0);
}