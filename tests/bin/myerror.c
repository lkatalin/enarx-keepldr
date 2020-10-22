#include "libc.h"

int main(void) {
	ssize_t rax = myerror();
	return rax != -1;
}
