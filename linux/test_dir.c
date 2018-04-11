#include <unistd.h>
#include <stdio.h>

int main()
{
	chdir("/tmp");
	FILE* f = fopen("./test.txt", "wb");
	fwrite("11", 2, 1, f);
	fclose(f);
	return 0;
}
