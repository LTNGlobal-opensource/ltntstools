#include <stdio.h>
#include <string.h>

/* In string 'str', find occurences of character src and replace with character dst. */
/* return the number of substituions occured. */
int character_replace(char *str, char src, char dst)
{
	int c = 0;

	for (int i = 0; i < strlen(str); i++) {
		if (str[i] == src) {
			str[i] = dst;
			c++;
		}
	}

	return c;
}
