
#include <stdio.h>

#include "parsers.h"

/* Mandatory format decimal pid: a.b.c.d:port.pid */
/* Mandatory format     hex pid: a.b.c.d:port.0xpid */

static int ippid_parse_args_ok(struct parser_ippid_s *dst)
{
	for (int i = 0; i < 4; i++) {
		if ((dst->digit[i] < 0) || (dst->digit[i] > 255))
			return 0;
	}
	if ((dst->port <= 0) || (dst->port > 65535))
		return 0;
	if ((dst->pid <= 0) || (dst->pid > 0x1fff))
		return 0;

	return 1; /* Success */
}

int parsers_ippid_parse(const char *str, struct parser_ippid_s *dst)
{
	if (!dst || !str)
		return -1;

	int ret = sscanf(str, "%d.%d.%d.%d:%d.0x%x",
		&dst->digit[0], &dst->digit[1], &dst->digit[2], &dst->digit[3], &dst->port, &dst->pid);
	if (ret == 6 && ippid_parse_args_ok(dst)) {
		sprintf(dst->address, "%d.%d.%d.%d",
			dst->digit[0], dst->digit[1], dst->digit[2], dst->digit[3]);
		sprintf(dst->ui_address_ip, "%d.%d.%d.%d:%d",
			dst->digit[0], dst->digit[1], dst->digit[2], dst->digit[3], dst->port);
		sprintf(dst->ui_address_ip_pid, "%d.%d.%d.%d:%d.0x%x",
			dst->digit[0], dst->digit[1], dst->digit[2], dst->digit[3], dst->port, dst->pid);
		return 0; /* Success */
	}

	ret = sscanf(str, "%d.%d.%d.%d:%d.%d",
		&dst->digit[0], &dst->digit[1], &dst->digit[2], &dst->digit[3], &dst->port, &dst->pid);
	if (ret == 6 && ippid_parse_args_ok(dst)) {
		sprintf(dst->address, "%d.%d.%d.%d",
			dst->digit[0], dst->digit[1], dst->digit[2], dst->digit[3]);
		sprintf(dst->ui_address_ip, "%d.%d.%d.%d:%d",
			dst->digit[0], dst->digit[1], dst->digit[2], dst->digit[3], dst->port);
		sprintf(dst->ui_address_ip_pid, "%d.%d.%d.%d:%d.%d",
			dst->digit[0], dst->digit[1], dst->digit[2], dst->digit[3], dst->port, dst->pid);
		return 0; /* Success */
	}

	return -1; /* Failed */
}

#if 0
struct parser_ippid_s
{
        char address;
        unsigned int port;
        unsigned int pid;

        /* User visible strings. */
        char ui_address_ip[24];
        char ui_address_ip_pid[32];
};
#endif

