
#ifndef LTN_PARSERS_H
#define LTN_PARSERS_H

/* Mandatory format decimal pid: a.b.c.d:port.pid */
/* Mandatory format     hex pid: a.b.c.d:port.0xpid */

struct parser_ippid_s
{
	unsigned int digit[4];
	char address[16];
	unsigned int port;
	unsigned int pid;

	/* User visible strings. */
	char ui_address_ip[24];
	char ui_address_ip_pid[32];
};

int parsers_ippid_parse(const char *str, struct parser_ippid_s *dst);

#endif  /* LTN_PARSERS_H */
