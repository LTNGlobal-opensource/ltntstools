#include <stdio.h>
#include <string.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netdb.h>


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

int networkInterfaceExists(const char *ifname)
{
	int exists = 0;

	/* Setup multicast on all IPV4 network interfaces, IPV6 interfaces are ignored */
	struct ifaddrs *addrs;
	int result = getifaddrs(&addrs);
	if (result >= 0) {
		const struct ifaddrs *cursor = addrs;
		while (cursor != NULL) {
#if 0
			char host[NI_MAXHOST];
			int r = getnameinfo(cursor->ifa_addr,
				cursor->ifa_addr->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
				host, NI_MAXHOST,
				NULL, 0, NI_NUMERICHOST);
			printf("name: %s\n", cursor->ifa_name);
			printf("\t host: %s\n", host);
			if (cursor->ifa_flags & IFF_BROADCAST)
				printf("\tflags: IFF_BROADCAST = true\n");
			else
				printf("\tflags: IFF_BROADCAST = false\n");
			if (cursor->ifa_flags & IFF_UP)
				printf("\tflags: IFF_UP = true\n");
			else
				printf("\tflags: IFF_UP = false\n");
#endif
			if (/* (cursor->ifa_flags & IFF_BROADCAST) && */ (cursor->ifa_flags & IFF_UP) &&
				(cursor->ifa_addr->sa_family == AF_INET)) {

				char host[NI_MAXHOST];

				int r = getnameinfo(cursor->ifa_addr,
					cursor->ifa_addr->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
					host, NI_MAXHOST,
					NULL, 0, NI_NUMERICHOST);
				if (r == 0) {
					if (strcmp(cursor->ifa_name, ifname) == 0) {
						exists = 1;
						break;
					}
				}
			}
			cursor = cursor->ifa_next;
		}
	}

	freeifaddrs(addrs);

	return exists;
}

void networkInterfaceList()
{
	/* Setup multicast on all IPV4 network interfaces, IPV6 interfaces are ignored */
	struct ifaddrs *addrs;
	int result = getifaddrs(&addrs);
	if (result >= 0) {
		const struct ifaddrs *cursor = addrs;
		while (cursor != NULL) {
			if (/* (cursor->ifa_flags & IFF_BROADCAST) && */ (cursor->ifa_flags & IFF_UP) &&
				(cursor->ifa_addr->sa_family == AF_INET)) {

				char host[NI_MAXHOST];

				int r = getnameinfo(cursor->ifa_addr,
					cursor->ifa_addr->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
					host, NI_MAXHOST,
					NULL, 0, NI_NUMERICHOST);
				if (r == 0) {
					printf("\t%s : %s\n", cursor->ifa_name, host);
				}
			}
			cursor = cursor->ifa_next;
		}
	}

	freeifaddrs(addrs);
}

