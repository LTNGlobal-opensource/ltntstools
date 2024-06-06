/* Copyright LiveTimeNet, Inc. 2017. All Rights Reserved. */

#ifndef HEXDUMP_H
#define HEXDUMP_H

static inline void hexdump(unsigned char *buf, unsigned int len, int bytesPerRow /* Typically 16 */)
{
        for (unsigned int i = 0; i < len; i++)
                printf("%02x%s", buf[i], ((i + 1) % bytesPerRow) ? " " : "\n");
        printf("\n");
}

#endif /* HEXDUMP_H */
