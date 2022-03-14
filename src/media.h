#ifndef LTNTSTOOLS_MEDIA_H
#define LTNTSTOOLS_MEDIA_H

#ifdef __cplusplus
extern "C" {
#endif

int media_init();
int media_write(const unsigned char *buf, int packetCount);

#ifdef __cplusplus
};
#endif

#endif /* LTNTSTOOLS_MEDIA_H */

