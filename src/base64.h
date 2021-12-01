#ifndef _LTNTSTOOLS_BASE64_H
#define _LTNTSTOOLS_BASE64_H

/* https://www.mycplus.com/source-code/c-source-code/base64-encode-decode/ */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
 
void build_decoding_table();
void base64_cleanup();
 
char *base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length);

#endif /* _LTNTSTOOLS_BASE64_H */

