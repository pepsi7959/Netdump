#ifndef _MEMMEM_H
#define _MEMMEM_H
#include <string.h>
#include <stdint.h>
/* Find any string in memorys */
char* NM_memmem(char* haystack, int hlen, char* needle, int nlen); 
#endif

