#include "NMstring.h"
 
// Implements the GNU function memmem much faster (2x) than the standard memmem included on my Debian system
char* NM_memmem(char* haystack, int hlen, char* needle, int nlen) {
	if (nlen > hlen) return 0;
	int i=0,j=0;
	switch(nlen) { // we have a few specialized compares for certain needle sizes
	case 0: // no needle? just give the haystack
		return haystack;
	case 1: // just use memchr for 1-byte needle
		return memchr(haystack, needle[0], hlen);
	case 2: // use 16-bit compares for 2-byte needles
		for (i=0; i<hlen-nlen+1; i++) {
			if (*(uint16_t*)(haystack+i)==*(uint16_t*)needle) {
				return haystack+i;
			}
		}
		break;
	case 4: // use 32-bit compares for 4-byte needles
		for (i=0; i<hlen-nlen+1; i++) {
			if (*(uint32_t*)(haystack+i)==*(uint32_t*)needle) {
				return haystack+i;
			}
		}
		break;
	/* actually slower on my 32-bit machine
	case 8: // use 64-bit compares for 8-byte needles
		for (i=0; i<hlen-nlen+1; i++) {
			if (*(uint64_t*)(haystack+i)==*(uint64_t*)needle) {
				return haystack+i;
			}
		}
		break;
	*/
	default: // generic compare for any other needle size
		// walk i through the haystack, matching j as long as needle[j] matches haystack[i]
		for (i=0; i<hlen-nlen+1; i++) {
			if (haystack[i]==needle[j]) {
				if (j==nlen-1) { // end of needle and it all matched?  win.
					return haystack+i-j;
				} else { // keep advancing j (and i, implicitly)
					j++;
				}
			} else { // no match, rewind i the length of the failed match (j), and reset j
				i-=j;
				j=0;
			}
		}
	}
	return NULL;
}
