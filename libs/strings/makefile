all: libstring.a

# LINUX-X86
PF_CC=gcc
PF_CCFLAG=-DOS_LINUX -DM_GENERIC_INT32 -march=i586 -fPIC -O -Wall
PF_EXEFLAG=
PF_EXELIB=
######################################################################
# LINUX-X86_64
#PF_CC=gcc
#PF_CCFLAG=-DOS_LINUX -DM_GENERIC_INT32 -m64 -fPIC -O -Wall -g
#PF_EXEFLAG=-m64
#PF_EXELIB=

PROJ_CC=$(PF_CC)
PROJ_CCFLAG=$(PF_CCFLAG) -I.

clean:
	rm -f *.a *.o

.c.o:
	$(PROJ_CC) $(PROJ_CCFLAG) -c $< -o $@

libstring.a: NMstring.o
	ar -r libstring.a NMstring.o
