all : snooper clean



PF_CC=gcc
PF_CCFLAG=-DOS_LINUX -DM_GENERIC_INT32 -fPIC -g -Wall
PF_EXEFLAG= -DFILTER_ON -DFILTERDATA_ON -DFILTERPORT_ON
PF_EXELIB=

PROJ_CC=$(PF_CC)
PROJ_CCFLAG=$(PF_CCFLAG)
PROJ_EXEFLAG=$(PF_EXEFLAG)
PROJ_EXELIB=$(PF_EXELIB) 

clean :
	rm -f snoop *.o *.a

.c.o:
	$(PROJ_CC) $(PROJ_CCFLAG) $(PROJ_EXEFLAG) -c $< -o $@
	
snooper : snooper.o
	echo "char build_date[] = \"@(#$@) Last build time -> `date`\";" > buildident.c
	$(PROJ_CC) $(PROJ_EXEFLAG) -c buildident.c
	$(PROJ_CC) $(PROJ_EXEFLAG) -o snooper snooper.o buildident.o $(PROJ_EXELIB)
	rm buildident.*
