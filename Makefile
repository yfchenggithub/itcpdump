CC=gcc
SRCS=$(wildcard *c)
OBJS=$(patsubst %.c,%.o,$(SRCS))
EXEC=itcpdump
CCFLAGS=-g -Wall
LIBS=-lpcap
RM=rm
RMFLAGS=-rf
$(EXEC):$(OBJS)
	$(CC) $(CCFLAGS) -o $@ $^ $(LIBS)
%.o:%.c
	$(CC) $(CCFLAGS) -c $^
clean:
	$(RM) $(RMFLAGS) $(EXEC) *.o
