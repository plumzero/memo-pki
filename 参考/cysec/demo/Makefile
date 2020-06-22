# Compiler settings
CC      = $(CROSS_COMPILE)gcc
CFLAGS  = -g -I. -D_REENTRANT -D_GNU_SOURCE -fPIC -I../include $(CCFLAGS)
LDFLAGS = $(LLDFLAGS)
LIBS = $(LLIBS) -lcysec

RM     = rm -f

STRIP  = $(CROSS_COMPILE)strip

# Implicit rules

SUFFIXES = .o .c .h .a .so .sl

COMPILE.c=$(CC) $(CFLAGS) -c
.c.o:
	@(echo "compiling $< ...")
	@($(COMPILE.c) -o $@ $(CFLAGS) $<)

TARGET1 = demo1
SRCS1 = demo1.c util.c
OBJS1 = $(SRCS1:.c=.o)

TARGET2 = demo2
SRCS2 = demo2.c util.c
OBJS2 = $(SRCS2:.c=.o)

TARGET3 = demo3
SRCS3 = demo3.c util.c
OBJS3 = $(SRCS3:.c=.o)

TARGET4 = demo4
SRCS4 = demo4.c util.c
OBJS4 = $(SRCS4:.c=.o)

all: $(TARGET1) $(TARGET2) $(TARGET3) $(TARGET4)

$(TARGET1) : $(OBJS1)
	$(CC) -o $(TARGET1) $(OBJS1) $(CFLAGS) $(CCFLAGS) $(LDFLAGS) $(LIBDIR) -lm -L../lib $(LIBS)
	#$(STRIP) $(TARGET1)

$(TARGET2) : $(OBJS2)
	$(CC) -o $(TARGET2) $(OBJS2) $(CFLAGS) $(CCFLAGS) $(LDFLAGS) $(LIBDIR) -lm -L../lib $(LIBS)
	#$(STRIP) $(TARGET2)

$(TARGET3) : $(OBJS3)
	$(CC) -o $(TARGET3) $(OBJS3) $(CFLAGS) $(CCFLAGS) $(LDFLAGS) $(LIBDIR) -lm -L../lib $(LIBS)
	#$(STRIP) $(TARGET3)

$(TARGET4) : $(OBJS4)
	$(CC) -o $(TARGET4) $(OBJS4) $(CFLAGS) $(CCFLAGS) $(LDFLAGS) $(LIBDIR) -lm -L../lib $(LIBS)
	#$(STRIP) $(TARGET3)

clean:
	@rm -f $(TARGET4)
	@rm -f $(TARGET3)
	@rm -f $(TARGET2)
	@rm -f $(TARGET1)
	@rm -f *.o
