# Define the KMOD name, which is the name of your kernel module
KMOD    = custom

# List your source files here (just the .c file)
SRCS    = custom.c
SRCS+	=          vnode_if.h
SRCS+	=          device_if.h
SRCS+	=          bus_if.h

CFLAGS += -I${.CURDIR}

# Include the kernel module makefile
.include <bsd.kmod.mk>

