ccflags-y += -std=gnu99

KERN_DIR = /lib/modules/3.5.0-37-generic/build
myfw-objs := test.o
obj-m += MarsFireWallKernel.o
all:
	make -C $(KERN_DIR) M=$(shell pwd) modules   
clean:                                  
	make -C $(KERN_DIR) M=$(shell pwd) modules clean
	rm -rf modules.order
	rm -f *.symvers

# make CFLAGS+=-std=c99
