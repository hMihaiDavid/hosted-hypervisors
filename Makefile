KDIR ?= $$PWD/../buildroot-2021.02.8/output/build/linux-5.10.7

default:
	$(MAKE) -C $(KDIR) M=$$PWD
clean:
	rm modules.order Module.symvers *.mod *.mod.* *.o *.ko

