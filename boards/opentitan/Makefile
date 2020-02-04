# Makefile for building the tock kernel for the OpenTitan platform

TARGET=riscv32imc-unknown-none-elf
PLATFORM=opentitan

include ../Makefile.common

flash: target/$(TARGET)/release/$(PLATFORM).bin
	$(OPENTITAN_TREE)/build-bin/sw/host/spiflash/spiflash --input=target/$(TARGET)/release/$(PLATFORM).bin
