# SPDX-License-Identifier: GPL-2.0
OBJECT_FILES_NON_STANDARD := y

hostprogs-y	:= mk_elfconfig
always		:= $(hostprogs-y) empty.o

modpost-objs	:= sumversion.o

devicetable-offsets-file := devicetable-offsets.h

$(obj)/$(devicetable-offsets-file): $(obj)/devicetable-offsets.s FORCE
	$(call filechk,offsets,__DEVICETABLE_OFFSETS_H__)

targets += $(devicetable-offsets-file) devicetable-offsets.s

# dependencies on generated files need to be listed explicitly

$(obj)/modpost.o $(obj)/file2alias.o $(obj)/sumversion.o: $(obj)/elfconfig.h
