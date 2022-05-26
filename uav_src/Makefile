#CC = arm-linux-gnueabihf-gcc


OUT_BIN = test

OUT_SHARE_LIB = libvecentek.so

# libse_test.so

OUT_STATIC_LIB =

# libse_test.a 

OBJDIR = obj

#CC = arm-linux-gnueabi-gcc


SHARELIBPATH = -L./lib #-Wl,-rpath=./lib

SHARELIB = -linitso -lvccrypt -lm 

INCLUDE = -I../include

VPATH = ./

CFLAGS = -fPIC #-DCRUL_TEST





DEFS =# -DTEST_IIC# -DTEST_ADD -DTEST_SUB=1 #the two method Macro define #define TEST_ADD TEST_SUB


DIRS := $(shell find . -maxdepth 3 -type d)



SRCSC = $(foreach dir,$(DIRS),$(wildcard $(dir)/*.c))
CFLAGS +=$(DEFS)


HEADERS = $(foreach dir,$(DIRS),-I $(dir))

INCLUDE = ./include



$(warning "HEADERS $(HEADERS)")



$(warning "SRCSC ------------------**----------------- $(SRCSC)")

$(warning "$(SRCSC)")

$(warning "SRCSC END --------------**-----------------")

OBJS_1 = $(addsuffix .o,$(basename $(SRCSC)))

OBJS = $(foreach n,$(notdir $(OBJS_1)),$(OBJDIR)/$(n))
LIB_OBJS = $(filter-out ./main.o, $(OBJS))



OUT_BIN_CMD =

OUT_SHARE_LIB_CMD =

OUT_STATIC_LIB_CMD =



ifdef OUT_BIN

   OUT_BIN_CMD = $(CC) -o $(OUT_BIN) $(OBJS) $(SHARELIBPATH) $(SHARELIB) 

endif



ifdef OUT_SHARE_LIB

   OUT_SHARE_LIB_CMD = $(CC) -shared -o $(OUT_SHARE_LIB) $(LIB_OBJS) $(SHARELIBPATH) $(SHARELIB)

endif



ifdef OUT_STATIC_LIB

   OUT_STATIC_LIB_CMD = ar rcs $(OUT_STATIC_LIB) $(LIB_OBJS) 

endif





all: $(CMP) $(OBJS)


	$(OUT_BIN_CMD)

	$(OUT_SHARE_LIB_CMD)

	$(OUT_STATIC_LIB_CMD)





$(OBJS):$(SRCSC) #$(HEADERS)

	$(CC) -c $(SRCSC) $(SHARELIBPATH) $(SHARELIB) $(CFLAGS) -I $(INCLUDE) $(HEADERS)

	rm -rf $(OBJDIR)

	mkdir -p $(OBJDIR)

	mv *.o $(OBJDIR)/



clean:

	-rm -rf $(OUT_BIN) $(OUT_SHARE_LIB) $(OUT_STATIC_LIB)

	-rm -rf ./$(OBJDIR)

