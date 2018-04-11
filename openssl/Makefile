CFLAGS += $(addprefix -I,$(INC_DIR))
CFLAGS += -I.
LDLIBS += -lcrypto

BIN := cryto_main
OBJS := readFile.o h264Util.o cryto_main.o

.PHONY: all

all:$(BIN)

$(BIN):$(OBJS)
	@echo "compile" $@
	@$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)
	
readFile.o : readFile.c
	@echo "compile" $@
	@$(CC) -c $(CFLAGS) $^ -o $@
	
h264Util.o : h264Util.c
	@echo "compile" $@
	@$(CC) -c $(CFLAGS) $^ -o $@
	
cryto_main.o : cryto_main.c
	@echo "compile" $@
	@$(CC) -c $(CFLAGS) $^ -o $@

clean:
	@rm -f  $(OBJS)
