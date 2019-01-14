EXEC=factory_test 
SRC=factory_test.c

all: $(EXEC)
factory_test: $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRC) $(LDLIBS)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o