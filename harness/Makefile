.PHONY: clean

harness: harness.c
	$(CC) $^ -Wall -Wextra -Wpedantic -O2 -o$@ -lnftables -Wl,-z,relro,-z,now -DHARNESS -masm=intel

clean:
	rm -f harness
