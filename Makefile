# Midnight-Hail donut Makefile — adds EXTRA_CFLAGS hook + seed prereq.
# Vanilla `make donut` with DONUT_SEED unset reproduces upstream byte-for-byte
# because include/seed.h ships committed with stock constants.

EXTRA_CFLAGS ?=

donut: clean seed
	gcc $(EXTRA_CFLAGS) -Wunused-function -Wall -fpack-struct=8 -DDONUT_EXE -I include donut.c hash.c encrypt.c format.c loader/clib.c lib/aplib64.a -odonut
	gcc $(EXTRA_CFLAGS) -Wunused-function -Wall -c -fpack-struct=8 -fPIC -I include donut.c hash.c encrypt.c format.c loader/clib.c
	ar rcs lib/libdonut.a donut.o hash.o encrypt.o format.o clib.o lib/aplib64.a
	gcc $(EXTRA_CFLAGS) -Wall -shared -o lib/libdonut.so donut.o hash.o encrypt.o format.o clib.o lib/aplib64.a

debug: clean seed
	gcc $(EXTRA_CFLAGS) -Wunused-function -ggdb -Wall -Wno-format -fpack-struct=8 -DDEBUG -DDONUT_EXE -I include donut.c hash.c encrypt.c format.c loader/clib.c lib/aplib64.a -odonut

hash: seed
	gcc $(EXTRA_CFLAGS) -Wall -Wno-format -fpack-struct=8 -DTEST -I include hash.c loader/clib.c -ohash

encrypt: seed
	gcc $(EXTRA_CFLAGS) -Wall -Wno-format -fpack-struct=8 -DTEST -I include encrypt.c loader/clib.c -oencrypt

# KAT round-trip linked against the SAME encrypt.o + hash.o the generator uses.
# Non-zero exit = cipher mismatch or identity-map degeneracy = Docker build halts.
kat: seed
	gcc $(EXTRA_CFLAGS) -Wall -fpack-struct=8 -I include tools/kat.c encrypt.c hash.c loader/clib.c -okat

# seed-gen is a no-op when DONUT_SEED is empty (keeps committed stock include/seed.h).
seed:
	@python3 tools/seed-gen.py

inject:
	gcc -Wall -Wno-format -fpack-struct=8 -DTEST -I include loader/inject.c -oinject
inject_local:
	gcc -Wall -Wno-format -fpack-struct=8 -DTEST -I include loader/inject_local.c -oinject_local
clean:
	rm -f loader.exe exe2h.exe exe2h loader32.exe loader64.exe donut.o hash.o encrypt.o format.o clib.o hash encrypt donut kat hash.exe encrypt.exe donut.exe lib/libdonut.a lib/libdonut.so

.PHONY: seed kat clean
