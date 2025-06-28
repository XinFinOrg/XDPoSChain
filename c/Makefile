.POSIX:

# =====================================================================
#
# Configurable options:
#   CC       C compiler; GCC or Clang are fine; MSVC (2015+) works too.
#   CFLAGS   Compilation flags:
#             * Optimization level -O2 or higher is recommended
#            See config.h for some possible configuration macros.
#   LD       Linker; normally the same command as the compiler.
#   LDFLAGS  Linker options, not counting the extra libs.
#   LIBS     Extra libraries for linking:
#             * If using the native FPU, test_falcon and application
#               code that calls this library may need: -lm
#               (normally not needed on x86, both 32-bit and 64-bit)

CC = gcc
CFLAGS = -Wall -Wextra -Wshadow -Wundef -O3 #-pg -fno-pie
CFLAGS += -DFALCON_PRNG_KECCAK256=0 # uses keccak prng
LD = gcc
LDFLAGS = #-pg -no-pie
LIBS = #-lm

# =====================================================================

OBJ = codec.o common.o falcon.o fft.o fpr.o keygen.o rng.o shake.o sign.o vrfy.o keccak_prng.o keccak256.o

all: test_falcon speed test_prng

clean:
	-rm -f $(OBJ) test_falcon test_falcon.o speed speed.o test_prng test_prng.o keccak_prng.o keccak256.o

test_falcon: test_falcon.o $(OBJ)
	$(LD) $(LDFLAGS) -o test_falcon test_falcon.o $(OBJ) $(LIBS)

speed: speed.o $(OBJ)
	$(LD) $(LDFLAGS) -o speed speed.o $(OBJ) $(LIBS)

test_prng: test_prng.o keccak_prng.o keccak256.o
	$(LD) $(LDFLAGS) -o test_prng test_prng.o keccak_prng.o keccak256.o shake.o $(LIBS)

codec.o: codec.c config.h inner.h fpr.h
	$(CC) $(CFLAGS) -c -o codec.o codec.c

common.o: common.c config.h inner.h fpr.h
	$(CC) $(CFLAGS) -c -o common.o common.c

falcon.o: falcon.c falcon.h config.h inner.h fpr.h
	$(CC) $(CFLAGS) -c -o falcon.o falcon.c

fft.o: fft.c config.h inner.h fpr.h
	$(CC) $(CFLAGS) -c -o fft.o fft.c

fpr.o: fpr.c config.h inner.h fpr.h
	$(CC) $(CFLAGS) -c -o fpr.o fpr.c

keygen.o: keygen.c config.h inner.h fpr.h
	$(CC) $(CFLAGS) -c -o keygen.o keygen.c

rng.o: rng.c config.h inner.h fpr.h
	$(CC) $(CFLAGS) -c -o rng.o rng.c

shake.o: shake.c config.h inner.h fpr.h
	$(CC) $(CFLAGS) -c -o shake.o shake.c

sign.o: sign.c config.h inner.h fpr.h
	$(CC) $(CFLAGS) -c -o sign.o sign.c

speed.o: speed.c falcon.h
	$(CC) $(CFLAGS) -c -o speed.o speed.c

test_falcon.o: test_falcon.c falcon.h config.h inner.h fpr.h
	$(CC) $(CFLAGS) -c -o test_falcon.o test_falcon.c

vrfy.o: vrfy.c config.h inner.h fpr.h
	$(CC) $(CFLAGS) -c -o vrfy.o vrfy.c

keccak_prng.o: keccak_prng.c keccak256.h
	$(CC) $(CFLAGS) -c -o keccak_prng.o keccak_prng.c

keccak256.o: keccak256.c keccak256.h
	$(CC) $(CFLAGS) -c -o keccak256.o keccak256.c

test_prng.o: test_prng.c keccak256.h
	$(CC) $(CFLAGS) -c -o test_prng.o test_prng.c