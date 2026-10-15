#include <stdio.h>

static int twice(int value) {
  return value * 2;
}

int main(void) {
  puts("REA radare2 transport fixture");
  return twice(7);
}
