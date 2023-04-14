#include <stdio.h>
int main() {
  printf("reachable code\n");
  while (1) {
  }
}
int unreachable() {
  printf("congratulations! you have executed unreachable code\n");
}
