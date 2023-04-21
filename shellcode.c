#include <stdio.h>
int main() {
  printf("reachable code\n");
  while (1) {
  }
}
void unreachable() {
  printf("congratulations! you have executed unreachable code\n");
}
