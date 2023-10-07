/*

clang -I /home/jordan/develop/chunk-fuzzer-pass/dfsan_rt/ -I /home/jordan/develop/chunk-fuzzer-pass/include/ \
-pie -fpic -funroll-loops \
-Wl,--whole-archive /home/jordan/develop/chunk-fuzzer-pass/install/lib/libdfsan_rt-x86_64.a -Wl,--no-whole-archive \
-Wl,--dynamic-list=/home/jordan/develop/chunk-fuzzer-pass/install/lib/libdfsan_rt-x86_64.a.syms \
/home/jordan/develop/chunk-fuzzer-pass/install/lib/libruntime.a -Wl,--gc-sections \
-lstdc++ -ldl -lpthread -lm -g -O3 dfsan_test.c

test-clang dfsan_test.c

*/

#include "../dfsan_rt/dfsan_interface.h"
#include <assert.h>
#include <stdio.h>

int main(void) {
  int i = 1;
  dfsan_label i_label = dfsan_create_label(0);
  dfsan_set_label(i_label, &i, sizeof(i));

  int j = 2;
  dfsan_label j_label = dfsan_create_label(4);
  dfsan_set_label(j_label, &j, sizeof(j));

  int k = 3;
  dfsan_label k_label = dfsan_create_label(8);
  dfsan_set_label(k_label, &k, sizeof(k));

  //printf("%u\n",__dfsw_dfsan_get_label(i));
  printf("%u\n",dfsan_read_label(&i,sizeof(i)));

  //printf("%u\n",__dfsw_dfsan_get_label(j));
  printf("%u\n",dfsan_read_label(&j,sizeof(j)));

  //printf("%d",__dfsw_dfsan_get_label(k));
  printf("%u\n",dfsan_read_label(&k,sizeof(k)));

  // dfsan_label ij_label = dfsan_read_label(i + j);
  // assert(dfsan_has_label(ij_label, i_label));
  // assert(dfsan_has_label(ij_label, j_label));
  // assert(!dfsan_has_label(ij_label, k_label));

  // dfsan_label ijk_label = dfsan_get_label(i + j + k);
  // assert(dfsan_has_label(ijk_label, i_label));
  // assert(dfsan_has_label(ijk_label, j_label));
  // assert(dfsan_has_label(ijk_label, k_label));

  return 0;
}
