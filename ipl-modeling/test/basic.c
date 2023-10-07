// RUN: %clang_dfsan %s -o %t && %run %t
// RUN: %clang_dfsan -mllvm -dfsan-args-abi %s -o %t && %run %t

// Tests that labels are propagated through loads and stores.

//test-clang basic.c
/*
i: 1,
j: 3,
k: 5
x = i + j 6
y = j + k 7
z = i + j + k 8
xy = x + y 8
*/

#include "../dfsan_rt/dfsan_interface.h"
#include <assert.h>
#include <stdio.h>

int main(void) {
  int i = 1;
  dfsan_label i_label = dfsan_create_label(0);
  dfsan_set_label(i_label, &i, sizeof(i));

  // dfsan_label new_label = dfsan_get_label(i);
  // assert(i_label == new_label);

  // dfsan_label read_label = dfsan_read_label(&i, sizeof(i));
  // assert(i_label == read_label);

  int j = 2;
  dfsan_label j_label = dfsan_create_label(1);
  dfsan_set_label(j_label, &j, sizeof(j));
  
  int k = 3;
  dfsan_label k_label = dfsan_create_label(2);
  dfsan_set_label(k_label, &k, sizeof(k));
  printf("i: %d,\nj: %d,\nk: %d\n", i_label, j_label, k_label);

  int x = i + j;
  int y = j + k;
  int z = i + j + k;
  int xy = x + y;

  printf("x = i + j %d\n",dfsan_read_label(&x, sizeof(x)));
  printf("y = j + k %d\n",dfsan_read_label(&y, sizeof(y)));
  printf("z = i + j + k %d\n",dfsan_read_label(&z, sizeof(z)));
  printf("xy = x + y %d\n",dfsan_read_label(&xy, sizeof(xy)));


  return 0;
}
