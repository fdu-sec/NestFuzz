#ifndef LOOP_HANDLERS_H
#define LOOP_HANDLERS_H
#ifdef __cplusplus
extern "C" {
#endif


void __chunk_object_stack_fini();

void __chunk_set_input_file_name(int );
    // const char* name

#ifdef __cplusplus
}
#endif

#endif