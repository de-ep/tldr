#ifndef UTILS
#define UTILS 

#include <stdio.h>
#include <stdlib.h>


#ifdef __cplusplus
extern "C" {
#endif


size_t calculate_file_size(FILE* fd);
size_t get_file_contents(const char* file_name, unsigned char** file);
void usage();

#ifdef __cplusplus
}
#endif

#endif