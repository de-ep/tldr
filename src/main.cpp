#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "utils.h"
#include "peutils.h"


int main (int argc, char* argv[]) {
    PE pe1;
    PPE pe = &pe1;
    PE_ERROR err = PE_ERROR_NO_ERROR;
    unsigned char* file = nullptr;
    size_t file_size;


    if (argc < 2)
        usage();

    file_size = get_file_contents(argv[1], &file);
    if(!file_size)
        goto cleanup;


    printf("calling parser :0");
    err = parse_pe(file, file_size, pe);
    if (err) { 
        fprintf(stderr, "Failed to parse PE: %d", err);
        goto cleanup;
    }




    cleanup: 
        if (file) 
            free(*(void** )file);
        if (pe)
            free(pe->section_headers);


    return EXIT_FAILURE;
}
