#include "utils.h"
#include "peutils.h"


int main(int argc, char * argv[]) {
    PE pe1;
    PPE pe = & pe1;
    PE_ERROR err = PE_ERROR_NO_ERROR;
    unsigned char * file = nullptr;
    size_t file_size;
    unsigned char* image_base = nullptr, *entry_point;

    if (argc < 2)
        usage();

    file_size = get_file_contents(argv[1], &file);
    if (!file_size)
        goto cleanup;


    err = parse_pe(file, file_size, pe);
    if (err) {
        fprintf(stderr, "Failed to parse PE: %d\n", err);
        goto cleanup;
    }


    err = map_pe(pe, file, file_size, &image_base);
    if (err) {
        fprintf(stderr, "Failed to load PE: %d\n", err);
        goto cleanup;
    }

    err = fix_iat(pe, file, file_size, &image_base);
    if (err) {
        fprintf(stderr, "Failed to fix IAT: %d\n", err);
        goto cleanup;
    }    

    entry_point = image_base + pe->nt_header->OptionalHeader.AddressOfEntryPoint;
   
   
   
   printf("success\n");

    cleanup:
        if (file)
            free(file);
        if (pe->section_headers)
            free(pe->section_headers);
        if (image_base)
            free(image_base);

    return err ? EXIT_FAILURE : EXIT_SUCCESS;
}
