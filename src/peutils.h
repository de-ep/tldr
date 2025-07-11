#ifndef PEUTILS
#define PEUTILS

#include <stdio.h>
#include <stdbool.h> 
#include <windows.h>

typedef enum {
    PE_ERROR_NO_ERROR,
    PE_ERROR_GENERAL_ERROR,
    PE_ERROR_INVALID_PE,
    PE_ERROR_UNSUPPORTED_IMAGE,
    PE_ERROR_FAILED_TO_ALLOCATE_MEMORY,
    PE_ERROR_FAILED_TO_SET_PERMISSIONS,
    PE_ERROR_FAILED_TO_LOAD_LIBRARY,
    PE_ERROR_FAILED_TO_GET_PROC_ADDRESS,

} PE_ERROR;

typedef struct {
    PIMAGE_DOS_HEADER dos_header;
    PIMAGE_NT_HEADERS64 nt_header;
    PIMAGE_SECTION_HEADER* section_headers;

} PE, *PPE;

#define DOS_SIGNATURE 23117     //MZ
#define NT_SIGNATURE 17744      //PE\0\0
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b
#define IMAGE_DIRECTORY_ENTRY_IMPORT 1

#ifdef __cplusplus
extern "C" {
#endif


PE_ERROR parse_pe(const unsigned char* pe, const size_t size, PPE parsed_pe);
PE_ERROR map_pe(const PPE pe, unsigned char* file, const size_t file_size, unsigned char** image_base);
PE_ERROR fix_iat(const PPE pe, unsigned char** image_base);
PE_ERROR fix_relocation_table(const PPE pe, unsigned char** image_base);

#ifdef __cplusplus
}
#endif

#endif