#include "peutils.h"

PE_ERROR parse_section_headers (const unsigned char* pe, const size_t size, DWORD no_of_sections, DWORD e_lfanew, PIMAGE_SECTION_HEADER** section_headers) {

    PIMAGE_SECTION_HEADER* section_headers1 = (PIMAGE_SECTION_HEADER* )malloc(no_of_sections * sizeof(PIMAGE_SECTION_HEADER));
    if (!section_headers1)
        return PE_ERROR_GENERAL_ERROR;

    size_t offset_section_header = e_lfanew + sizeof(IMAGE_NT_HEADERS64);

    
    for (DWORD i = 0 ; i < no_of_sections ; i++) {
        if (offset_section_header >= size)
            return PE_ERROR_INVALID_PE;  

        section_headers1[i] = (PIMAGE_SECTION_HEADER)(pe + offset_section_header);
        offset_section_header += sizeof(IMAGE_SECTION_HEADER);

    }

    *section_headers = section_headers1;

    return PE_ERROR_NO_ERROR;
}

PE_ERROR parse_pe (const unsigned char* pe, const size_t size, PPE parsed_pe) {

    PIMAGE_DOS_HEADER dos_header =  (PIMAGE_DOS_HEADER) pe;
    if (dos_header->e_magic != DOS_SIGNATURE)
        return PE_ERROR_INVALID_PE;


    //parsing nt header 
    //offset to nt header
    if (dos_header->e_lfanew >= size)
        return PE_ERROR_INVALID_PE;

    PIMAGE_NT_HEADERS64 nt_header = (PIMAGE_NT_HEADERS64 )(pe + dos_header->e_lfanew);

    //checking if pe is 64bit executable file
    if (nt_header->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return PE_ERROR_UNSUPPORTED_IMAGE;

    if (nt_header->Signature !=  NT_SIGNATURE)
        return PE_ERROR_INVALID_PE;
    

    //parsing section headers
    PIMAGE_SECTION_HEADER* section_headers;
    PE_ERROR err = parse_section_headers(pe, size, nt_header->FileHeader.NumberOfSections, dos_header->e_lfanew, &section_headers);
    
    if (err) 
        return err;


    parsed_pe->dos_header = dos_header;
    parsed_pe->nt_header = nt_header;
    parsed_pe->section_headers = section_headers;


    return PE_ERROR_NO_ERROR;
}

// to free - section_headers