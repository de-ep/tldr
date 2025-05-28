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

PE_ERROR map_pe(const PPE pe, unsigned char* file, const size_t file_size, unsigned char** image_base) {
    if ((pe -> nt_header->FileHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL)
        return PE_ERROR_UNSUPPORTED_IMAGE;
    
    DWORD size_of_image, size_of_headers, number_of_sections;

    size_of_image = pe->nt_header->OptionalHeader.SizeOfImage;

    *image_base = (unsigned char * ) VirtualAlloc(NULL, size_of_image, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!*image_base)
        return PE_ERROR_FAILED_TO_ALLOCATE_MEMORY;


    //mapping header to memory
    size_of_headers = pe->nt_header->OptionalHeader.SizeOfHeaders;
    if (size_of_image < size_of_headers)
        return PE_ERROR_INVALID_PE;
    memcpy(*image_base, file, size_of_headers);


    //mapping sections to memory
    number_of_sections = pe->nt_header->FileHeader.NumberOfSections;

    for (DWORD i = 0; i < number_of_sections; i++) {
        if (pe->section_headers[i]->SizeOfRawData == 0)
            continue;

        if (pe->section_headers[i]->VirtualAddress > size_of_image)
            return PE_ERROR_INVALID_PE;
        unsigned char * dest = *image_base + pe->section_headers[i]->VirtualAddress;

        if (pe->section_headers[i]->PointerToRawData > file_size)
            return PE_ERROR_INVALID_PE;
        unsigned char * src = file + pe->section_headers[i]->PointerToRawData;

        DWORD size = pe->section_headers[i]->SizeOfRawData;
        if (pe->section_headers[i]->VirtualAddress + size > size_of_image)
            return PE_ERROR_INVALID_PE;

        memcpy(dest, src, size);
    }


    DWORD op;
    //setting permissions 
    if (!VirtualProtect(*image_base, size_of_headers, PAGE_READONLY, &op) ) {
            return PE_ERROR_FAILED_TO_SET_PERMISSIONS;
        }


    for (DWORD i = 0; i < number_of_sections; i++) {
        if (pe->section_headers[i]->SizeOfRawData == 0)
            continue;

        unsigned char* dest = *image_base + pe->section_headers[i]->VirtualAddress;
        DWORD protection = 0;

        bool readable = (pe->section_headers[i]->Characteristics & IMAGE_SCN_MEM_READ) == IMAGE_SCN_MEM_READ;
        bool writeable = (pe->section_headers[i]->Characteristics & IMAGE_SCN_MEM_WRITE) == IMAGE_SCN_MEM_WRITE; 
        bool executable = (pe->section_headers[i]->Characteristics & IMAGE_SCN_MEM_EXECUTE) == IMAGE_SCN_MEM_EXECUTE;

        if (executable) {
            if (writeable)
                protection = PAGE_EXECUTE_READWRITE;
            else 
                protection = PAGE_EXECUTE_READ;
        }
        else if (writeable)
            protection = PAGE_READWRITE;
        else if (readable) 
            protection = PAGE_READONLY;

        
        if (!VirtualProtect(dest, pe->section_headers[i]->SizeOfRawData, protection, &op) ) {
            printf("vp failed: %lu\n", GetLastError());
            return PE_ERROR_FAILED_TO_SET_PERMISSIONS;
        }
    }
    return PE_ERROR_NO_ERROR;
}


// to free - section_headers image_base
