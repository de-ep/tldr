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
printf("Allocated: %d for loading the pe\n", size_of_image);

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
        unsigned char* dest = *image_base + pe->section_headers[i]->VirtualAddress;

        if (pe->section_headers[i]->PointerToRawData > file_size)
            return PE_ERROR_INVALID_PE;
        unsigned char* src = file + pe->section_headers[i]->PointerToRawData;

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

        
        if (!VirtualProtect(dest, pe->section_headers[i]->SizeOfRawData, protection, &op) )
            return PE_ERROR_FAILED_TO_SET_PERMISSIONS;
        
    }
    return PE_ERROR_NO_ERROR;
}

PE_ERROR fix_iat(const PPE pe, unsigned char** image_base) {
    const DWORD image_size =  pe->nt_header->OptionalHeader.SizeOfImage; 

    DWORD offset_import_dir =  pe->nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!offset_import_dir || offset_import_dir > image_size+sizeof(IMAGE_IMPORT_DESCRIPTOR))
        return PE_ERROR_INVALID_PE;
    
    PIMAGE_IMPORT_DESCRIPTOR import_dir = (PIMAGE_IMPORT_DESCRIPTOR)(*image_base + offset_import_dir);


    while (import_dir->Name) {
        const char* name = (const char* )(*image_base+import_dir->Name);
printf("%s\n", name);
        HMODULE han_lib = LoadLibrary(name);
        if (!han_lib)
            return PE_ERROR_FAILED_TO_LOAD_LIBRARY;
        

        //resolving fn addresses
        DWORD offset_thunk_data = import_dir->OriginalFirstThunk;
        if (!offset_thunk_data || offset_thunk_data > image_size+sizeof(IMAGE_THUNK_DATA64))
            return PE_ERROR_INVALID_PE;
        PIMAGE_THUNK_DATA64 orig_thunk = (PIMAGE_THUNK_DATA64) (*image_base + offset_thunk_data); 

        offset_thunk_data = import_dir->FirstThunk;
        if (!offset_thunk_data || offset_thunk_data > image_size+sizeof(IMAGE_THUNK_DATA64))
            return PE_ERROR_INVALID_PE;
        PIMAGE_THUNK_DATA64 first_thunk = (PIMAGE_THUNK_DATA64) (*image_base + offset_thunk_data); 


        while (orig_thunk->u1.AddressOfData) {
            
            if (orig_thunk->u1.AddressOfData > image_size+sizeof(IMAGE_IMPORT_BY_NAME))
                return PE_ERROR_INVALID_PE;

            PIMAGE_IMPORT_BY_NAME import_by_name = (PIMAGE_IMPORT_BY_NAME)(*image_base + orig_thunk->u1.AddressOfData);
            const char* function_name = import_by_name->Name;
printf("\t\t%s\n", function_name);            
            FARPROC fn_add = GetProcAddress(han_lib, (LPCSTR)function_name);
            if (!fn_add)
                return PE_ERROR_FAILED_TO_GET_PROC_ADDRESS;

            first_thunk->u1.Function = (ULONGLONG)fn_add;

            first_thunk++;
            orig_thunk++;
        }

        import_dir ++;
    }

    return PE_ERROR_NO_ERROR;
}

PE_ERROR fix_relocation_table(const PPE pe, unsigned char** image_base) {
    const DWORD image_size = pe->nt_header->OptionalHeader.SizeOfImage;

    ULONGLONG delta = (ULONGLONG)*image_base - pe->nt_header->OptionalHeader.ImageBase;
    if (!delta) 
        return PE_ERROR_NO_ERROR;

    DWORD offset_base_relocation = pe->nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;

    for (;;) {

        if (!offset_base_relocation || offset_base_relocation > image_size + sizeof(IMAGE_BASE_RELOCATION))
            return PE_ERROR_INVALID_PE;

        PIMAGE_BASE_RELOCATION base_reloc = (PIMAGE_BASE_RELOCATION)(*image_base + offset_base_relocation);
        if (!base_reloc->SizeOfBlock) 
            break;

        DWORD cur_size = sizeof(IMAGE_BASE_RELOCATION);
        PWORD word = (PWORD)(*image_base + offset_base_relocation + sizeof(IMAGE_BASE_RELOCATION));

        while (base_reloc->SizeOfBlock > cur_size) {
            WORD type = *word >> 12;     // fetch high 4 bits
            WORD offset = *word & 4095;  // fetch low 12 bits

            PULONGLONG fix_this_ptr =
                PULONGLONG(*image_base + base_reloc->VirtualAddress + offset);

            switch (type) {
                case IMAGE_REL_BASED_DIR64: {
                    DWORD lpflOldProtect, lpflOldProtect1;
                    
                    bool ret = VirtualProtect(
                        (LPVOID)fix_this_ptr, 
                        sizeof(ULONGLONG),
                        PAGE_READWRITE, 
                        &lpflOldProtect
                    );
                    if (!ret) 
                        return PE_ERROR_FAILED_TO_SET_PERMISSIONS;

                    *fix_this_ptr += delta;

                    ret = VirtualProtect(
                        (LPVOID)fix_this_ptr, 
                        sizeof(ULONGLONG),
                        lpflOldProtect, 
                        &lpflOldProtect1
                    );
                    if (!ret) 
                        return PE_ERROR_FAILED_TO_SET_PERMISSIONS;

                    
                    break;
                }

                default:
                    break;
            }

            cur_size += sizeof(WORD);
            word++;
        }
        offset_base_relocation += base_reloc->SizeOfBlock;
    }

    return PE_ERROR_NO_ERROR;
}


// to free - section_headers image_base
