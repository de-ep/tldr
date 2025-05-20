#include "utils.h"

size_t calculate_file_size(FILE* fd) {
    if (fseek(fd, 0, SEEK_END)) {
        perror("Fseek fail");
        return 0;
    }

    size_t file_size = ftell(fd);
    if (file_size <= 0) {
        perror("Ftell fail");
        return 0;
    }

    rewind(fd);

    return file_size;
}

size_t get_file_contents(const char* file_name, unsigned char** file) {
    int err = 1;
    size_t file_size;

    FILE* fd = fopen(file_name, "rb");
    if (!fd) {
        perror("Failed to open file");
        goto cleanup;
    }

    file_size = calculate_file_size(fd);
    if(!file_size)
        goto cleanup;

    *file = (unsigned char* )malloc(file_size);
        if (!*file) {
            fprintf(stderr, "Failed to allocate buffer\n");
            goto cleanup;
        }

    if (fread(*file, 1, file_size, fd) != file_size) {
        perror("Failed to read from file");
        goto cleanup;
    }

    err = 0;


    cleanup:
        if (fd)
            fclose(fd);
        return (err) ? 0 : file_size;
}

void usage() {
    fprintf(stderr, "Usage: tldr.exe <executable>");
    exit(EXIT_FAILURE);

}

// to free - *file