#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#pragma pack(1) // Ensure no padding in structures

// ISO 9660 Primary Volume Descriptor structure
typedef struct {
    char type[5];
    char id[32];
    uint8_t version;
    uint8_t unused1;
    char system_id[32];
    char volume_id[32];
    char unused2[8];
    uint32_t volume_space_size;
    char unused3[32];
    uint16_t volume_set_size;
    uint16_t volume_sequence_number;
    uint16_t logical_block_size;
    uint32_t path_table_size;
    uint32_t type_l_path_table;
    uint32_t type_m_path_table;
    char root_directory_record[34];
    char volume_set_id[128];
    char publisher_id[128];
    char data_preparer_id[128];
    char application_id[128];
    char copyright_file_id[38];
    char abstract_file_id[36];
    char bibliographic_file_id[37];
    char creation_date[17];
    char modification_date[17];
    char expiration_date[17];
    char effective_date[17];
    uint8_t file_structure_version;
    uint8_t unused4;
    char application_data[512];
    uint8_t reserved[653];
} PrimaryVolumeDescriptor;

int main(int argc, char *argv[]) {
    // Check for the correct number of command line arguments
    if (argc != 2) {
        printf("Usage: %s <iso_filename>\n", argv[0]);
        return 1;
    }

    // Open the ISO file for reading
    FILE *file = fopen(argv[1], "rb");

    // Check if the file opened successfully
    if (file == NULL) {
        perror("Error opening ISO file");
        return 2;
    }

    // Read the primary volume descriptor
    PrimaryVolumeDescriptor pvd;
    if (fseek(file, 16 * 2048, SEEK_SET) != 0 || fread(&pvd, sizeof(PrimaryVolumeDescriptor), 1, file) != 1) {
        fprintf(stderr, "Error reading primary volume descriptor\n");
        fclose(file);
        return 3;
    }

    // Print some information from the primary volume descriptor
    printf("System ID: %s\n", pvd.system_id);
    printf("Volume ID: %s\n", pvd.volume_id);
    printf("Logical Block Size: %u\n", pvd.logical_block_size);
    printf("Volume Space Size: %u\n", pvd.volume_space_size);

    // Close the file
    fclose(file);

    return 0;
}

