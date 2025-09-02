#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

void test_fopen(const char *filename){

	// Step 1: Create a new file (should log as creation)
    FILE *file = fopen(filename, "w");
    if (file) {
        fprintf(file, "This is a test file for creation.\n");
        fclose(file);
        printf("File '%s' created and written successfully.\n", filename);
    } else {
        printf("Failed to create '%s'.\n", filename);
    }

    // Step 2: Open an existing file for reading (should log as open with a hash)
    file = fopen(filename, "r");
    if (file) {
        printf("File '%s' opened for reading successfully.\n", filename);
        fclose(file);
    } else {
        printf("Failed to open '%s' for reading.\n", filename);
    }

    // Step 3: Append to an existing file (should log as write with proper UID and timestamp)
    file = fopen(filename, "a");
    if (file) {
        fprintf(file, "Appending additional text to %s.\n",filename);
        fclose(file);
        printf("File '%s' opened for appending and written successfully.\n", filename);
    } else {
        printf("Failed to open '%s' for appending.\n", filename);
    }

    // Step 4: Try to open a file that does not exist (should log access failure)
    file = fopen("nonexistent_file.txt", "r");
    if (!file) {
        printf("Failed to open 'nonexistent_file.txt' as expected.\n");
    } else {
        fclose(file);
    }

}

void test_fwrite(const char *filename){

	// Step 1: Create a new file and write to it (tests fopen with "w" and fwrite)
    FILE *file = fopen(filename, "w");
    if (file) {
        const char *text = "This is a test write operation.\n";
        fwrite(text, sizeof(char), strlen(text), file);
        fclose(file);
        printf("File '%s' created and written successfully.\n", filename);
    } else {
        printf("Failed to create '%s'.\n", filename);
    }

    // Step 2: Open the file again in append mode and write more data (tests fopen with "a" and fwrite)
    file = fopen(filename, "a");
    if (file) {
        const char *text = "Appending more text to test fwrite.\n";
        fwrite(text, sizeof(char), strlen(text), file);
        fclose(file);
        printf("File '%s' opened for appending and written successfully.\n", filename);
    } else {
        printf("Failed to open '%s' for appending.\n", filename);
    }

    // Step 3: Open the file in read mode (tests fopen with "r" and should not trigger fwrite logging)
    file = fopen(filename, "r");
    if (file) {
        char buffer[128];
        while (fgets(buffer, sizeof(buffer), file)) {
            printf("%s", buffer);
        }
        fclose(file);
        printf("File '%s' read successfully.\n", filename);
    } else {
        printf("Failed to open '%s' for reading.\n", filename);
    }

    // Step 4: Change ownership to root and attempt to write to it
    // to see results here, execute the file with sudo, in order to run as admin
    if (geteuid() == 0) { // Check if running as root
        // Change ownership to root (requires root privileges)
        if (chown(filename, 0, 0) == 0 && chmod(filename, S_IRUSR | S_IRGRP | S_IROTH) == 0) { // Set file to read-only for all users
            printf("File '%s' set to read-only and owned by root.\n", filename);

            file = fopen(filename, "a");
            if (!file) {
                printf("Access denied as expected for appending to root-owned file '%s': %s\n", filename, strerror(errno));
            } else {
                fclose(file);
                printf("Unexpectedly succeeded in opening '%s' for appending.\n", filename);
            }

            // Restore ownership to the current user (requires root privileges)
            chown(filename, getuid(), getgid());
            chmod(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH); // Restore permissions
        } else {
            printf("Failed to change ownership or permissions for '%s'.\n", filename);
        }
    } else {
        printf("Run this test as root (using sudo) to test root-owned file access denial.\n");
    }

}

int main() {
    const char *files[] = { "file1.txt", "file2.txt", "file3.txt", "file4.txt", "file5.txt", "file6.txt", "file7.txt"};

    // Step 1: test fopen
    for (int i = 0; i < 7; i++) {
        test_fopen(files[i]);
    }

    // Step 2: test fwrite
    for (int i = 0; i < 7; i++) {
        test_fwrite(files[i]);
    }

    return 0;
}
