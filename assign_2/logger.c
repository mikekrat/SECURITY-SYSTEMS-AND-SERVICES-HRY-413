#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <string.h>
#include <errno.h>

#include <stdlib.h>
#include <stdbool.h>
#define MAX_LEN 256
#define TIME_LEN 32

static int in_fopen = 0; // Prevent recursive fopen calls

// Function to calculate the SHA-256 hash of a file and return as a hex string
char* calculate_file_hash(const char *filename) {
    static char hash_str[65]; // SHA-256 produces a 64-char hex hash, plus null terminator
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    // Obtain the original fopen function to avoid triggering our own override
    FILE* (*original_fopen)(const char *, const char *) = dlsym(RTLD_NEXT, "fopen");
    if (!original_fopen) {
        return NULL;
    }

    FILE *file = original_fopen(filename, "rb");
    if (!file) {
        return NULL;
    }
    
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fclose(file);
        return NULL;
    }
    
    const EVP_MD *md = EVP_sha256();
    EVP_DigestInit_ex(mdctx, md, NULL);
    
    unsigned char buffer[1024];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), file)) != 0) {
        EVP_DigestUpdate(mdctx, buffer, bytes);
    }
    
    fclose(file);
    
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);
    
    // Convert hash to hex string
    for (unsigned int i = 0; i < hash_len; i++) {
        sprintf(&hash_str[i * 2], "%02x", hash[i]);
    }
    return hash_str;
}

FILE* fopen(const char *filename, const char *mode) {
    // Avoid recursion by skipping override in our own fopen calls
    if (in_fopen) {
        return NULL;
    }

    in_fopen = 1; // Set recursion prevention flag

    // Obtain the original fopen function using dlsym
    FILE* (*original_fopen)(const char *, const char *) = dlsym(RTLD_NEXT, "fopen");
    if (!original_fopen) {
        in_fopen = 0;
        return NULL;
    }

    // Define variables for logging details
    uid_t uid = getuid();
    //char *access_type;
    int access_type_code;
    int denied_flag = 0;
    char tmp_time[TIME_LEN], tmp_date[TIME_LEN];
    char abs_file_path[MAX_LEN];
    char *file_hash = NULL;

    // Determine access type based on mode
    if (strstr(mode, "w") != NULL || strstr(mode, "a") != NULL) {
        //access_type = "creation";
        access_type_code = 0;
    } else {
        //access_type = "open";
        access_type_code = 1;
    }

    // Get the absolute path of the file
    realpath(filename, abs_file_path);

    // Get current UTC date and time separately
    time_t now = time(NULL);
    struct tm *utc_tm = gmtime(&now);
    strftime(tmp_date, sizeof(tmp_date), "%Y-%m-%d", utc_tm);
    strftime(tmp_time, sizeof(tmp_time), "%H:%M:%S", utc_tm);

    // Calculate the file hash if access type is open (not for new files being created)
    if (access_type_code == 1) {
        file_hash = calculate_file_hash(abs_file_path);
    }

    // Open log file for appending the log entry
    FILE *log_file = original_fopen("file_logging.log", "a");
    if (!log_file) {
        in_fopen = 0;
        return NULL;
    }

    // Log entry to "file_logging.log" with separated date and time
    fprintf(log_file, "UID: %d\tFilename: %s\tDate: %s\tTimestamp: %s\tAccessType: %d\tIs_Action_Denied Flag: %d\tFile Fingerprint: %s\n",
            uid, abs_file_path, tmp_date, tmp_time, access_type_code, denied_flag, file_hash ? file_hash : "N/A");

    // Close log file after writing
    fclose(log_file);

    // Call the original fopen function for the requested file
    FILE *result = original_fopen(filename, mode);

    in_fopen = 0; // Reset recursion prevention flag
    return result;
}



void refresh_log_file(char* file_path, bool has_action, int access_type, int user_id) {
    time_t raw_time;
    int has_action_int = has_action ? 1 : 0;
    struct tm* time_info;
    char abs_file_path[MAX_LEN], tmp_time[TIME_LEN], tmp_date[TIME_LEN];
    char log_entry[MAX_LEN * 2];
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    
    /* Resolve the absolute path */
    realpath(file_path, abs_file_path);

    /* Get current time */
    raw_time = time(NULL);
    time_info = localtime(&raw_time);
    strftime(tmp_time, TIME_LEN, "%T", time_info);
    strftime(tmp_date, TIME_LEN, "%F", time_info);

    /* Prepare logging format */
    sprintf(log_entry, "UID: %d\tFilename: %s\tDate: %s\tTimestamp: %s\tAccessType: %d\tIs_Action_Denied Flag: %d\tFile Fingerprint: ",
            user_id, abs_file_path, tmp_date, tmp_time, access_type, has_action_int);

    /* Calculate SHA-256 hash of the file */
    FILE* file = fopen(abs_file_path, "rb");
    if (!file) {
        printf("[ERROR] Failed to open file for hashing: %s\n", abs_file_path);
        strcat(log_entry, "N/A\n");
    } else {
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        const EVP_MD *md = EVP_sha256();
        EVP_DigestInit_ex(mdctx, md, NULL);

        unsigned char buffer[1024];
        size_t bytes_read;
        while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
            EVP_DigestUpdate(mdctx, buffer, bytes_read);
        }

        EVP_DigestFinal_ex(mdctx, hash, &hash_len);
        EVP_MD_CTX_free(mdctx);
        fclose(file);

        /* Convert hash to hex and append to log entry */
        for (unsigned int i = 0; i < hash_len; i++) {
            sprintf(&log_entry[strlen(log_entry)], "%02x", hash[i]);
        }
        strcat(log_entry, "\n");
    }

    /* Write log entry to file_logging.log */
    FILE* log_file = fopen("file_logging.log", "a");
    if (log_file) {
        fputs(log_entry, log_file);
        fclose(log_file);
    } else {
        printf("[ERROR] Failed to open log file for writing.\n");
    }
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    char file_path[MAX_LEN];
    char proc[MAX_LEN];
    ssize_t read_len;
    size_t original_fwrite_ret;
    size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);
    bool has_action = false;

    /* Call the original fwrite function */
    original_fwrite = dlsym(RTLD_NEXT, "fwrite");
    original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);

    /* Ensure all data is written */
    fflush(stream);

    /* Determine file path */
    sprintf(proc, "/proc/self/fd/%d", fileno(stream));
    read_len = readlink(proc, file_path, MAX_LEN);

    if (read_len >= 0) {
        file_path[read_len] = '\0';
    } else {
        printf("[ERROR] Failed to resolve file path.\n");
        return original_fwrite_ret;
    }

    /* Check if the user has write access to the file */
    if (access(file_path, W_OK) == 0) {
        has_action = true;
    }

    /* Log the write action */
    refresh_log_file(file_path, has_action, 2, getuid());

    return original_fwrite_ret;
}


