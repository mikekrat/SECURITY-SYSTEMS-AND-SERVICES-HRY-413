#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_LOG_ENTRIES 1000
#define MAX_FILENAME_LEN 256

struct log_entry {
	int uid;              /* User ID (positive integer) */
	int access_type;      /* Access type values [0-2] */
	int action_denied;    /* Is action denied values [0-1] */
	time_t date;          /* File access date */
	time_t time;          /* File access time */
	char file[MAX_FILENAME_LEN]; /* Filename (string) */
	char fingerprint[65]; /* File fingerprint (SHA-256 as hex string) */
};

void usage(void) {
	printf(
	       "\n"
	       "usage:\n"
	       "\t./acmonitor\n"
	       "Options:\n"
	       "-m, Prints malicious users\n"
	       "-i <filename>, Prints table of users that modified "
	       "the file <filename> and the number of modifications\n"
	       "-h, Help message\n\n"
	       );
	exit(1);
}

/* Parses a line from log and fills a log_entry struct */
int parse_log_entry(char *line, struct log_entry *entry) {
	struct tm tm_info;
	char date_str[20], time_str[20];
	int parsed_fields = sscanf(line, 
	                           "UID: %d\tFilename: %s\tDate: %s\tTimestamp: %s\tAccessType: %d\tIs_Action_Denied Flag: %d\tFile Fingerprint: %s",
	                           &entry->uid,
	                           entry->file,
	                           date_str,
	                           time_str,
	                           &entry->access_type,
	                           &entry->action_denied,
	                           entry->fingerprint);
	
	if (parsed_fields != 7) {
		printf("[DEBUG] Failed to parse line: %s\n", line);
		return -1;
	}

	/* Parse date and time */
	strptime(date_str, "%Y-%m-%d", &tm_info);
	entry->date = mktime(&tm_info);
	strptime(time_str, "%H:%M:%S", &tm_info);
	entry->time = mktime(&tm_info);
	
	//printf("[DEBUG] Parsed entry - UID: %d, Filename: %s, AccessType: %d, Denied: %d\n",
           //entry->uid, entry->file, entry->access_type, entry->action_denied);
	//printf("[DEBUG] Parsed entry - UID: %d, Filename: %s, File Fingerprint: %s\n",
           //entry->uid, entry->file, entry->fingerprint);

	return 0;
}

/* Lists users who attempted unauthorized access more than five times */
void list_unauthorized_accesses(FILE *log) {
	struct log_entry entries[MAX_LOG_ENTRIES];
	int entry_count = 0, uid_count[MAX_LOG_ENTRIES] = {0};
	int malicious_user_found[MAX_LOG_ENTRIES] = {0};
	
	char line[1024];
	while (fgets(line, sizeof(line), log) && entry_count < MAX_LOG_ENTRIES) {
		if (parse_log_entry(line, &entries[entry_count]) == 0) {
			entry_count++;
		}
	}

	/* Count denied accesses per user */
	for (int i = 0; i < entry_count; i++) {
		int uid;
		if (entries[i].action_denied) {
			uid = entries[i].uid;
			uid_count[uid] = uid_count[uid] + 1;
		}
		
	}

	int uid;
	/*for (int i = 0; i < entry_count; i++) {
		uid = entries[i].uid;
		printf("[DEBUG] Checking UID: %d with denied count: %d\n", entries[i].uid, uid_count[uid]);
	}*/


	printf("Malicious users (more than 5 denied accesses):\n");

	int prev_user = -1;

	for (int i = 0; i < entry_count; i++) {
		uid = entries[i].uid;
		if (uid_count[uid] > 5 && uid != prev_user) {
			prev_user = uid;
			printf("User ID: %d, Denied Attempts: %d\n", uid, uid_count[uid]);
		}
	}

}

/* Lists users who accessed and modified a specified file */
void list_file_modifications(FILE *log, char *file_to_scan) {
	struct log_entry entries[MAX_LOG_ENTRIES];
	int entry_count = 0, mod_count[MAX_LOG_ENTRIES] = {0};
	char last_fingerprint[65] = "";
	int malicious_user_found[MAX_LOG_ENTRIES] = {0};
	int uid;

	//printf("[DEBUG] file to scan %s", file_to_scan);

	char line[1024];
	while (fgets(line, sizeof(line), log) && entry_count < MAX_LOG_ENTRIES) {
		if (parse_log_entry(line, &entries[entry_count]) == 0) {
			entry_count++;
		}
	}

	printf("File modifications for: %s\n", file_to_scan);
	for (int i = 0; i < entry_count; i++) {
		if (strcmp(entries[i].file, file_to_scan) == 0) {
			uid = entries[i].uid;
			/* Check if file was modified by comparing fingerprints */
			if (strcmp(entries[i].fingerprint, last_fingerprint) != 0 && strcmp(entries[i].fingerprint, "N/A") != 0 ) {
				mod_count[uid] = mod_count[uid] + 1;
				strcpy(last_fingerprint, entries[i].fingerprint);
			}
		}
	}

	int prev_user = -1;

	/* Print modification counts per user */
	for (int i = 0; i < entry_count; i++) {
		uid = entries[i].uid;
		if (mod_count[uid] > 0 && uid != prev_user) {
			prev_user = uid;
			printf("User ID: %d, Modifications: %d\n", uid, mod_count[uid]);
		}
	}
}

int main(int argc, char *argv[]) {
	int ch;
	FILE *log;

	if (argc < 2) usage();

	log = fopen("./file_logging.log", "r");
	if (log == NULL) {
		printf("Error opening log file \"%s\"\n", "./file_logging.log");
		return 1;
	}

	while ((ch = getopt(argc, argv, "hi:m")) != -1) {
		switch (ch) {		
		case 'i':
			list_file_modifications(log, optarg);
			break;
		case 'm':
			list_unauthorized_accesses(log);
			break;
		default:
			usage();
		}
	}

	fclose(log);
	return 0;
}
