#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#define LOG "./file_logging.log"
#define MAX_RECORD_IDX 1023


struct entry {
	int uid; /* user id (positive integer) */
	int accessType; /* access type values [0-2] */
	int actionDenied; /* is action denied values [0-1] */

	char *file; /* filename (string) */
	char *fingerprint; /* file fingerprint */

    struct tm tm; /*timestamp of action*/
};

/*
	A struct for keeping track of modifications on file made by specific user
*/
struct record {
	int uid;
	int modification;
};

int getNumberOfLines(FILE *fp){
	int lines = 0;
	char c;
	for (c = getc(fp); c != EOF; c = getc(fp)) {
        if (c == '\n') {
            lines = lines + 1; 
        }
	}
  	rewind(fp);
	return lines;
}




char *readLine(FILE *fp) {
    char *line_buffer = NULL;
    size_t len = 0;
    ssize_t read;

    if (fp == NULL) {
        exit(EXIT_FAILURE);
    }
    getline(&line_buffer, &len, fp);
    return line_buffer;
}




int filenameChecked(char *filename, char filenames[][10], int lines){
	int i;
    for(i = 0; i < lines; i++){
        if(strcmp(filenames[i], filename) == 0){
            return 1;
        }
    }
    return 0;
}




int userChecked(int user_id, int *malicious_users, int lines){
    int i;
    for(i = 0; i < lines; i++){
        if(malicious_users[i] == user_id){
            return 1;
        }
    }
    return 0;
}




int parseFile(FILE *fp, struct entry **entries, int linesCount){

	char *buffer;
	char *temp;

	for(int i=0; i<linesCount; i++){
		
		buffer = readLine(fp);

		//User id 
		(*entries)[i].uid = atoi(strsep(&buffer, "\t"));

		//Path
		(*entries)[i].file = strsep(&buffer, "\t");

		//Date
		temp = strsep(&buffer, "\t");
		(*entries)[i].tm.tm_mday = atoi(strsep(&temp,"/"));
		(*entries)[i].tm.tm_mon = atoi(strsep(&temp,"/"));
		(*entries)[i].tm.tm_year= atoi(strsep(&temp,"/"));

		//Time
		temp = strsep(&buffer, "\t");
		(*entries)[i].tm.tm_hour = atoi(strsep(&temp,":"));
		(*entries)[i].tm.tm_min = atoi(strsep(&temp,":"));
		(*entries)[i].tm.tm_sec = atoi(strsep(&temp,":"));

		//Access Type
		(*entries)[i].accessType = atoi(strsep(&buffer, "\t"));

		//Action Denied
		(*entries)[i].actionDenied = atoi(strsep(&buffer, "\t"));

		//Fingerprint
		(*entries)[i].fingerprint = strsep(&buffer, "\t");	
	}
}




void usage(void)
{
	printf(
	       "\n"
	       "usage:\n"
	       "\t./monitor \n"
		   "Options:\n"
		   "-m, Prints malicious users\n"
		   "-i <filename>, Prints table of users that modified "
		   "the file <filename> and the number of modifications\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}





void list_unauthorized_accesses(FILE *log)
{
	int entriesLength = getNumberOfLines(log);

	//Parse the file and fill in the entries list
	struct entry *entries = malloc(sizeof(struct entry)* entriesLength);
	parseFile(log, &entries, entriesLength);

	//Create struct to keep track of the modifications, 1024 records should be enough
	struct record *records = malloc(sizeof(struct record)* 1024);

	//Counters & variables
	int record_idx = 0;


	printf("-------------- Malicious Access Statistics --------------\n");

	for(int i=0; i<entriesLength; i++){		
		if(entries[i].actionDenied == 1){
			//Append record in the list of records of malicious accesses
			records[record_idx].uid = entries[i].uid;
			records[record_idx].modification = 1;

			//Prevent overflow, from that point and on no more records will be held
			if(record_idx + 1 <= MAX_RECORD_IDX){
				record_idx++;
			}
		}
	}

	int *usersParsed = malloc(1024 * sizeof(int));	//Array to store uid of users that are already printed
	memset(usersParsed, 0x00, 1024);
	int modifications = 0;
	int curr_uid = 0;

	for(int j=0; j<=MAX_RECORD_IDX; j++){
		curr_uid = records[j].uid;
		if(userChecked(curr_uid, usersParsed, 1024)==1){
			continue;
		}
		for (int i=0; i<=MAX_RECORD_IDX; i++){
			if(records[i].uid == curr_uid){
				modifications+=records[i].modification;
			}
		}
		if(modifications>=7){
		    printf("User with UID *%d* made [%d] malicious accesess\n", records[j].uid , modifications);
		}
		usersParsed[j] = records[j].uid; // Mark user uid as parsed;
		modifications = 0;
	}

	printf("---------------------------------------------------------\n");
	return;
}




void list_file_modifications(FILE *log, char *file_to_scan)
{
	int entriesLength = getNumberOfLines(log);

	//Parse the file and fill in the entries list
	struct entry *entries = malloc(sizeof(struct entry)* entriesLength);
	parseFile(log, &entries, entriesLength);

	//Create struct to keep track of the modifications, 1024 records should be enough
	struct record *records = malloc(sizeof(struct record)* 1024);

	//Counters & variables
	int record_idx = 0;

	//Keep track of the fingerprints to recognize modifications
	char currFingerprint[33];
	memset(&currFingerprint, 0x00, 33);
	char prevFingerprint[33];
	memset(&prevFingerprint, 0x00, 33);
	
	printf("-------------- Modifications on file: %s --------------\n", file_to_scan);


	for(int i=0; i<entriesLength; i++){		
		if((!strcmp(entries[i].file, realpath(file_to_scan, NULL)) || !strcmp(entries[i].file, file_to_scan))){
			strcpy(currFingerprint, entries[i].fingerprint);

			if(strcmp(currFingerprint,prevFingerprint)!=0 && (entries[i].accessType == 2 || entries[i].accessType == 3)){
				//Append record in the list of records
				records[record_idx].uid = entries[i].uid;
				records[record_idx].modification = 1;

				//Prevent overflow, from that point and on no more records will be held
				if(record_idx + 1 <= MAX_RECORD_IDX){
					record_idx++;
				}

				//The last known fingerprint is the current one for future modifications to be detected
				strcpy(prevFingerprint, currFingerprint);
			}
		}
	}

	int *usersParsed = malloc(1024 * sizeof(int));	//Array to store uid of users that are already printed
	memset(usersParsed, 0x00, 1024);
	int modifications = 0;
	int curr_uid = 0;

	for(int j=0; j<=MAX_RECORD_IDX; j++){
		curr_uid = records[j].uid;
		if(userChecked(curr_uid, usersParsed, 1024)==1){
			continue;
		}
		for (int i=0; i<=MAX_RECORD_IDX; i++){
			if(records[i].uid == curr_uid){
				modifications+=records[i].modification;
			}
		}
		printf("User with UID *%d* made %d modifications on this file\n", records[j].uid , modifications);
		usersParsed[j] = records[j].uid; // Mark user uid as parsed;
		modifications = 0;
	}

	for (int i=0; i<entriesLength; i++){
		if(strcmp(realpath(file_to_scan,NULL), entries[i].file)==0){
			printf("--------------------------------------------------------------\n");
			return;
		}
	}

	printf("--> No such file!\n");
	printf("--------------------------------------------------------------\n");



	return;
}

int main(int argc, char *argv[])
{

	int ch;
	FILE *log;

	if (argc < 2)
		usage();

	log = fopen(LOG, "r");
	if (log == NULL) {
		printf("Error opening log file at: \"%s\"\n", LOG);
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
	argc -= optind;
	argv += optind;	
	
	return 0;
}
