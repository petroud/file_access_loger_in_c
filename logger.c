#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/md5.h>

#define LOG "./file_logging.log"

/*
	Function that recovers the path of a file given a file pointer to the file
	src: https://stackoverflow.com/questions/11221186/how-do-i-find-a-filename-given-a-file-pointer
*/
char* recoverPath(FILE * f) {
	int fd;
	char fd_path[255];
	char * filename = malloc(255);
	ssize_t n;

	fd = fileno(f);
	sprintf(fd_path, "/proc/self/fd/%d", fd);
	n = readlink(fd_path, filename, 255);
	if (n < 0)
		return NULL;
	filename[n] = '\0';
	return filename;
}


/*
	Function that return an MD5 hash for the contents of a file specified by @path 
*/
unsigned char* hasher(const char* path){

	unsigned char *digest = (unsigned char*) malloc(MD5_DIGEST_LENGTH);

	MD5_CTX ctx;
	int bytes;
	int length;

	FILE *fd;
	FILE *(*original_fopen)(const char*, const char*);
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	fd = (*original_fopen)(path, "rb");

	if (!fd) {
		unsigned char *hash = (unsigned char*) malloc(1024);
		return hash;
	}

	//Calculate the length of the file to be hashed
	fseek(fd, 0, SEEK_END);
	length = ftell(fd);
	fseek(fd, 0, SEEK_SET);

	unsigned char buffer[length];


	MD5_Init(&ctx);

	//Read from the file till the EOF and append data to MD5 context
	while((bytes = fread(buffer, 1, length, fd))!=0 ) {
		MD5_Update(&ctx, buffer, bytes);		
	}

	MD5_Final(digest, &ctx);

	return digest;
}


/*
	This function appends the action appropriately in the logfile 
*/
void logAction(const char* path, int accessType, int actionDenied){

	//Get the acting user id
	uid_t uid = getuid();
   
	//Generate the current timestamp
	time_t t = time(NULL);
  	struct tm tm;
  	tm = *localtime(&t);

	//Get the full system path of the file under action
	char* fullPath = realpath(path, NULL);
 
	unsigned char* hash = hasher(path);

	//Open the log file with the original fopen method
	FILE *log;
	FILE *(*original_fopen)(const char*, const char*);
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	log = (*original_fopen)(LOG, "a");

	//Log everything the log file except the fingerprint which requires a recursive print
	//If the absolute path cannot be resolved, then the case is creation with no permission so we only store the name of the file
	if (fullPath == NULL){
  		fprintf(log, "%d\t%s\t%02d/%02d/%d\t%02d:%02d:%02d\t%d\t%d\t", uid, path, tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec, accessType, actionDenied);
	}else{
  		fprintf(log, "%d\t%s\t%02d/%02d/%d\t%02d:%02d:%02d\t%d\t%d\t", uid, fullPath, tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec, accessType, actionDenied);
	}
	

	//Append the MD5 hash of the contents
	for (int i=0; i < MD5_DIGEST_LENGTH; i++){
		fprintf(log, "%02x", hash[i]);
	}

	fprintf(log,"\n");
	fclose(log);

}

FILE * fopen(const char *path, const char *mode) {

	int accessType, actionDenied = 0;

	FILE *original_fopen_pointer;
	FILE *(*original_fopen)(const char*, const char*);

	//Check whether the action is an opening or a creation of the file
	if(access(path, F_OK) != 0){
		accessType = 0 ;
		
		if(strcmp(mode, "r")==0 || strcmp(mode, "r+")==0 || strcmp(mode, "rb")==0 || strcmp(mode, "rb+")==0){
			actionDenied = 1;
		}

	}else{

		accessType = 1;	

		if(strcmp(mode, "r")==0 || strcmp(mode,"rb")==0){
			actionDenied = (access(path, R_OK)==0) ? 0 : 1;
		}
		else if(strcmp(mode, "r+")==0 || strcmp(mode,"rb+")==0){
			actionDenied = ((access(path, R_OK))==0 && (access(path, W_OK))==0) ? 0 : 1;
		}
		else if(strcmp(mode, "a")==0 || strcmp(mode,"a+")==0){
			actionDenied = ((access(path, R_OK))==0 && (access(path, W_OK))==0) ? 0 : 1;
		}
		else if(strcmp(mode, "w")==0 || strcmp(mode,"wb")==0){
			//Overwrites contents (deletion technically but not literally)
			accessType = 3;
			actionDenied = (access(path, W_OK)==0) ? 0 : 1;
		}
		else if(strcmp(mode, "w+")==0 || strcmp(mode,"wb+")==0){
			//Overwrites contents (deletion technically but not literally)
			accessType = 3;
			actionDenied = ((access(path, R_OK))==0 && (access(path, W_OK))==0) ? 0 : 1;
		}

	}

	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_pointer = (*original_fopen)(path, mode);	
	logAction(path, accessType, actionDenied);

	return original_fopen_pointer;
}


size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) 
{
	int accessType, actionDenied = 0;

	size_t original_fwrite_pointer;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_pointer = (*original_fwrite)(ptr, size, nmemb, stream);
	
	fflush(stream);
	char* path = recoverPath(stream);

	accessType = 2;

	
	if(access(path, W_OK) == 0){
		actionDenied = 0;
	}
	else{
		actionDenied = 1;
	}

	logAction(path, accessType, actionDenied);

	free(path);

	return original_fwrite_pointer;
}


