#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#include <signal.h>
#include <sys/stat.h>


int main() 
{
	int i;
	size_t bytes;


	/*
		TEST 1

		Try to read files that dont exist.
		Then try to read by creating first and
		then writing on them
	
	*/
	FILE *file1;
	char filenames1[10][10] = {"file_MD_0", "file_MD_1", 
			"file_MD_2", "file_MD_3", "file_MD_4",
			"file_MD_5", "file_MD_6", "file_MD_7", 		
			"file_MD_8", "file_MD_9"};

	for (i = 0; i < 10; i++) {
		file1 = fopen(filenames1[i], "r"); //Expect failure

		file1 = fopen(filenames1[i], "w+"); //Expect success

		if (file1 != NULL){
			bytes = fwrite(filenames1[i], strlen(filenames1[i]), 1, file1);
			fclose(file1);
			//Modify contents again in such a way that a modification will be tracked
			file1 = fopen(filenames1[i], "w+");
			bytes = fwrite(filenames1[i], strlen(filenames1[i]), 1, file1);
		}

	}


	/*
		TEST 2

		Try to read files that dont exist.
		Then try to read by creating first and
		then writing on them. Change permissions to write only
		and try reading them, to cause a malicious access
	
	*/	
	FILE *file2;
	char filenames2[10][10] = {"file_WO_0", "file_WO_1", 
			"file_WO_2", "file_WO_3", "file_WO_4",
			"file_WO_5", "file_WO_6", "file_WO_7", 		
			"file_WO_8", "file_WO_9"};

	for (i = 0; i < 10; i++) {

		file2 = fopen(filenames2[i], "r"); //Expect failure

		file2 = fopen(filenames2[i], "w+"); //Expect success

		if (file2 == NULL){
			file2 = fopen(filenames2[i], "w");
		}

		if (file2 != NULL){
			bytes = fwrite(filenames2[i], strlen(filenames2[i]), 1, file2);	
			fclose(file2);
		}
		
		file2 = fopen(filenames2[i], "r");
		
		//Change permissions to write only 
		chmod(filenames2[i], S_IWUSR);			

		file2 = fopen(filenames2[i], "r");	//Expect failure
	}



	/*
		TEST 3

		Try to read files that dont exist.
		Then try to read by creating first and
		then writing on them. Change permissions to read only
		and try writing them, to cause a malicious access
	
	*/	
	FILE *file3;
	char filenames3[10][10] = {"file_RO_0", "file_RO_1", 
			"file_RO_2", "file_RO_3", "file_RO_4",
			"file_RO_5", "file_RO_6", "file_RO_7", 		
			"file_RO_8", "file_RO_9"};

	for (i = 0; i < 10; i++) {

		file3 = fopen(filenames3[i], "r"); //Expect failure

		file3 = fopen(filenames3[i], "w+"); //Expect success

		if (file3 == NULL){
			file3 = fopen(filenames3[i], "r");
		}

		if (file3 != NULL){
			bytes = fwrite(filenames3[i], strlen(filenames3[i]), 1, file3);	
		}
				
		//Change permissions to write only 
		chmod(filenames3[i], S_IRUSR);		

		file3 = fopen(filenames3[i], "r"); //Expect success

		if(file3!=NULL){
			bytes = fwrite(filenames3[i], strlen(filenames3[i]) , 1, file3); //Expect failure
		}

	}






}
