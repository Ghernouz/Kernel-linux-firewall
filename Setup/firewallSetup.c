#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

int main (int argc, char **argv) {
    
    char *letter; /* the name of the device */
    char *filename; 
// METTRE LE LOCK
    int result;
    size_t size;

    if (argc != 3 && argc!=2) {								
	fprintf (stderr, "1 or 2 argument required, exiting!\n");
	exit (1);
    }
        if (argc==2) {
    		letter = argv[1];
		fprintf (stderr, "L %s\n",letter);	
		if(strcmp(letter,"L")==0){
			fprintf (stderr, "L\n");
		//	fprintf (stderr, "L\n");	
		//	sprintf(commande,"sudo echo '%s' > /dev/firewallExtensions",cmd);
			char commande[4096]; 
			sprintf(commande,"sudo echo '%s' > /dev/firewallExtensions","L");
			printf("cmd :  %s\n", commande);
			system(commande);
	
		}
		else{
			fprintf (stderr, "L argument required or W <file>, exiting!\n");
			exit (1);
		}
	}
	else{
	    	letter = argv[1];
		if(strcmp(letter,"W")==0){
   			 filename = (char*)argv[2];
			//printf("%s\n",filename);
   			FILE *fp = fopen (filename, "r");
    		         if (fp == NULL) {
                  	 fprintf (stderr, "Could not open file %s, exiting!\n", filename);
			 exit (1);
			 }
   			char line[4096];
    			size_t len = 0;
    			ssize_t read;
			char * pch;
			int i = 0;
			int port;
  			while (fgets(line, 4096, fp) != NULL) {
        			printf("%s", line);
				pch = strtok (line," ");

				 while (pch != NULL)
				{

					if(i==0){
							
						port = strtol(pch, NULL, 10);
						if(!(0<=port && port<=65536)){

						  	 fprintf (stderr, "ERROR: Ill-formed file\n"); exit(1);
						} 

						}
					if(i == 1){

						pch[strlen(pch)-1]=0;
				       		if( access( pch, F_OK|X_OK ) != -1 ) {
							
						} else {
						  	 fprintf (stderr, "ERROR: Cannot execute file\n");
							 exit (1);
						}
					}

				pch = strtok (NULL, " ");
					i++;
				}
				i=0;	
    			}
    			fclose(fp);
			fp = fopen (filename, "r");
    		         if (fp == NULL) {
                  	 fprintf (stderr, "Could not open file %s, exiting!\n", filename);
			 exit (1);
			 }
			char cmd[4096]; 
			char commande[4096]; 
  			while (fgets(cmd, 4096, fp) != NULL) {
			cmd[strlen(cmd)-1]=0;
			sprintf(commande,"sudo echo '%s' > /dev/firewallExtensions",cmd);
			printf("cmd :  %s\n", commande);
			system(commande);
			}
    			fclose(fp);
    		



		}
		else{
			fprintf (stderr, "L argument required or W <file>, exiting!\n");
			exit (1);
		}
		
	}

    return 0;
}

    
    

	
