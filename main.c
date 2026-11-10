#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include "rsa_common_header.h"
#include "phase2.h"
#include "interpreter.h"

FILE *logfp;

void INThandler(int sig)
{
     char c;
     signal(sig, SIG_IGN);
     printf("\nOUCH, did you hit Ctrl-C?\n"
            "Do you really want to quit without saving? [y/n] ");
     c = getchar();
     if (c == 'y' || c == 'Y'){
       if (logfp) fclose(logfp);
       exit(0);
     }
     else{
          printf("Je reprends...\nDIYPG> ");
          signal(SIGINT, INThandler);
     }
     int ch;
     while ((ch = getchar()) != '\n' && ch != EOF);
}



int main(void) {
  logfp = fopen("./logfp", "w");
  srand(time(NULL));

  signal(SIGINT, INThandler);
  
  start_interpreter();

  return 0;
}