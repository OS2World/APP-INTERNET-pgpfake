/*

    PGPFAKE: translate PGP 2.6.3 command line to PGP 5.0
    Copyright (C) 1998    Thomas Vandahl
    Copyright (C) 1999    Nick Burch
    Copyright (C) 2001    Dieter Werner

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define VERSION "0.05"
#define SIGFILE "signok.txt"
#define LOGFILE "pgpfake.log"
#define dprintf if (debug) fprintf


/* Note. Encript to Self uses the UserID supplied by PMMail */
/* If not called by PMMail, no Encript to Self is performed */
/* To always encript to a particular ID, edit pgp.cfg */
/* Encript_self = 1 only useful if you have multiple accounts, */
/* each with their own pgp key */

int  debug=0,encript_self=0;
char cmdline[256], sigfile[256], logfile[256], line[256];


int convert_signature(char *sigfile)
{
  char dummy[80], answer[6], date[12], name[80];
  FILE *sig;
  int  cnt_parsed;
  int rc=0;

  /* read result of signature check */
  sig = fopen(sigfile, "r");
  while (!feof(sig))
  {
    fgets(line, 256, sig);
    /* handle good and bad signatures */
    if (strstr(line,"signature") != NULL)
    {
      sscanf(line, "%s", answer);
      cnt_parsed = sscanf(line, "%[^0-9]%s", dummy, date);
      if (cnt_parsed != 2)
        strcpy(date, "unknown");

      fgets(line, 256, sig);   /* read dummy line */
      fgets(line, 256, sig);   /* read name */
      cnt_parsed = sscanf(line, " \"%[^\"]", name);
      if (cnt_parsed != 1)
        strcpy(name, "unknown");

      if (stricmp(answer,"GOOD") == 0)
        fprintf(stderr, "Good signature from user \"%s\".\nSignature made %s\n", name, date);
      else
        fprintf(stderr, "Bad signature from user \"%s\".\nSignature made %s\n", name, date);
      break;
    }

    /* handle unknown signatures */
    if (strstr(line,"unknown keyid") != NULL)
    {
      fprintf(stderr, "not found\n");
      break;
    }

    /* handle decryption pass phrase error, mod004a */
    if (strstr(line,"Cannot decrypt message.") != NULL)
    {
      fprintf(stderr,"\007Error:  Bad pass phrase.\n");
      rc=31;
      break;
    }

  }
  fclose(sig);
  if (!debug) remove(sigfile);
  return (rc);
}


int feed_pgp(FILE *log, char *pgpcmdline)
{
  FILE *pgpcmd;
  int  i, rc;

  pgpcmd = popen(pgpcmdline, "wb");
  if (pgpcmd == NULL)
  {
    dprintf(log, "\npopen failed with %d!\n", errno);
    return(-1);
  }

  i=0;
  while (!feof(stdin))
  {
    fgets(line, 256, stdin);
    if (feof(stdin)) continue;
       // dprintf(log,"Line %d: %s\n", i, line); 
    fputs(line, pgpcmd);
    i++;
  }
  dprintf(log,"\n%d lines processed\n",i-1);
  return(pclose(pgpcmd));
}


int pgp_check_signature(FILE *log, char *pgppath, char *sigfile)
{
  int rc;

  sprintf(cmdline, "%s\\pgp5.exe v --batchmode -fq 2>%s", pgppath, sigfile);

  rc = feed_pgp(log, cmdline);
  if (rc < 0) return(rc);

  convert_signature(sigfile);
  return(rc);
}


int pgp_encrypt(FILE *log, char *pgppath, char *to, char *from)
{
  if(encript_self)
  {
     sprintf(cmdline, "%s\\pgp5.exe e --batchmode -faqr %s -faqr %s", pgppath, to, from);
  }
  else
  {
     sprintf(cmdline, "%s\\pgp5.exe e --batchmode -faqr %s", pgppath, to);
  }

  return(feed_pgp(log, cmdline));
}


int pgp_sign(FILE *log, char *pgppath, char *passphrase, char *userid)
{
  /* Added -t switch for clear text signature as proposed by Dieter Werner <e8726172@student.tuwien.ac.at> */
  int rc;	/* mod004a begin */
  sprintf(cmdline, "%s\\pgp5.exe s --batchmode -ftaq -z\"%s\" -u %s", pgppath, passphrase, userid);

  /* check if there was _some_ error from pgp:
	pgp 2.6.3i returns 20 (?) on wrong pass phrase
	pgp5.0 returns 255 (?) on wrong pass phrase
      this output on stderr makes PMMail display "Wrong Passphrase"
      and lets user re-enter pass phrase */
  rc=feed_pgp(log, cmdline); 
  if (rc!=0)
  {
     rc=20; /* PMMail does not check RC, but maybe some other program */
     fprintf(stderr,"\n");
     fprintf(stderr,"\007Error:  Bad pass phrase.\n");
     fprintf(stderr,"\007Signature error\n");
     fprintf(stderr,"\n");
  }
  return(rc);
}


/* Added by Dieter Werner <e8726172@student.tuwien.ac.at> */
int pgp_signencr(FILE *log, char *pgppath, char *passphrase, char *to, char *userid)
{
  /* Added --batchmode switch to avoid blocking of PGP (tv) */
  int rc; 
  if(encript_self)
  {
     sprintf(cmdline, "%s\\pgp5.exe e --batchmode -safq -z\"%s\" -r %s -r %s -u %s", pgppath, passphrase, to, userid, userid);
  }
  else
  {
     sprintf(cmdline, "%s\\pgp5.exe e --batchmode -safq -z\"%s\" -r %s -u %s", pgppath, passphrase, to, userid);
  }
  
  /* check if there was _some_ error from pgp:
	pgp 2.6.3i returns 20 (?) on wrong pass phrase
	pgp5.0 returns 255 (?) on wrong pass phrase
      this output on stderr makes PMMail display "Wrong Passphrase"
      and lets user re-enter pass phrase */
  rc=feed_pgp(log, cmdline);
  if (rc!=0)
  {
     rc=20; /* PMMail does not check RC, but maybe some other program */
     fprintf(stderr,"\n");
     fprintf(stderr,"\007Error:  Bad pass phrase.\n");
     fprintf(stderr,"\007Signature error\n");
     fprintf(stderr,"\n");
  }
  return(rc);	/* mod004a end */
}


int pgp_decrypt(FILE *log, char *pgppath, char *sigfile, char *passphrase)
{
  int rc;

  sprintf(cmdline, "%s\\pgp5.exe v --batchmode -fq -z\"%s\" 2>%s", pgppath, passphrase, sigfile);

  rc = feed_pgp(log, cmdline);
  if (rc < 0) return(rc);

  convert_signature(sigfile);
  return(rc);
}


int pgp_extract_my_key(char *pgppath, char *userid)
{
  int rc;

  sprintf(cmdline, "%s\\pgpk.exe --batchmode -xa %s", pgppath, userid);
  rc = system(cmdline);

  return(0);
}


/* Added by Nick Burch <Nick@Horton-Vineyard.com> */
int pgp_call_no_args(char *pgppath)
{
  int rc;
  
  /* Simply calls PGP, and gets it to display some help */

  sprintf(cmdline, "%s\\pgp5.exe", pgppath);
  rc = system(cmdline);

  return(0);
}


int pgp_add_new_key(FILE *log, char *pgppath, char *sigfile)
{
  FILE *pgpkey;
  int  i, rc;

  pgpkey = fopen(sigfile, "wb");
  if (pgpkey == NULL)
  {
    dprintf(log, "\nfopen failed with %d!\n", errno);
    return(-1);
  }

  i=0;
  while (!feof(stdin))
  {
    fgets(line, 256, stdin);
    if (feof(stdin)) continue;
/*    dprintf(log,"Line %d: %s\n", i, line); */
    fputs(line, pgpkey);
    i++;
  }
  dprintf(log,"\n%d lines processed\n",i-1);
  fclose(pgpkey);

  sprintf(cmdline, "%s\\pgpk.exe -a %s --batchmode", pgppath, sigfile);
  rc = system(cmdline);
  remove(sigfile);

  return(rc);
}


/* Added by Nick Burch <Nick@Horton-Vineyard.com> */
char *get_cmd_line(FILE *log, char *args[], int start, int end)
{
   /* Converts the supplied command line to a string */
   
   int i,rc,len_args,relpos;
   char *cmd_line, *blank;
   blank = " ";
   
      // Cycle through args[], summing the length (add 1 for the trailing space)
   for(i = start;i<end;i++)
      len_args = strlen(args[i]) + 1;
      
   // Pointer to enough memory to store the whole string
   cmd_line = malloc( len_args );
   relpos = 0;
   
   for(i = start;i<end;i++)
   {
      // Copy current args[] to the next bit of the string
      memmove(cmd_line + relpos,args[i],strlen(args[i]));
      relpos = relpos + strlen(args[i]);
      
      if(i != end - 1 )
      {
        // If not the last args[], add a space
        memmove(cmd_line + relpos,blank,1);
        ++relpos;
      }  
   }
   // Add null to end
   memmove(cmd_line + relpos,"\0",1);
   
   dprintf( log, "\nCommand Line is:%s\n",cmd_line);
   
   return (cmd_line);
}


/* Added by Nick Burch <Nick@Horton-Vineyard.com> */
int call_pgp(FILE *log, char *pgppath, char *args[], int start, int end )
{
   /* Calls PGP5.EXE */
   
   int rc;
   char *opts;
   
   // Get Command Line from args[]
   opts = get_cmd_line( log,args,start,end );
   
   sprintf(cmdline, "%s\\pgp5.exe %s", pgppath, opts);
   rc = system(cmdline);
   
   dprintf( log, "Called PGP5.EXE, with RC=%d",rc);
   
   return(rc);    
}


/* Added by Nick Burch <Nick@Horton-Vineyard.com> */
int call_pgpk(FILE *log, char *pgppath, char *args[], int start, int end )
{
   /* Calls PGPK.EXE */
   
   int rc;
   char *opts;
   
   // Get command line from args[]
   opts = get_cmd_line( log,args,start,end );
   
   sprintf(cmdline, "%s\\pgpk.exe %s", pgppath, opts);
   rc = system(cmdline);
   
   dprintf( log, "Called PGPK.EXE, with RC=%d",rc);
   
   return(rc);    
}


/* Added by Nick Burch <Nick@Horton-Vineyard.com> */
int pgp_check_command_line(FILE *log, int num_args, char *args[], char *pgppath )
{
  /* If the command line isn't from PMMail, */
  /* Then this anylises it very simply, */
  /* And calls PGP as needed */
  
  int rc,i,len_args;
  char *temp;
  
  rc = 0;

  /* Call simply made to PGP assuming PGP.EXE is PGP5.EXE */
  if(strcmp(strlwr(args[1]),"e") == 0)
  {
       /* PGP 5 Encript */
          rc = call_pgp( log, pgppath, args, 1, num_args );
  }
  if(strcmp(strlwr(args[1]),"v") == 0)
  {
       /* PGP 5 Verify/Decript */
          rc = call_pgp( log, pgppath, args, 1, num_args );
  }
  if(strcmp(strlwr(args[1]),"s") == 0)
  {
       /* PGP 5 Sign */
          rc = call_pgp( log, pgppath, args, 1, num_args );
  }
  
  /* Legacy 2.6 Decript support - assume cypertext ends in .pgp or .asc */
  if(strstr(strlwr(args[1]),".asc") == args[1] + strlen(args[1]) - 4)
  {
     temp = malloc(strlen(args[1]) + 2);
     memmove( temp, "v ",2);
     memmove( temp + 2, args[1], strlen(args[1]) );
     args[1] = temp;
     rc = call_pgp( log, pgppath, args, 1, num_args );
  }   
  if(strstr(strlwr(args[1]),".pgp") == args[1] + strlen(args[1]) - 4)
  {
     temp = malloc(strlen(args[1]) + 2);
     memmove( temp, "v ",2);
     memmove( temp + 2, args[1],strlen(args[1]) );
     args[1] = temp;
     rc = call_pgp( log, pgppath, args, 1, num_args );
  }   

  /* Check the first character */
  /* If the pointer the the first occurance of a character */
  /* Is the pointer of the start of the string, then that */
  /* Character is first found at the start of the string */
  if(strstr(args[1],"-") == args[1])
  {
       /* Legacy PGP 2.6 structure */
       fprintf(stderr,"\nLegacy 2.6.x Command Line Detected\n");
       
       /* Keys (-k) */
       if( strstr( args[1], "-k" ) == args[1] )
       {
          /* All we want to do is remove the 'k' and pass to PGPK */
          /* Making any changes as needed - for kv & kvv */
          len_args = strlen(args[1]);
          
          if( strcmp(args[1]+2,"v") == 0 ) 
          {
             memmove(args[1]+2,"l",1);
          }   
          if( strcmp(args[1] + 2,"vv") == 0 ) 
          {            
             memmove(args[1]+2,"ll",2);
          }  
          
          // Shift everything 1 byte to the left, to replace "k"
          memmove( args[1]+1,args[1]+2,len_args - 2);
          // Null terminate string 1 character earlier than before
          memmove( args[1] + len_args - 1, "\0",1);
          
          rc = call_pgpk( log, pgppath, args, 1, num_args );
       }   
       
       /* Encript  (-e) */
       if( strstr( args[1], "-e" ) == args[1] )
       {
          /* We just need to replace -e for e */
           /* unless -es, in which case e -s */
           if( strstr( args[1], "-es") == args[1])
              args[1] = "e -s";
           else   
              args[1] = args[1] + 1;
              
          rc = call_pgp( log, pgppath, args, 1, num_args );
       }
       
       /* Simple Encript  (-c) (No Key, only a message Passphrase) */
       if( strstr( args[1], "-c" ) == args[1] )
       {
          /* We just need to replace -c for e -c */
          args[1] = "e -c";
          
          rc = call_pgp( log, pgppath, args, 1, num_args );
       }
       
       /* Sign  (-s) */
       if( strstr( args[1], "-s" ) == args[1])
       {
          /* instead of file -u USERID needs to be -u USERID file */
            // Change -s to s
          temp = args[1] + 1;
          if( num_args > 3 )
          {
            // Supplied -u
              // Save file name
             args[1] = args[2];
              // Move -u
             args[2] = args[3];
              // Move username
             args[3] = args[4];
              // Put file name back
             args[4] = args[1];
              // Put back in PGP command line
             args[1] = temp;
           }
           else
           {
              // Nothing else to change
              args[1] = temp;
           }   
          
          rc = call_pgp( log, pgppath, args, 1, num_args );
       }
  }
  
  return(rc);
}


int main(int argc, char *argv[])
{
  int i, j, k, rc;
  FILE *log;
  char *pgppath, *tmppath, *temp;

  rc = 0;

  tmppath = getenv("TMP");
  if (tmppath == NULL)
  {
    tmppath=".";
  }
  sprintf(sigfile,"%s\\%s",tmppath,SIGFILE);
  sprintf(logfile,"%s\\%s",tmppath,LOGFILE);

  debug = (getenv("PGPFAKE_DEBUG") != NULL);
  encript_self = (getenv("PGPFAKE_ENCRIPT_TO_SELF") != NULL);

  /* switch on debug mode manually */
  /* debug = 1; */
  
  /* switch on self encript manually */
  /* encript_self = 1; */

  if (debug)
  {
    debug = 1;
    log = fopen(logfile,"w");
    for (i=1; i<argc; i++)
      fprintf(log, "%d: %s\n",i,argv[i]);
    fprintf(log, "Num of Args: %d\n",argc);  
  }

  pgppath = getenv("PGPPATH");
  if (pgppath == NULL)
  {
    dprintf(log, "\nPGP not installed correctly!\n");
    if (debug) fclose(log);
    return(-1);
  }
  
         // As you can see, PGPFake decides what it's being called to do
         // Based on the number of arguments. This is due to it originally
         // Only being a shell for PMMail. This can lead to a few odd 
         // Problems (see Bugs section of readme), but I can't see the
         // Point of re-doing it, so if you can be bothered, go ahead!
         // I'd recomend doing it in a similar way to the new bit above
         // (The bit I wrote)
         //                             Nick Burch <Nick@Horton-Vineyard.com>
  
  switch (argc)
  {
    case 1:  /* no arguments, print version then PGP Help*/
             fprintf(stderr,"\nPGPfake, Version %s, (C) 1998 by Thomas Vandahl, 1999 by Nick Burch,\n",VERSION);
             fprintf(stderr,"2001 by Dieter Werner\n");
             
             rc = pgp_call_no_args( pgppath );

             break;

    case 9:  /* called to verify signature */
             dprintf(log, "check signature\n");
             rc = pgp_check_signature(log, pgppath, sigfile);
             break;

    case 11: /* called to extract public key */
             /*
                argv[10]: my userid
             */
             
             /* Check We're not being asked to Fingerprint */
             if( strcmp(argv[9],"-fkvcat") == 0)
             { 
                // Fingerprint not supported: Needs a passphrase with pgp 5.0
                // Do nothing except log the problem
                dprintf(log, "Fingerprint key: not supported\n");
             }
             else
             {
                // Extract, which we can do
                dprintf(log, "extract key\n");
                rc = pgp_extract_my_key(pgppath, argv[10]);
             }   
             break;

    case 12: /* called to decrypt or to add key information */
             /*
                decrypt: argv[9] -> passphrase
                addkey:  argv[9] = "-a"
             */
             if (argv[9][1] == 'a') /* called to add public key */
             {
               dprintf(log, "addkey\n");
               rc = pgp_add_new_key(log, pgppath, sigfile);
             }
             else                   /* called to decrypt */
             {
               dprintf(log, "decrypt\n");
               rc = pgp_decrypt(log, pgppath, sigfile, argv[9]+2);
             }
             break;

    case 13: /* called to encrypt */
             /*
                argv[11]: userid to encrypt to
                argv[12]: my userid
             */
             dprintf(log, "encrypt\n");
             rc = pgp_encrypt(log, pgppath, argv[11], argv[12]);
             break;

    case 14: /* called to sign */
             /*
                argv[11]: passphrase
                argv[13]: my userid
             */
             dprintf(log, "sign\n");
             rc = pgp_sign(log, pgppath, argv[11]+2, argv[13]);
             break;

    /* Added by Dieter Werner <e8726172@student.tuwien.ac.at> */
    case 16: /* called to sign & encrypt */
             /*
                argv[11]: passphrase
                argv[12]: userid to encrypt to
                argv[13]: my userid
             */
             dprintf(log, "encrypt and sign\n");
             rc = pgp_signencr(log, pgppath, argv[11]+2, argv[12]+2, argv[13]);
             break;

    /* Based on case 16, coded by Nick Burch <Nick@Horton-Vineyard.com> */
    case 17: /* called to sign & encrypt to 2 people */
             /*
                argv[11]: passphrase
                argv[12]: userid to encrypt to
                argv[13]: other userid to encript to
                argv[14]: my userid
             */
             
             i = strlen(argv[12]);
             j = strlen(argv[13]);
             
             temp = malloc( i + j + 4 );
             memmove( temp, argv[12], i);
             memmove(temp + i , " -r ",4);
             memmove( temp + i + 4, argv[13], j);
             
             dprintf(log, "encrypt and sign, 2 recipients\n");
             rc = pgp_signencr(log, pgppath, argv[11]+2, temp, argv[14]);
             break;

    /* Based on case 16, coded by Nick Burch <Nick@Horton-Vineyard.com> */
    case 18: /* called to sign & encrypt to 3 people */
             /*
                argv[11]: passphrase
                argv[12]: userid to encrypt to
                argv[13]: other userid to encript to
                argv[14]: final userid to encript to
                argv[15]: my userid
             */
             
             i = strlen(argv[12]);
             j = strlen(argv[13]);
             k = strlen(argv[14]);
             
             temp = malloc( i + j + k + 8 );
             memmove( temp, argv[12] ,i);
             memmove( temp + i, " -r ", 4 );
             memmove( temp + i + 4, argv[13], j);
             memmove( temp + i + j + 4, " -r ",4 );
             memmove( temp + i + j + 8, argv[14],k);
             
             dprintf(log, "encrypt and sign, 3 recipients\n");
             rc = pgp_signencr(log, pgppath, argv[11]+2, temp, argv[15]);
             break;

    default: /* unknown call */
       /* Anylise command line, and call as needed */
       rc = pgp_check_command_line( log, argc, argv, pgppath );
  }
  
  dprintf(log,"\nreturn code: %d\n",rc);
  if (debug) fclose(log);
  return(rc);
}