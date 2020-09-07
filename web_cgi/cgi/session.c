#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>   
#include <dirent.h>

#define REMOTE_ADDR getenv("REMOTE_ADDR") 
#define HTTP_COOKIE getenv("HTTP_COOKIE") 
char *sess_user_name; 
char *sess_user_pwd; 
static void print_session_error(int); 
static void clean_session_file(); 
int set_session(char *name,char *pwd) 
{ 
        char str_now[11]; 
        //char hash_key[17]; 
        char *session_id; 
        time_t now; 
        FILE *sf; 
        char sfp[32]; 
        int i,temp,r; 
        time(&now); 
        /** 
        *  clean time out session file 
        */ 
        clean_session_file(); 
         
        /** 
        * get str_now 
        */ 
        sprintf(str_now,"%10d",(unsigned)now); 
        srand(now); 
        session_id = (char*) malloc(17*sizeof(char)); 
        for(i=0;i<16; i++) 
        { 
                r = rand(); 
                session_id[i] = r%26 + 'A'; 
        }  
        session_id[16] = '\0'; 
        /** 
        * create session file 
        */ 
        strcpy(sfp,"/tmp"); 
        strcat(sfp,"/sess_"); 
        strcat(sfp,session_id); 
        sf = fopen(sfp,"w");  
        chmod(sfp,06777); 
        if( sf == NULL ) 
        { 
                printf("cant creat session file");  
                return -1;
        } 
        /** 
        * fputs session file 
        */ 
        fputs(str_now,sf); 
        fputs("\n",sf); 
        //fputs(hash_key,sf); 
        //fputs("\n",sf); 
        fputs(REMOTE_ADDR,sf); 
        fputs("\n",sf); 
        fputs(name,sf);    //sess_user_name 
        fputs("\n",sf); 
        fputs(pwd,sf);     // sess_user_pwd_ 
        fputs("\n",sf);     
        fclose(sf); 
        /** 
        *  set cookie 
        */  
        printf("Set-Cookie:sess=%s\n",session_id); 

        return 0; 
} 
int start_session() 
{ 
       char session_id[17]; 
       char *info;
       FILE *sf; 
       char sfp[32]; 
       time_t now; 
       char temp[64]; 
       char str_time[16]; 
       char str_client_ip[20];  
       sess_user_name = (char*)malloc(32*sizeof(char)); 
       sess_user_pwd  = (char*)malloc(32*sizeof(char)); 

      //session_id = cgi_val(entries,"session_id"); 
      info=getenv("HTTP_COOKIE");  
      if(info!=NULL)  
      {  
            sscanf(info,"sess=%s",session_id);  
      } else {
        return -1;
      }
    /** 
      * open session file 
      */ 
       strcpy(sfp,"/tmp");  
       strcat(sfp,"/sess_"); 
       strcat(sfp,session_id); 
       sf = fopen(sfp,"r+"); 
       if(  sf == NULL ) 
                /** can’t open session file,maybe session has time out **/  
       { 
           //print_session_error(1); 
           return -2;
       } 
    /** 
      * read session var 
      */ 
      fgets(str_time, sizeof(str_time), sf);
      fgets(str_client_ip, sizeof(str_client_ip), sf);
      fgets(sess_user_name, 32, sf);
      fgets(sess_user_pwd, 32, sf);
      str_time[strlen(str_time) - 1] = '\0';
      str_client_ip[strlen(str_client_ip) - 1] = '\0';
      sess_user_name[strlen(sess_user_name) - 1] = '\0';
      sess_user_pwd[strlen(sess_user_pwd) - 1] = '\0';
    /** 
      * check active time 
      */  
      time(&now); 
      if( now - atoi(str_time) > 1800 ) 
      { 
         //print_session_error(2);  
         return -3;
      }  
 
      if( strcmp( REMOTE_ADDR, str_client_ip ) != 0 ) 
      { 
        // print_session_error(4); 
         return -4;
      } 
    /**   
      * refresh session active time 
      */  
      time(&now); 
      sprintf(str_time,"%10d\n",(unsigned)now); 
      fseek(sf,0,SEEK_SET); 
      fputs(str_time,sf);   
      fclose(sf);  
      return 0;
} 
void kill_session() 
{ 
  char session_id[17]; 
  char *info; 
  char sfp[128]; 
  info=getenv("HTTP_COOKIE");  
  if(info!=NULL)  
  {  
        sscanf(info,"sess=%s",session_id);  
  } 
  strcpy(sfp,"/tmp");  
  strcat(sfp,"/sess_"); 
  strcat(sfp,session_id); 
  remove(sfp); 
} 
void clean_session_file() 
{ 
  DIR *pdir; 
  struct dirent *ent; 
  char *path; 
  char *filename; 
  char filepath[64]; 
  int fd; 
  char str_time[11] ={0}; 
  time_t  now; 
  path = "/tmp"; 
  pdir = opendir(path); 
  if(pdir != NULL) 
  { 
    while( ent =readdir(pdir) ) 
    { 
       filename = ent->d_name;  
       if( strncmp(filename,"sess_",5)==0 ) 
       { 
          strcpy(filepath,path); 
          strcat(filepath,"/"); 
          strcat(filepath,filename); 
          fd = open(filepath,O_RDONLY); 
          read(fd,str_time,10); 
          time(&now); 
          if( now - atoi(str_time) > 1800 )  
          { 
            remove(filepath); 
          }  
          close(fd); 
       } 
    }  
  } 
  closedir(pdir); 
} 
void print_session_error(int n) 
{ 
   printf("请重新登陆!"); 
   printf("\n"); 
   printf("\n"); 
   switch(n){
      case 1:
          printf("对不起，请重新登陆。\n");
          break;
      case 2: 
          printf("你长时间没有操作，登陆已经超时。或者是系统发生了错误。\n"); 
          break;
      case 4:
          printf("如果是后者，请与管理人员联系。\n"); 
          break;
   }
}