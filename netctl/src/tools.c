#include "tools.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

char *mac2str(uint8 *mac)
{
	char *str = malloc(20);
	memset(str, 0, 20);
	snprintf(str, 20, "%02X:%02X:%02X:%02X:%02X:%02X",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	return str;
}
int shell_printf(char *cmd, char *dst, int dlen)
{
  FILE *fp;
  int rlen;

  if (!cmd || !dst|| dlen <= 1)
  {
    return -1;
  }
  if ((fp = popen(cmd, "r")) == NULL)
  {
    return -1;
  }
  rlen = fread(dst, sizeof(char), dlen - 1, fp);
//  dst[dlen-1] = 0;
  dst[rlen] = 0;

  pclose(fp);
  return rlen;
}

int str2mac(char *str, unsigned char *mac)
{
	int i = 0, j = 0;
	unsigned char v = 0;

	for (i = 0; i < 17; i++) 
  {
		if (str[i] >= '0' && str[i] <= '9') 
    {
			v = str[i] - '0';
		} 
    else if (str[i] >= 'a' && str[i] <= 'f') 
    {
			v = str[i] - 'a' + 10;
		} 
    else if (str[i] >= 'A' && str[i] <= 'F') 
    {
			v = str[i] - 'A' + 10;
		} 
    else if (str[i] == ':' || str[i] == '-' ||
					str[i] == ',' || str[i] == '\r' ||
					str[i] == '\n') {
			continue;
		} 
    else if (str[i] == '\0') 
    {
			return 0;
		} 
    else 
    {
			return -1;
		}
		if (j%2)
    {
			mac[j/2] += v;
    }
		else
    {
			mac[j/2] = v*16;
    }
		j++;
		if (j/2 > 5)
    {
			break;
    }
	}
	return 0;
}

int macformat(char *mac, char split)
{
	int i = 0;
	for (i = 0; i < 5; i++) 
  {
		mac[(i+1)*3-1] = split;
	}
	return 0;
}
void urlencode(const unsigned char *s, char *t) 
{
    const unsigned char *p = s;
    char *tp = t;

    for (; *p; p++) 
    {
        if ((*p > 0x00 && *p < ',') ||
                (*p > '9' && *p < 'A') ||
                (*p > 'Z' && *p < '_') ||
                (*p > '_' && *p < 'a') ||
                (*p > 'z' && *p < 0xA1)) 
        {
            sprintf((char *)tp, "%%%02X", *p);
            tp += 3; 
        } 
        else 
        {
            *tp = *p;
            tp++;
        }
    }

    *tp='\0';
}

void urldecode(char *p)  
{  
	int i=0;  
	while(*(p+i))  
	{  
	   if ((*p=*(p+i)) == '%')  
	   {  
	    *p=*(p+i+1) >= 'A' ? ((*(p+i+1) & 0XDF) - 'A') + 10 : (*(p+i+1) - '0');  
	    *p=(*p) * 16;  
	    *p+=*(p+i+2) >= 'A' ? ((*(p+i+2) & 0XDF) - 'A') + 10 : (*(p+i+2) - '0');  
	    i+=2;  
	   }  
	   else if (*(p+i)=='+')  
	   {  
	    *p=' ';  
	   }  
	   p++;  
	}  
	*p='\0';  
} 

char *trim(char *str)
{
        char *p = str;
        char *p1;
        if(p)
        {
                p1 = p + strlen(str) - 1;
                while(*p && isspace(*p)) p++;
                while(p1 > p && isspace(*p1)) *p1-- = '\0';
        }
        return p;
}
/*获取指定字段（name）信息存入result中*/
int getfile_info(char *filename, char *name,char *result)
{
  char linebuffer[100] = {0};
  char buffer1[100] = {0};
  char buffer2[100] = {0};
  char *key = NULL;
  char *value = NULL;
  uint8 flag = 0;
  int buffer_size=0;
  FILE *fp = fopen(filename, "r");
  if(fp == NULL)
  {
      printf("open error");
      return 1;
  }
  while(1)
  {
      char *ret = fgets(linebuffer, 100, fp);
      if(ret == NULL)
      {
        break;
      }
      sscanf(linebuffer, "%[^=]=%[^=]", buffer1,buffer2);
      key = trim(buffer1);
      value = trim(buffer2);
      if(!strcmp(name, key))
      {
         
         buffer_size=strlen(value);
         memcpy(result,value,buffer_size);
        result[buffer_size]='\0';//remove the \n
        flag = 1;
        break;   
      }
      memset(buffer1,0,sizeof(buffer1));
      memset(buffer2,0,sizeof(buffer2));
      memset(linebuffer,0,sizeof(linebuffer));
  }
  fclose(fp);
  if(flag != 1)
  {
    return 1;
  }
  return 0;
}
