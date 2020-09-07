#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#define DEAL_BUF_LEN  4096
#define SIGN_CODE_LEN  100
#define FILE_NAME_LEN 64
#define FILE_SAVE_DIR "/mnt/app/"

#define UPLOAD_PRINT(fmt,args...) do{ \
    upload_log("/tmp/upload", "[IPC:%05d,%d]:"fmt, __LINE__, getpid(), ##args); \
}while(0)

void upload_log(char *file, const char *fmt, ...)
{
    va_list ap;
    FILE *fp = NULL;
    char bakfile[32] = {0,};

    fp = fopen(file, "a+");
    if (fp == NULL)
        return;
    va_start(ap, fmt);
    vfprintf(fp, fmt, ap);
    va_end(ap);
    if (ftell(fp) > 10*1024)
        snprintf(bakfile, sizeof(bakfile), "%s.bak", file);
    fclose(fp);
    if (bakfile[0])
        rename(file, bakfile);
}

enum
{
    STATE_START,
    STATE_GET_SIGN_CODE,
    STATE_GET_FILE_NAME,
    STATE_GET_FILE_START,
    STATE_GET_FILE_CONTENT,
    STATE_CHECK_END,
    STATE_END
};

/* 主体从这里开始 */

int upload_file(void)
{
    FILE *fp; /* 文件指针，保存我们要获得的文件 */
    int getState = STATE_START;
    int contentLength;/*标准输入内容长度*/
    int nowReadLen;
    int signCodeLen;
    int tmpLen;
    char *nowReadP;
    char *nowWriteP;
    char dealBuf[DEAL_BUF_LEN];
    char signCode[SIGN_CODE_LEN]; /*存储本次的特征码*/
    char tmpSignCode[SIGN_CODE_LEN];
    char fileName[FILE_NAME_LEN];
    memset(dealBuf,0,DEAL_BUF_LEN);
    memset(signCode,0,SIGN_CODE_LEN);
    memset(fileName,0,FILE_NAME_LEN);
    nowReadLen = 0;
    if((char *)getenv("CONTENT_LENGTH")!=NULL)
    {
        contentLength = atoi((char *)getenv("CONTENT_LENGTH"));
    }
    else
    {
        return -1;
    }
    if (contentLength > 3000000)
        return -1;
    while(contentLength > 0)
    {
        if(contentLength >= DEAL_BUF_LEN)
        {
            nowReadLen = DEAL_BUF_LEN;
        }
        else
        {
            nowReadLen = contentLength;
        }
        contentLength -= nowReadLen;
        if(fread(dealBuf,sizeof(char),nowReadLen,stdin) != nowReadLen)
        {
            return -1;
        }
        nowReadP = dealBuf;
        while(nowReadLen > 0)
        {
            switch (getState)
            {
                case STATE_START:
                    nowWriteP = signCode;
                    getState = STATE_GET_SIGN_CODE;
                case STATE_GET_SIGN_CODE:
                    if(strncmp(nowReadP,"\r\n",2) == 0)
                    {
                        signCodeLen = nowWriteP - signCode;
                        nowReadP++;
                        nowReadLen--;
                        *nowWriteP = 0;
                        getState = STATE_GET_FILE_NAME;
      //ShowErrorInfo(signCode);
                    }
                    else
                    {
                        *nowWriteP = *nowReadP;
                        nowWriteP++;
                    }
                    break;
                case STATE_GET_FILE_NAME:
                    if(strncmp(nowReadP,"filename=",strlen("filename=")) == 0)
                    {
                        nowReadP += strlen("filename=");
                        nowReadLen -= strlen("filename=");
                        nowWriteP = fileName + strlen(FILE_SAVE_DIR);
                        while(*nowReadP != '\r')
                        {
                            if(*nowReadP == '\\' || *nowReadP == '/')
                            {
                                nowWriteP = fileName + strlen(FILE_SAVE_DIR);
                            }
                            else if(*nowReadP != '\"')
                            {
                                *nowWriteP = *nowReadP;
                                nowWriteP++;
                            }
                            nowReadP++;
                            nowReadLen--;
                        }
                        *nowWriteP = 0;
                        nowReadP++;
                        nowReadLen--;
                        getState = STATE_GET_FILE_START;
                        memcpy(fileName,FILE_SAVE_DIR,strlen(FILE_SAVE_DIR));
                        if (strncmp(fileName,"/mnt/app/clou.tgz",strlen(fileName)) != 0) {
                            UPLOAD_PRINT("filename:%s\n", fileName);
                            return -1;
                        }
                        if((fp=fopen(fileName,"w"))==NULL)
                        {
                            return -1;
                        }
      //ShowErrorInfo(fileName);
                    }
                    break;
                case STATE_GET_FILE_START:
                    if(strncmp(nowReadP,"\r\n\r\n",4) == 0)
                    {
                        nowReadP += 3;
                        nowReadLen -= 3;
                        getState = STATE_GET_FILE_CONTENT;
      //ShowErrorInfo("get");
                    }
                    break;
                case STATE_GET_FILE_CONTENT:
                    if(*nowReadP != '\r')
                    {
                        fputc(*nowReadP,fp);
                    }
                    else
                    {
                        if(nowReadLen >= (signCodeLen + 2))
                        {
                            if(strncmp(nowReadP + 2,signCode,signCodeLen) == 0)
                            {
                                getState = STATE_END;
                                nowReadLen = 1;
                            }
                            else
                            {
                                fputc(*nowReadP,fp);
                            }
                        }
                        else
                        {
                            getState = STATE_CHECK_END;
                            nowWriteP = tmpSignCode;
                            *nowWriteP = *nowReadP;
                            nowWriteP++;
                            tmpLen = 1;
                        }
                    }
                    break;
                case STATE_CHECK_END:
                    if(*nowReadP != '\r')
                    {
                        if(tmpLen < signCodeLen + 2)
                        {
                            *nowWriteP = *nowReadP;
                            nowWriteP++;
                            tmpLen++;
                            if(tmpLen == signCodeLen + 2)
                            {
                                *nowWriteP = 0;
                                if((tmpSignCode[1] == '\n')&&(strncmp(tmpSignCode + 2,signCode,signCodeLen) == 0))
                                {
                                    getState = STATE_END;
                                    nowReadLen = 1;
                                }
                                else
                                {
         //fprintf(fp,tmpSignCode);
                                    fwrite(tmpSignCode,sizeof(char),tmpLen,fp);
                                    getState = STATE_GET_FILE_CONTENT;
                                }
                            }
                        }
                    }
                    else
                    {
                        *nowWriteP = 0;
      //fprintf(fp,tmpSignCode);
                        fwrite(tmpSignCode,sizeof(char),tmpLen,fp);
                        nowWriteP = tmpSignCode;
                        *nowWriteP = *nowReadP;
                        nowWriteP++;
                        tmpLen = 1;
                    }
                    break;
                case STATE_END:
                    nowReadLen = 1;
                    break;
                    default:break;
            }
            nowReadLen--;
            nowReadP++;
        }
    }
    if(fp != NULL)
    {
        fclose(fp);
    }
    return 0;
}