#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int main(void) {
    int dfd;
    char *argv[2];

    dfd = open("/root", O_RDONLY | O_CLOEXEC);
    if (dfd == -1) {
        perror("open /root");
        exit(1);
    }
    printf("Directory FD is %d\n", dfd);

    if (mkdir("/root/backupssi", 0700) == -1) {
        perror("mkdir /root/backupssi");
    }

    if (close(dfd) == -1) {
        perror("close /root fd");
        exit(1);
    }

    if (setuid(getuid()) == -1) {
        perror("setuid");
        exit(1);
    }

    argv[0] = "/bin/sh";
    argv[1] = NULL;
    execve(argv[0], argv, NULL);

    perror("execve");
    return 0;
}
