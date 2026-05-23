#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    int fd = open("/etc/passwd", O_WRONLY | O_APPEND | O_CLOEXEC);
    if (fd < 0) {
        perror("open /etc/passwd");
        exit(1);
    }

    printf("Passwd FD is %d\n", fd);

    if (close(fd) == -1) {
        perror("close /etc/passwd fd");
        exit(1);
    }

    if (setuid(getuid()) == -1) {
        perror("setuid");
        exit(1);
    }

    execl("/bin/sh", "sh", NULL);

    perror("execl");
    return 1;
}
