#pragma once

#include <stddef.h>
#include <stdio.h>

void exit(int code);
ssize_t write(int fd, const void *data, size_t size);
ssize_t read(int fd, void *data, size_t size);
int open(const char *path, int flags, ...);
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int arch_prctl(int code, unsigned long addr);

extern int errno;
