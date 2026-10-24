#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_DOMAINS 1000000
#define MAX_DOMAIN_LENGTH 256
extern char domains[MAX_DOMAINS][MAX_DOMAIN_LENGTH];
extern int ndomains;

int load_blocklist(const char *path);