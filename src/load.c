#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "load.h"

int load_blocklist(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    static char tmp[MAX_DOMAINS][MAX_DOMAIN_LENGTH];   // load into a temp list first
    int n = 0;
    char line[MAX_DOMAIN_LENGTH];
    while (n < MAX_DOMAINS && fgets(line, sizeof line, f)) {
        line[strcspn(line, "\r\n")] = '\0';
        char *p = line;
        while (*p == ' ' || *p == '\t' || *p == '.') p++;   // trim leading space/dot
        if (*p == '\0' || *p == '#') continue;              // skip blanks and comments
        size_t len = strlen(p);
        while (len > 0 && (p[len-1] == ' ' || p[len-1] == '\t' || p[len-1] == '.'))
            p[--len] = '\0';                                // trim trailing space/dot
        for (char *c = p; *c; c++) *c = (char)tolower((unsigned char)*c);
        strcpy(tmp[n++], p);
    }
    fclose(f);

    if (n == 0) return -1;               // treat an empty list as an error
    memcpy(domains, tmp, sizeof tmp);
    ndomains = n;
    return n;
}