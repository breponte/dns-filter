#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_DOMAINS 1000000
static char domains[MAX_DOMAINS][256];
static int  ndomains = 0;

int load_blocklist(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    static char tmp[MAX_DOMAINS][256];   // load into a temp list first
    int n = 0;
    char line[256];
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

int main(int argc, char *argv[])
{
    const char *path = (argc > 1) ? argv[1] : "C:\\Users\\brepo\\OneDrive\\Desktop\\playground\\dns-filter\\blocked.txt";
    if (load_blocklist(path) < 0) {
        fprintf(stderr, "Failed to load blocklist: %s\n", path);
        return 1;                            // non-zero exit shows up as a failed service
    }

    char buff[256];
    while (1) {
        fgets(buff, sizeof(buff), stdin);
        for (int j = 0; j < sizeof(buff); j++) {
            if (buff[j] == '\n' || buff[j] == '\r') {
                buff[j] = '\0';
                break;
            }
        }
        for (int i = 0; i < ndomains; i++) {
            if (strcmp(buff, domains[i]) == 0) {
                printf("Blocked: %s\n", buff);
                break;
            }
            
        }
    }
    
    return 0;
}