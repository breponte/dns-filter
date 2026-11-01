#include "load.h"

char domains[MAX_DOMAINS][MAX_DOMAIN_LENGTH];
int ndomains = 0;

int main(int argc, char *argv[])
{
    const char *path = (argc > 1) ? argv[1] : "C:\\Users\\brepo\\OneDrive\\Desktop\\playground\\dns-filter\\blocked.txt";
    if (load_blocklist(path) < 0) {
        fprintf(stderr, "Failed to load blocklist: %s\n", path);
        return 1;                            // non-zero exit shows up as a failed service
    }

    char buff[MAX_DOMAIN_LENGTH];
    while (1) {
        fgets(buff, sizeof(buff), stdin);
        for (long long unsigned int j = 0; j < sizeof(buff); j++) {
            if (buff[j] == '\n' || buff[j] == '\r') {
                buff[j] = '\0';
                break;
            }
        }

        // printf("Checking: %s\n", domains[773272]);

        for (int i = 0; i < ndomains; i++) {
            if (strcmp(buff, domains[i]) == 0) {
                printf("Blocked: %s\n", buff);
                break;
            } 
        }
    }
    
    return 0;
}