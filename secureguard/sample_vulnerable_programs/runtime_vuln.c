#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void vulnerable_function(char *input) {
    char buffer[64];
    printf("Processing input of size %zu...\n", strlen(input));
    
    // VULNERABILITY: strcpy without bounds checking
    strcpy(buffer, input); 
    
    printf("Processed successfully: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input_string>\n", argv[0]);
        return 1;
    }
    
    vulnerable_function(argv[1]);
    
    return 0;
}
