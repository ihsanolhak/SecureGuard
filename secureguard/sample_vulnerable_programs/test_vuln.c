#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    char buffer[50];
    char* password = "hardcoded_super_secret"; // Hardcoded credential
    
    printf("Enter input: ");
    gets(buffer); // CRITICAL
    
    char dest[50];
    strcpy(dest, buffer); // CRITICAL
    
    char msg[100];
    sprintf(msg, "You entered: %s", dest); // CRITICAL
    
    system("ls -la"); // HIGH
    
    strcat(msg, " !!!"); // HIGH
    
    int random_val = rand(); // MEDIUM
    
    // TODO: Fix this security vulnerability later // LOW
    
    int *ptr = (int *)malloc(sizeof(int) * 10); // MEMORY LEAK AND POINTER
    
    #ifdef DEBUG // LOW
    printf("Debug is enabled\n");
    #endif
    
    return 0;
}
