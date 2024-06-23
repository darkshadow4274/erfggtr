#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

unsigned long long int secret_codes[10];
int indexvar = 0;

void help(){
	__asm__("ret");
	__asm__("mov %rbp, %rdi");
	__asm__("ret");
}

void chaos(){
    char mission_statement[136];
        
    setbuf(stdin, 0LL);
    setbuf(stdout, 0LL);
    setbuf(stderr, 0LL);
    printf("Mission Briefing: Provide secret codes for your operations.\n");
    printf("Enter your mission statement: ");
    fgets(mission_statement, 162, stdin); 
    printf("Mission acknowledged! Proceeding with operation details...\n");
    
    printf("Enter the operation index: ");
    scanf("%d", &indexvar);
    
    if (indexvar >= 10) {
        printf("Error: Operation index out of range! We don't have that many operations.\n");
        exit(1);
    }
    
    printf("Enter the secret code for Operation %d: ", indexvar);
    scanf("%llu", &secret_codes[indexvar]);
    
    return;
}

int main() {
    printf("Welcome to the Spy Network Headquarters!\n");
    printf("----------------------------------------\n");
    chaos();
    return 0;
}

