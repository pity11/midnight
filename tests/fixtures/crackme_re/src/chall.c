#include <stdio.h>
#include <string.h>

/* The flag is stored obfuscated and printed only on the right input,
   but `strings` / static inspection can recover the embedded constant. */
static const char *flag = "flag{strings_reveal_secrets}";

int main(void) {
    char buf[64];
    printf("Enter password: ");
    if (!fgets(buf, sizeof(buf), stdin)) return 1;
    buf[strcspn(buf, "\n")] = 0;
    if (strcmp(buf, "letmein") == 0) {
        printf("Correct! %s\n", flag);
    } else {
        printf("Nope.\n");
    }
    return 0;
}
