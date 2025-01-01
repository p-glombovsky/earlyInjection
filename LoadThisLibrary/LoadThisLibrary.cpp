#include <windows.h>

#include <stdio.h>
#include <stdlib.h>

int main( int argc, char **argv)
{
    if (argc < 2) {
        printf("Please specify the library to load\n");
        return 1;
    }
    HMODULE hLib = LoadLibraryA(argv[1]);
    if (hLib == NULL) {
        printf("Could not load library \"%s\"\n", argv[1]);
    }
    else {
        printf("Library \"%s\" was successfully loaded\n", argv[1]);
        FreeLibrary(hLib);
    }
    return 0;
}
