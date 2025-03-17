/**
    * @file: main.c
    * @author: without eyes
    *
    * This file contains main function which runs WSTR.
*/

#include "wstr.h"

int main(int argc, char *argv[]) {
    const struct Options options = parse_arguments(argc, argv);
    wstr(&options);
    return 0;
}