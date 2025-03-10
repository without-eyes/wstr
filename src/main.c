/**
    * @file: main.c
    * @author: without eyes
    *
    * This file contains main function which runs WSTR.
*/

#include "../include/wstr.h"

int main(int argc, char *argv[]) {
    const struct Options options = parse_arguments(argc, argv);
    wstr(argv[1], &options);
    return 0;
}