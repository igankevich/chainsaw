/*
Copyright © 2019–2021 Ivan Gankevich
SPDX-License-Identifier: Unlicense
*/

#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <unordered_set>

#include "config.h"

void print_usage(const char* name) {
    printf("usage: %s [-h] [--help] [--version] [blacklist-file whitelist-file]\n", name);
}

void print_version() {
    printf("%s\n", CHAINSAW_VERSION);
}

int main(int argc, char* argv[]) {
    const char* whitelist_path = "whitelist";
    const char* blacklist_path = "blacklist";
    if (argc == 2 && std::strcmp(argv[1], "--version") == 0) { print_version(); exit(0); }
    if (argc == 2) { print_usage(argv[0]); std::exit(1); }
    if (argc == 3) { blacklist_path = argv[1], whitelist_path = argv[2]; }
    std::string line;
    std::unordered_set<std::string> whitelist, blacklist;
    std::ifstream in;
    in.exceptions(std::ios::badbit | std::ios::failbit);
    in.open(whitelist_path);
    while (!(in >> std::ws).eof() && !std::getline(in, line).eof()) {
        whitelist.insert(std::move(line));
    }
    in.close();
    in.open(blacklist_path);
    while (!(in >> std::ws).eof() && !std::getline(in, line).eof()) {
        blacklist.insert(std::move(line));
    }
    in.close();
    for (const auto& x : whitelist) {
        blacklist.erase(x);
    }
    std::ofstream out;
    out.exceptions(std::ios::badbit | std::ios::failbit);
    out.open("diff");
    for (const auto& x : blacklist) {
        out << x << '\n';
    }
    out.close();
    return 0;
}
