/*
Copyright © 2019–2021 Ivan Gankevich
SPDX-License-Identifier: Unlicense
*/

#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <system_error>
#include <vector>

#include "config.h"

void print_usage(const char* name) {
    printf("usage: %s [-h] [--help] [--version] [--confirm] [diff-file]\n", name);
}

void print_version() {
    printf("%s\n", CHAINSAW_VERSION);
}

int main(int argc, char* argv[]) {
    bool confirmed = false;
    const char* diff_path = "diff";
    if (argc <= 1) { print_usage(argv[0]); std::exit(1); }
    if (argc == 2 && std::strcmp(argv[1], "--version") == 0) { print_version(); exit(0); }
    if (argc == 2) {
        if (std::strcmp(argv[1], "--confirm") == 0) { confirmed = true; }
        else { diff_path = argv[1]; }
    }
    if (argc == 3) {
        if (std::strcmp(argv[1], "--confirm") == 0) {
            confirmed = true;
            diff_path = argv[2];
        } else if (std::strcmp(argv[2], "--confirm") == 0) {
            confirmed = true;
            diff_path = argv[1];
        } else {
            print_usage(argv[0]);
            std::exit(1);
        }
    }
    std::ifstream in;
    in.open(diff_path);
    if (!in.is_open()) {
        std::stringstream msg;
        msg << "failed to open " << diff_path;
        throw std::runtime_error(msg.str());
    }
    in.exceptions(std::ios::badbit | std::ios::failbit);
    std::vector<std::string> files;
    std::string line;
    while (!(in >> std::ws).eof() && !std::getline(in, line).eof()) {
        files.emplace_back(std::move(line));
    }
    in.close();
    if (!confirmed) {
        std::string answer;
        do {
            std::cout
                << "This command will delete " << files.size()
                << " file(s). Are you sure? [y/N]" << std::endl;
            std::cin >> answer;
            for (auto& ch : answer) { ch = std::tolower(ch); }
        } while (answer == "y" || answer == "n");
        if (answer == "y") { confirmed = true; }
    }
    if (confirmed) {
        for (const auto& f : files) {
            int ret = std::remove(f.data());
            if (ret == -1) {
                std::cerr << "failed to remove " << f.data() << ": " << std::strerror(errno) << std::endl;
            }
        }
    }
    return 0;
}
