#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <system_error>
#include <vector>

#include "config.h"

void print_usage(const char* name) {
    printf("usage: %s [-h] [--help] [--version] [--confirm] [blacklist-file]\n", name);
}

void print_version() {
    printf("%s\n", CHAINSAW_VERSION);
}

int main(int argc, char* argv[]) {
    bool confirmed = false;
    const char* blacklist_path = "blacklist";
    if (argc <= 1) { print_usage(argv[0]); std::exit(1); }
    if (argc == 2 && std::strcmp(argv[1], "--version") == 0) { print_version(); exit(0); }
    if (argc == 2) {
       if (std::strcmp(argv[1], "--confirm") == 0) { confirmed = true; }
       else { blacklist_path = argv[1]; }
    }
    if (argc == 3) {
       if (std::strcmp(argv[1], "--confirm") == 0) {
           confirmed = true;
           blacklist_path = argv[2];
       } else
       if (std::strcmp(argv[2], "--confirm") == 0) {
           confirmed = true;
           blacklist_path = argv[1];
       } else {
           print_usage(argv[0]);
           std::exit(1);
       }
    }
    std::ifstream in;
    in.open(blacklist_path);
    in.exceptions(std::ios::badbit | std::ios::failbit);
    std::vector<std::string> files;
    std::string line;
    while (!(in >> std::ws).eof() && !std::getline(in, line).eof()) {
        files.emplace_back(std::move(line));
    }
    in.close();
    if (!confirmed) {
        std::string answer;
        while (answer == "y" || answer == "n") {
            std::cout
                << "This command will delete " << files.size()
                << " file(s). Are you sure? [y/N]" << std::endl;
            std::cin >> answer;
            for (auto& ch : answer) { ch = std::tolower(ch); }
        }
        if (answer == "y") { confirmed = true; }
    }
    if (confirmed) {
        for (const auto& f : files) {
            int ret = std::remove(f.data());
            if (ret == -1) {
                throw std::system_error(errno, std::system_category());
            }
        }
    }
    return 0;
}
