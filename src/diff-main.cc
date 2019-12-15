#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <unordered_set>

int main(int argc, char* argv[]) {
    std::string line;
    std::unordered_set<std::string> whitelist, blacklist;
    std::ifstream in;
    in.exceptions(std::ios::badbit | std::ios::failbit);
    in.open("whitelist");
    while (!(in >> std::ws).eof() && !std::getline(in, line).eof()) {
        whitelist.insert(std::move(line));
    }
    in.close();
    in.open("blacklist");
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
