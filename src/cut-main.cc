#include <fstream>
#include <string>
#include <system_error>
#include <vector>

int main(int argc, char* argv[]) {
    std::ifstream in;
    in.open("blacklist");
    in.exceptions(std::ios::badbit | std::ios::failbit);
    std::vector<std::string> files;
    std::string line;
    while (!(in >> std::ws).eof() && !std::getline(in, line).eof()) {
        files.emplace_back(std::move(line));
    }
    in.close();
    for (const auto& f : files) {
        int ret = std::remove(f.data());
        if (ret == -1) {
            throw std::system_error(errno, std::system_category());
        }
    }
    return 0;
}
