#include <iostream>
#include "wwpdb.hpp"

int main() {
    const auto syms = wwpdb::parse(L"/download/symbols/ntdll.pdb/75F7CCDE5DADB62667C438A0754DF9521/ntdll.pdb");

    if (syms.empty()) {
        std::cerr << "Failed to fetch or parse PDB.\n";
        return 1;
    }

    for (const auto& sym : syms)
        std::cout << sym["name"].get<std::string>() << " @ 0x" << std::hex << sym["rva"].get<uint32_t>() << '\n';

    return 0;
}