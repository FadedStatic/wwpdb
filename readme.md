# World's Worst PDB Parser (WWPDB)
The acronym should actually be WWPDBP, but I dropped the last letter because it didn't sound as nice. \
Anyway, this is the world's worst PDB parser because it serves only one purpose; to parse symbols and output them as JSON.

## Why only the symbols?
For certain applications, symbols are all that is needed. \
Potentially, the type info table may also hold some valuable things (for instance, UserDirectoryTableBase off of _EPROCESS) \
I don't have the need for types at the moment, so it unfortunately will not be in the implementation right now.

## Why use this instead of other opensource libraries
If your scope is anything more than parsing just symbols, you are better off using [raw_pdb](https://github.com/MolecularMatters/raw_pdb) \
This project is designed to do nothing but parse the symbols, it is designed to be as small as possible, with the option to download these symbols from a server. \
It's a header-only lib which requires another commonly-included lib, nlohmann_json. \
The project is quick, easy, and lightweight, making it a decent candidate for this specific purpose.

Anyway, that's it. Have fun!

## Third-party licenses
This project uses [nlohmann/json](https://github.com/nlohmann/json), which is licensed under the MIT License: