#pragma once
#include <fstream>

namespace DES{
    // DES_Functor lfsr_func {::seed, ::mask};

    // void run_stream_cipher(std::ifstream &, std::ofstream &, uint64_t);
    uint64_t encrypt(uint64_t, uint64_t);
    uint64_t decrypt(uint64_t, uint64_t);
}