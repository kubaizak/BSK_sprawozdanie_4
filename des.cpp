#include "des.hpp"
#include <iostream>
#include <stdio.h>
#include <bitset>

namespace DES{
    static constexpr uint8_t num_rows = 8;
    static constexpr uint8_t num_KS_iterations = 16;
    static constexpr uint8_t PC_1_word_length = 7;
    static constexpr uint8_t PC_2_word_length = 6;
    static constexpr uint8_t E_word_length = 6;
    static constexpr uint8_t S_word_length = 4;
    static constexpr uint8_t P_word_length = 4;

    // Input block LR permutation table
    static constexpr uint8_t IP[][num_rows] {
        {58, 50, 42, 34, 26, 18, 10, 2},
        {60, 52, 44, 36, 28, 20, 12, 4},
        {62, 54, 46, 38, 30, 22, 14, 6},
        {64, 56, 48, 40, 32, 24, 16, 8},
        {57, 49, 41, 33, 25, 17, 9,  1},
        {59, 51, 43, 35, 27, 19, 11, 3},
        {61, 53, 45, 37, 29, 21, 13, 5},
        {63, 55, 47, 39, 31, 23, 15, 7}
    };

    static constexpr uint8_t IP_INV[][num_rows] {
        {40, 8, 48, 16, 56, 24, 64, 32},
        {39, 7, 47, 15, 55, 23, 63, 31},
        {38, 6, 46, 14, 54, 22, 62, 30},
        {37, 5, 45, 13, 53, 21, 61, 29},
        {36, 4, 44, 12, 52, 20, 60, 28},
        {35, 3, 43, 11, 51, 19, 59, 27},
        {34, 2, 42, 10, 50, 18, 58, 26},
        {33, 1, 41, 9,  49, 17, 57, 25}
    };

    // PC1 - permuted choice; KS key permutation table 
    static constexpr uint8_t PC_1[][PC_1_word_length] {
        //C half
        {57, 49, 41, 33, 25, 17, 9},
        {1, 58, 50, 42, 34, 26, 18},
        {10, 2, 59, 51, 43, 35, 27},
        {19, 11, 3, 60, 52, 44, 36},
        //D half
        {63, 55, 47, 39, 31, 23, 15},
        {7, 62, 54, 46, 38, 30, 22},
        {14, 6, 61, 53, 45, 37, 29},
        {21, 13, 5, 28, 20, 12, 4}
    };

    static constexpr uint8_t KS_shifts[num_KS_iterations] {
        1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
    };

    static constexpr uint8_t PC_2[][PC_2_word_length] {
        {14, 17, 11, 24, 1, 5},
        {3, 28, 15, 6, 21, 10},
        {23, 19, 12, 4, 26, 8},
        {16, 7, 27, 20, 13, 2},
        {41, 52, 31, 37, 47, 55},
        {30, 40, 51, 45, 33, 48},
        {44, 49, 39, 56, 34, 53},
        {46, 42, 50, 36, 29, 32}
    };

    static constexpr uint8_t E[][E_word_length] {
        {32, 1,  2,  3,  4,  5},
        {4,  5,  6,  7,  8,  9},
        {8,  9,  10, 11, 12, 13},
        {12, 13, 14, 15, 16, 17},
        {16, 17, 18, 19, 20, 21},
        {20, 21, 22, 23, 24, 25},
        {24, 25, 26, 27, 28, 29},
        {28, 29, 30, 31, 32, 1}
    };

    // S-box definition
    static constexpr uint8_t S[][4][16] {
        {
            {14 ,4 ,13 ,1 ,2 ,15 ,11 ,8 ,3 ,10 ,6 ,12 ,5 ,9 ,0 ,7},
            {0 ,15 ,7 ,4 ,14 ,2 ,13 ,1 ,10 ,6 ,12 ,11 ,9 ,5 ,3 ,8},
            {4 ,1 ,14 ,8 ,13 ,6 ,2 ,11 ,15 ,12 ,9 ,7 ,3 ,10 ,5 ,0},
            {15 ,12 ,8 ,2 ,4 ,9 ,1 ,7 ,5 ,11 ,3 ,14 ,10 ,0 ,6 ,13}
        },
        {
            {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
            {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
            {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
            {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
        },
        {
            {10 ,0 ,9 ,14 ,6 ,3 ,15 ,5 ,1 ,13 ,12 ,7 ,11 ,4 ,2 ,8},
            {13 ,7 ,0 ,9 ,3 ,4 ,6 ,10 ,2 ,8 ,5 ,14 ,12 ,11 ,15 ,1},
            {13 ,6 ,4 ,9 ,8 ,15 ,3 ,0 ,11 ,1 ,2 ,12 ,5 ,10 ,14 ,7},
            {1 ,10 ,13 ,0 ,6 ,9 ,8 ,7 ,4 ,15 ,14 ,3 ,11 ,5 ,2 ,12}
        },
        {
            {7 ,13 ,14 ,3 ,0 ,6 ,9 ,10 ,1 ,2 ,8 ,5 ,11 ,12 ,4 ,15},
            {13 ,8 ,11 ,5 ,6 ,15 ,0 ,3 ,4 ,7 ,2 ,12 ,1 ,10 ,14 ,9},
            {10 ,6 ,9 ,0 ,12 ,11 ,7 ,13 ,15 ,1 ,3 ,14 ,5 ,2 ,8 ,4},
            {3 ,15 ,0 ,6 ,10 ,1 ,13 ,8 ,9 ,4 ,5 ,11 ,12 ,7 ,2 ,14}
        },
        {
            {2 ,12 ,4 ,1 ,7 ,10 ,11 ,6 ,8 ,5 ,3 ,15 ,13 ,0 ,14 ,9},
            {14 ,11 ,2 ,12 ,4 ,7 ,13 ,1 ,5 ,0 ,15 ,10 ,3 ,9 ,8 ,6},
            {4 ,2 ,1 ,11 ,10 ,13 ,7 ,8 ,15 ,9 ,12 ,5 ,6 ,3 ,0 ,14},
            {11 ,8 ,12 ,7 ,1 ,14 ,2 ,13 ,6 ,15 ,0 ,9 ,10 ,4 ,5 ,3}
        },
        {
            {12 ,1 ,10 ,15 ,9 ,2 ,6 ,8 ,0 ,13 ,3 ,4 ,14 ,7 ,5 ,11},
            {10 ,15 ,4 ,2 ,7 ,12 ,9 ,5 ,6 ,1 ,13 ,14 ,0 ,11 ,3 ,8},
            {9 ,14 ,15 ,5 ,2 ,8 ,12 ,3 ,7 ,0 ,4 ,10 ,1 ,13 ,11 ,6},
            {4 ,3 ,2 ,12 ,9 ,5 ,15 ,10 ,11 ,14 ,1 ,7 ,6 ,0 ,8 ,13}
        },
        {
            {4 ,11 ,2 ,14 ,15 ,0 ,8 ,13 ,3 ,12 ,9 ,7 ,5 ,10 ,6 ,1},
            {13 ,0 ,11 ,7 ,4 ,9 ,1 ,10 ,14 ,3 ,5 ,12 ,2 ,15 ,8 ,6},
            {1 ,4 ,11 ,13 ,12 ,3 ,7 ,14 ,10 ,15 ,6 ,8 ,0 ,5 ,9 ,2},
            {6 ,11 ,13 ,8 ,1 ,4 ,10 ,7 ,9 ,5 ,0 ,15 ,14 ,2 ,3 ,12}
        },
        {
            {13 ,2 ,8 ,4 ,6 ,15 ,11 ,1 ,10 ,9 ,3 ,14 ,5 ,0 ,12 ,7},
            {1 ,15 ,13 ,8 ,10 ,3 ,7 ,4 ,12 ,5 ,6 ,11 ,0 ,14 ,9 ,2},
            {7 ,11 ,4 ,1 ,9 ,12 ,14 ,2 ,0 ,6 ,10 ,13 ,15 ,3 ,5 ,8},
            {2 ,1 ,14 ,7 ,4 ,10 ,8 ,13 ,15 ,12 ,9 ,0 ,3 ,5 ,6 ,11}
        }
    };

    static constexpr uint8_t P[][P_word_length] {
        { 16, 7,  20, 21 },
        { 29, 12, 28, 17 },
        { 1,  15, 23, 26 },
        { 5,  18, 31, 10 },
        { 2,  8,  24, 14 },
        { 32, 27, 3,  9 },
        { 19, 13, 30, 6 },
        { 22, 11, 4,  25 }
    };



    uint64_t perform_initial_permutation(uint64_t input_block){
        uint64_t LR = 0;
        
        // I   - shift right input block for the IP[i][j] places then perform binary AND with 1 to get its value
        // II  - shift left that result bit from above i * DES::num_rows + j then perform binary OR with LR
        for(uint8_t i = 0; i < DES::num_rows; ++i)
            for(uint8_t j = 0; j < DES::num_rows; ++j)
                LR |= /* I */ (input_block >> (IP[i][j] - 1) & 1) /* II */ << (i * DES::num_rows + j);

        return LR;
    }

    uint64_t perform_inverse_initial_permutation(uint64_t preoutput_block){
        uint64_t out = 0;
        
        for(uint8_t i = 0; i < DES::num_rows; ++i)
            for(uint8_t j = 0; j < DES::num_rows; ++j)
                out |= (preoutput_block >> (DES::IP_INV[i][j] - 1) & 1) << (i * DES::num_rows + j);

        return out;
    }

    // Key schedule KS returns 48-bit block Kn - permuted selection of bits from KEY
    uint64_t KS(uint8_t n, uint64_t KEY){
        if(n >= DES::num_KS_iterations) throw std::out_of_range("DES::KS n parameter must be unsigned integer lower than 16");

        uint64_t Kn = 0;

        //compute permuted choice 1 - 8*7 bits block
        for(uint8_t i = 0; i < DES::num_rows; ++i)
            for(uint8_t j = 0; j < DES::PC_1_word_length; ++j)
                Kn |= (KEY >> (DES::PC_1[i][j] - 1) & 1) << (i * DES::PC_1_word_length + j);

        //divide to two 28-bit blocks C and D  
        uint32_t mask_28 { (1 << 28) - 1 },  //28 bits set to 1
                 C { static_cast<uint32_t>(Kn >> 28 & mask_28) }, 
                 D { static_cast<uint32_t>(Kn & mask_28) };
        
        //compute shift length
        uint8_t shift = 0;
        for(uint8_t i = 0; i < n + 1; ++i){
            shift += DES::KS_shifts[i];
        }

        //compute Cn and Dn from C and D by rotating bits to the left by length of shift
        uint32_t Cn { C << shift | C >> (28 - shift) & ((1 << shift) - 1) },    // left outer most shift bits (overflow) become least significant bits
                 Dn { D << shift | D >> (28 - shift) & ((1 << shift) - 1) };    // left outer most shift bits (overflow) become least significant bits
        uint64_t CnDn { (uint64_t)Cn << 28 | Dn };                              // merge to one block

        //compute permuted choice 2 - 8*6 bits block
        Kn = 0;
        for(uint8_t i = 0; i < DES::num_rows; ++i)
            for(uint8_t j = 0; j < DES::PC_2_word_length; ++j)
                Kn |= (CnDn >> (DES::PC_2[i][j] - 1) & 1) << (i * DES::PC_2_word_length + j);

        return Kn;  //48-bit block
    }

    // cipher function returns 48-bit block
    // input parameters are:
    //  - R 32-bit
    //  - K 48-bit (Key schedule output)
    uint32_t cipher_function(uint32_t R, uint64_t K){
        //compute expansion_block 48-bit block from R
        uint64_t expansion_block = 0;
        for(uint8_t i = 0; i < DES::num_rows; ++i)
            for(uint8_t j = 0; j < DES::E_word_length; ++j)
                expansion_block |= (R >> (DES::E[i][j] - 1) & 1) << (i * DES::E_word_length + j);

        //48-bit block
        uint64_t block_48 = expansion_block ^ K;
       
        //S-box processing
        uint32_t S_block_length = DES::num_rows * DES::S_word_length;
        uint32_t S_block        = 0;
        for(uint8_t n = 0; n < DES::num_rows; ++n){
            uint8_t B = block_48 >> (48 - (n + 1) * DES::E_word_length) & ((1 << DES::E_word_length) - 1);
            uint8_t i = (B >> 5 & 1) << 1 | B & 1;                                      // S-box row idx computed from outer most left and right bits 
            uint8_t j = (B >> 1) & ((1 << DES::S_word_length) - 1);                     // S-box column idx computed from inner 4-bit block 

            // S1 - highest block; S2 - (highest - 1) block; ... S8 - 1st block
            S_block |= S[n][i][j] << (S_block_length - (n + 1) * DES::S_word_length);   // shift left 4 bits (it is word length for newly created 32-bit block)
        }

        // S-box created block gets permutated by P
        uint32_t output = 0;
        for(uint8_t i = 0; i < DES::num_rows; ++i)
            for(uint8_t j = 0; j < DES::P_word_length; ++j)
                output |= (S_block >> (DES::P[i][j] - 1) & 1) << (i * DES::P_word_length + j);

        return output;
    }

    uint64_t encrypt(uint64_t input_block, uint64_t KEY){
        uint64_t LR      = perform_initial_permutation(input_block);
        uint32_t mask_32 = -1,
                 L       = LR >> 32 & mask_32, 
                 R       = LR & mask_32;

        // 16 iterations 
        for(uint8_t i = 0; i < DES::num_KS_iterations; ++i){
            uint32_t temp_L = L;
            L = R;
            R = temp_L ^ cipher_function(R, KS(i, KEY));
        }

        uint64_t RL = static_cast<uint64_t>(R) << 32 | L;                   // preoutput block R16L16
        uint64_t output_block = perform_inverse_initial_permutation(RL);    // inverse initial permutation
        return output_block;
    }

    uint64_t decrypt(uint64_t input_block, uint64_t KEY){
        uint64_t LR      = perform_initial_permutation(input_block);
        uint32_t mask_32 = -1,
                 L       = LR >> 32 & mask_32, 
                 R       = LR & mask_32;

        // 16 iterations 
        for(uint8_t i = 0; i < DES::num_KS_iterations; ++i){
            uint32_t temp_L = L;
            L = R;
            R = temp_L ^ cipher_function(R, KS(DES::num_KS_iterations - i - 1, KEY));
        }

        uint64_t RL = static_cast<uint64_t>(R) << 32 | L;                   // preoutput block R16L16
        uint64_t output_block = perform_inverse_initial_permutation(RL);    // inverse initial permutation
        return output_block;
    }

    // void run_stream_cipher(std::ifstream & ifs, std::ofstream & ofs, uint64_t KEY){
    //     uint64_t LR = 0;        // input block
    //     uint32_t L = 0,         // left  portion of LR
    //              R = 0,         // right portion of LR
    //              mask_32 = -1;  // we end up with all bits set to 1

    //     // read input data as 64bit blocks LR
    //     while(ifs.read((char *)(&LR), sizeof(uint64_t))){
    //         LR = perform_initial_permutation(LR);
    //         L = LR >> 32 & mask_32;
    //         R = LR & mask_32;

    //         // 16 iterations 
    //         for(uint8_t i = 0; i < DES::num_KS_iterations; ++i){
    //             uint32_t temp_L = L;
    //             L = R;
    //             R = temp_L ^ cipher_function(R, KS(i, KEY));
    //             // R = temp_L ^ cipher_function(R, KS(15 - i, KEY));
    //         }

    //         uint64_t RL = static_cast<uint64_t>(R) << 32 | L;                                  // preoutput block R16L16
    //         uint64_t out = perform_inverse_initial_permutation(RL);     // inverse initial permutation

    //         // saving to file
    //         ofs.write((char *)(&out), sizeof(uint64_t));
    //     }
    // }
}