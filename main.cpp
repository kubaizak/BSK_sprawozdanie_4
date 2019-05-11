#include "des.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <bitset>
#include <vector>
#include <deque>
#include <string>

static uint64_t key;
static std::ifstream ifs;
static std::ofstream ofs;
static uint64_t (*executeFn)(uint64_t, uint64_t) = DES::encrypt;

void set_global_variables(int argc, char** argv) {
    if(argc == 1)   throw 0;
    if(argc < 4)    throw -1;

    std::deque<std::string> params_list;

    for(int i {1}; i < argc; ++i){
        params_list.push_back(std::string(argv[i]));
    }
        
    //-d option
    std::string param = params_list.front();
    if(param[0] == '-'){                            //check if option flag
        if(param.size() == 2 && param[1] == 'd')    //if -d then decrypt
            executeFn = DES::decrypt;
        else throw -4; 

        params_list.pop_front();                    //either way it is flag so remove param
    }

    //KEY
    std::stringstream ss;
    ss << std::hex << params_list.front();
    ss >> ::key;
    params_list.pop_front();

    //INPUT_FILE_STREAM
    std::string iname = params_list.front();
    ifs = std::ifstream{iname, std::ios_base::binary};
    if(!ifs) throw -2;
    params_list.pop_front();
    
    //OUTPUT_FILE_STREAM
    std::string oname = params_list.front();
    ofs = std::ofstream{oname, std::ios_base::binary};
    if(!ofs) throw -3;
}

int main(int argc, char* argv[]){
    try{
        set_global_variables(argc, argv);
    }catch(std::invalid_argument e){
        std::cout << "Not a number argument!" << '\n';
        return -1;
    }catch(int e){
        std::string msg;

        switch(e){
            case  0: msg =  "Usage:\n"
                            "\tdes <key> <input_file_path> <output_file_path>\n"
                            "\t\t- where key is unsigned 64-bit integer\n"
                            "\tdes -d <key> <input_file_path> <output_file_path>\n";
                break;
            case -1: msg = "Invalid arguments!"; break;
            case -2: msg = "Input file not found!"; break;
            case -3: msg = "Output file could not be created!"; break;
            case -4: msg = "Invalid option parameter!"; break;
            default: msg = "WTF?";
        }

        std::cout << msg << '\n';
        return -1;
    }

    // DES::run_stream_cipher(::ifs, ::ofs, key);
    uint64_t input_block_64;
    while(ifs.read((char *)(&input_block_64), sizeof(uint64_t))){
        uint64_t output_block_64 = ::executeFn(input_block_64, key);
        ofs.write((char *)(&output_block_64), sizeof(uint64_t));
    }

    return 0;
}