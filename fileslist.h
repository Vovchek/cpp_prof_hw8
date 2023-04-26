#pragma once

#include <boost/filesystem.hpp>
#include <boost/regex.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/variant.hpp>
#include <boost/crc.hpp>
#include <boost/uuid/detail/md5.hpp>
#include <boost/uuid/detail/sha1.hpp>
#include <boost/optional.hpp>

#include <iostream>
#include <fstream>
#include <list>
#include <string>
#include <unordered_set>
#include <memory>
#include <iomanip>

class FileStruct;
class FileList;
class FileListBuilder;

std::string wildcard_to_regex(const std::string &mask);

namespace fs = boost::filesystem;
using md5 = boost::uuids::detail::md5;
using crc = boost::crc_32_type;
using sha1 = boost::uuids::detail::sha1;
using hash_type = std::string;

template <typename Algo>
hash_type str_hash(const char *buffer, size_t buffer_size);

bool equal_files(FileStruct &file1, FileStruct &file2);

class FileStruct {
public:
    enum class HashAlgorithm {crc32, md5, sha1};
    static inline  HashAlgorithm ha{HashAlgorithm::md5};
    static inline size_t block_size{128};

private:
    std::string path;
    std::ifstream ifs;
    size_t file_size{0};
    size_t blocks_total() {return (file_size - 1) / block_size + 1;}
    size_t cur_block{0};
    //std::unique_ptr<char> block_buf; // i have to review how to use it
    char *block_buf{nullptr};
    std::vector<hash_type> hash_vec;

public:
    FileStruct(std::string path_, size_t file_size_) : path{path_}, file_size{file_size_} {}
    FileStruct(const FileStruct&) = default;
    FileStruct(FileStruct&&) = default;
    ~FileStruct() {
        delete[] block_buf;
    }
    std::string& get_path() {return path;}
    size_t size() {return file_size;}
    void reset() {
        cur_block = 0;
    }
    boost::optional<hash_type &> hash() {
        boost::optional<hash_type& > retval{};
        if(cur_block >= hash_vec.size() && cur_block < blocks_total()) { // read next block from file and calculate hash
            try {
                if(!ifs.is_open()) {
                    ifs.open(path, std::ios_base::binary);
                    block_buf = new char[block_size];
                    hash_vec.reserve(blocks_total());
                }

                ifs.read(block_buf, block_size);
                if(ifs.eof())
                    ifs.close();
                if(ifs.gcount() < block_size)
                    std::fill_n(block_buf+ifs.gcount(), block_size-ifs.gcount(), 0);

                switch(ha) {
                    case HashAlgorithm::md5:
                        hash_vec.emplace_back(str_hash<md5>(block_buf, block_size));
                        break;
                    case HashAlgorithm::sha1:
                        hash_vec.emplace_back(str_hash<sha1>(block_buf, block_size));
                        break;
                    case HashAlgorithm::crc32:
                    default:
                        std::cout << "Catastropha!!!\n";
                        assert(0);
                        break;
                }

            } catch(const std::exception& e) {
                std::cout << "Error: " << e.what() << std::endl;
                return retval;
            }
        } // read from file & calc hash
        if(hash_vec.size() > cur_block) { // block already loaded, hash was calculated
            retval = hash_vec[cur_block++];
        }
        return retval;
    }

}; // class FileStruct

class FilesList {
    friend class FilesListBuilder;

    std::list<FileStruct> files;

    boost::regex mask;
    std::unordered_set<std::string> scan_dirs;// {".\\"};
    std::unordered_set<std::string> excl_dirs;// {""};
    int recurse {0};
    size_t min_size{1};

public:
    bool mask_match(const std::string &fn) {
        return boost::regex_match(fn, mask);
    }

    void build() {
        for(auto &d : scan_dirs)
            add_files(d);
    }

    void add_file(const fs::directory_entry &entry) {
        const fs::path p = entry.path();
        const auto full_path  = fs::canonical(p).string();
        const auto fn = p.filename().string();

        if(fs::is_regular_file(p) && mask_match(fn) && fs::file_size(p) >= min_size)
            files.emplace_back(FileStruct{full_path, fs::file_size(p)});
    }

    void add_files(const std::string &root) {
        if(recurse) {
            auto directory {fs::recursive_directory_iterator(root, fs::directory_options::skip_permission_denied)};

            for(auto &entry : directory) {
                auto level = directory.depth();
                auto rp = directory.recursion_pending();
                if(recurse >= 0 && level >= recurse && rp) {
                    directory.disable_recursion_pending();
                }
                add_file(entry);

            }
        } else {
            for(auto &entry : fs::directory_iterator(root, fs::directory_options::skip_permission_denied))
                add_file(entry);
        }

    } // add_files()

    std::list<FileStruct> &operator ()()
    {
        return files;
    }

};

class FilesListBuilder {
public:
    FilesListBuilder &add_path(const std::string &dir) {
        fs::path p(dir);
        if(fs::exists(p) && fs::is_directory(p))
            fl.scan_dirs.insert(dir);
        else
            std::cout << "Warning: directory \"" << dir << "\" does not exist\n";
        return *this;
    }
    FilesListBuilder &add_path(const std::vector<std::string> &dirs) {
        for(auto &d : dirs) {
            add_path(d);
        }
        return *this;
    }
    FilesListBuilder &exclude(const std::string &dir) {
        fs::path p(dir);
        if(fs::exists(p))
            fl.excl_dirs.insert(dir);
        return *this;
    }
    FilesListBuilder &exclude(const std::vector<std::string> &arg) {
        for(auto &p : arg) {
            exclude(p);
        }
        return *this;
    }
    FilesListBuilder &recurse(int r) {
        fl.recurse = r;
        return *this;
    }
    FilesListBuilder &set_mask(const std::string &m) {
        fl.mask = boost::regex(wildcard_to_regex(m), boost::regex_constants::icase);
        return *this;
    }
    FilesListBuilder &set_size(size_t sz) {
        fl.min_size = sz;
        return *this;
    }
    FilesListBuilder &set_block_size(size_t sz) {
        FileStruct::block_size = sz;
        return *this;
    }
    FilesListBuilder &set_hash(const std::string &algo) {
        if(algo == "md5")
            FileStruct::ha = FileStruct::HashAlgorithm::md5;
        else if(algo == "sha1")
            FileStruct::ha = FileStruct::HashAlgorithm::sha1;
        else if(algo == "crc32")
            FileStruct::ha = FileStruct::HashAlgorithm::crc32;
        return *this;
    }

    FilesList &build() {
        fl.build();
        return fl;
    }
private:
    FilesList fl;
};

