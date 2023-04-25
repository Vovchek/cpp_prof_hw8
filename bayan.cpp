/**
 * @file bayan.cpp
 * @brief command batches processor. Detects bulks and writes them both to cout and files.
 * @author Vladimir Chekal
 * @date April 2023

 * @mainpage Otus C++ Professional Homework #8 'bayan'

 * @anchor _condition
 *
Условие
-------
Пользуясь имеющимися в библиотеке Boost структурами и алгоритмами
разработать утилиту для обнаружения файлов-дубликатов.
Утилита должна иметь возможность через параметры командной строки
указывать:\n
    + директории для сканирования (может быть несколько).
    + директории для исключения из сканирования (может быть несколько).
    + уровень сканирования (один на все директории, 0 - только указанная
директория без вложенных).
    + минимальный размер файла, по умолчанию проверяются все файлы
больше 1 байта.
    + маски имен файлов разрешенных для сравнения (не зависят от
регистра).
    + размер блока, которым производится чтения файлов, в задании этот
размер упоминается как S.
    + один из имеющихся алгоритмов хэширования (crc32, md5 -
конкретные варианты определить самостоятельно), в задании
эта функция упоминается как H.

Результатом работы утилиты должен быть список полных путей файлов
с идентичным содержимым, выводимый на стандартный вывод. На одной
строке один файл. Идентичные файлы должны подряд, одной группой.
Разные группы разделяются пустой строкой.
Обязательно свойство утилиты - бережное обращение с дисковым вводом
выводом. Каждый файл может быть представлен в виде списка блоков
размера S. Если размер файла не кратен, он дополняется бинарными
нулями.\n

 * @anchor _example
Файл world.txt из одной строки
Hello, World\n
При размере блока в 5 байт, будет представлен как
Hello
, Wor
ld\n\0\0
Каждый блок должен быть свернут выбранной функцией хэширования.
Возможные коллизии игнорируются. Из предположения, что
H("Hello") == A
H(", Wor") == B
H("ld\n\0\0") == C
1
Наш файл world.txt может быть представлен в виде последовательности
ABC
Рассмотрим второй файл cpp.txt
Hello, C++\n
Который после хэширования блоков
H("Hello") == A
H(", C++") == D
H("\n\0\0\0\0") == E
может быть представлен в виде последовательности ADE
Порядок сравнения этих файлов должен быть максимально бережным. То
есть обработка первого файла world.txt вообще не приводит к чтению с
диска, ведь нам еще не с чем сравнивать. Как только мы добираемся до
файла cpp.txt только в этот момент происходит перое чтение первого блока
обоих файлов. В данном случае блоки идентичны, и необходимо прочесть
вторые блоки, которые уже различаются. Файлы различны, оставшиеся
данные не читаются.
Файлы считаются идентичными при полном совпадении последовательности
хешей блоков.\n

* @anchor _self_checks
Самоконтроль
------------
    + блок файла читается с диска не более одного раза
    + блок файла читается только в случае необходимости
    + не забыть, что дубликатов может быть больше чем два
    + пакет bayan содержащий исполняемый файл bayan опубликован на
bintray
    + описание параметров в файле README.md корне репозитория
    + отправлена на проверку ссылка на страницу репозитория

* @anchor _checks
Проверка
--------
Задание считается выполнено успешно, если после просмотра кода,
подключения репозитория, установки пакета и запуска бинарного файла
командой (параметры из описания):
$ bayan [...]
будут обнаружены файлы-дубликаты, без ложных срабатываний и
пропуска существующих дубликатов.
Количество прочитанных данных с диска минимально.
*/

// program_options
// crc
//

#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <boost/regex.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/variant.hpp>
#include <boost/crc.hpp>
#include <boost/uuid/detail/md5.hpp>
#include <boost/uuid/detail/sha1.hpp>
#include <boost/optional.hpp>
#include <boost/algorithm/hex.hpp>

#include <iostream>
#include <fstream>
#include <list>
#include <string>
#include <unordered_set>
#include <memory>
#include <sstream>
#include <iomanip>


namespace opt = boost::program_options;
namespace fs = boost::filesystem;
using md5 = boost::uuids::detail::md5;
using crc = boost::crc_32_type;
using sha1 = boost::uuids::detail::sha1;

/// @brief Converts file mask, containing wildcards to regular expression
/// @param mask [in] - std::string, passed as a program --mask parameter
/// @return std::string containing regular expression that may be used
/// to filter file names with  boost::regex_match()
/// @details Removes single quoutes ('), adds escape slash \ to all chars that
/// may occure in file name but have special meaning to regex, converts wildecards * and ?
/// that were escaped in a command line with slash \ to equalent regex wildcards . and .*
std::string wildcard_to_regex(const std::string &mask)
{
    std::string rx {mask};
    const char *srch[] {"\'", "\\", "^", ".", "$", "|", "(", ")", "{", "}", "[", "]", "*", "+", "?", "/", "\\?", "\\*"};
    const char *fmt[] {"", "\\\\", "\\^", "\\.", "\\$", "\\|", "\\(", "\\)", "\\{", "\\}", "\\[", "\\]", "\\*", "\\+", "\\?", "\\/", ".", ".*"};
    for(int i = 0; i < sizeof(srch)/sizeof(srch[0]); ++i) {
        boost::replace_all(rx, srch[i], fmt[i]);
    }

    return rx;
}

using hash_type = std::vector<uint8_t>;

template <typename Algo>
hash_type str_hash(const char *buffer, size_t buffer_size)
{
    Algo boost_hash;
    boost_hash.process_bytes(buffer, buffer_size);
    hash_type digest(sizeof(typename Algo::digest_type));
    boost_hash.get_digest(reinterpret_cast<typename Algo::digest_type &>(digest[0]));
    //typename Algo::digest_type dg;
    //boost_hash.get_digest(dg);
    return digest;
}

template <typename Algo>
void get_hash(hash_type& digest, const char *buffer, size_t buffer_size)
{
    Algo boost_hash;
    boost_hash.process_bytes(buffer, buffer_size);
    //hash_type digest(sizeof(typename Algo::digest_type));
    boost_hash.get_digest(reinterpret_cast<typename Algo::digest_type &>(digest[0]));
}


class FileStruct {
public:
    enum class HashAlgorithm {crc32, md5, sha1};
    static inline  HashAlgorithm ha{HashAlgorithm::md5};
    static inline size_t block_size{128};
    std::string path;

private:
    std::ifstream ifs;
    size_t blocks_total{0};
    size_t cur_block{0};
    std::unique_ptr<char> block_buf;

    std::vector<hash_type> hash_vec;

public:
    FileStruct(std::string path_, size_t file_size_) : path{path_} {
        blocks_total = (file_size_ - 1) / block_size + 1; // round up
    }

    void reset() {
        cur_block = 0;
    }
    boost::optional<hash_type &> H() {
        boost::optional<hash_type& > retval{};
        if(cur_block >= hash_vec.size() && cur_block < blocks_total) { // read next block from file and calculate hash
            try {
                if(!ifs.is_open()) {
                    ifs.open(path, std::ios_base::binary);
                    block_buf = std::make_unique<char>(block_size);
                    hash_vec.reserve(blocks_total);
                }
                ifs.read(block_buf.get(), block_size);
                if(ifs.gcount() < block_size)
                    std::fill_n(block_buf.get()+ifs.gcount(), block_size-ifs.gcount(), 0);
                switch(ha) {
                    case HashAlgorithm::md5:
                    {
                        //hash_vec.emplace_back(str_hash<md5>(block_buf.get(), block_size));
                        hash_type dig(sizeof(typename md5::digest_type));
                        //get_hash<md5>(dig, block_buf.get(), block_size);
                        hash_vec.push_back(dig);
                    }
                        break;
                    case HashAlgorithm::sha1:
                        hash_vec.emplace_back(str_hash<sha1>(block_buf.get(), block_size));
                        break;
                    case HashAlgorithm::crc32:
                    default:
                        std::cout << "Catastropha!!!\n";
                        assert(0);
                        break;
                }

            } catch(const std::ifstream::failure& e) {
                std::cout << "dmmned: " << e.what() << std::endl;               
                return retval;
            }
        } // read from file & calc hash
        if(hash_vec.size() > cur_block) { // block already loaded, hash was calculated
            retval = hash_vec[cur_block++];
        }
        return retval;
    }

    std::string &operator ()()
    {
        return path;
    }

}; // class FileStruct

class FilesListBuilder;

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
        std::cout << wildcard_to_regex(m) << '\n';
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

bool equal_files(FileStruct &file1, FileStruct &file2)
{
    std::cout << file1.path << " & " << file2.path << '\n';
    file1.reset();
    file2.reset();

    return true;

    boost::optional<hash_type> h1, h2;
    do {
        h1 = file1.H();
        h2 = file2.H();

    std::cout << "h1 : ";
    if(h1) std::cout << std::hex << +(*h1)[0] << +(*h1)[1]<< +(*h1)[2]<< +(*h1)[3];
    else std::cout << "false";
    std::cout << " <=> h2 : ";
    if(h2) std::cout << std::hex << +(*h2)[0] << +(*h2)[1]<< +(*h2)[2]<< +(*h2)[3] << std::endl;
    else std::cout << "false" << std::endl;

        if(h1 != h2)
            return false;
    } while(h1 && h2);
    return true;
}


int main(int argc, char *argv[])
{

    opt::options_description desc("Allowed options");

    desc.add_options()
        ("help,h", "produce help message")
        ("mask,m", opt::value<std::string>()->default_value("'*.*'"), "files mask, must be single-quoted")
        ("size,s", opt::value<size_t>()->default_value(1), "minimum file size")
        ("exclude,x", opt::value<std::vector<std::string>>()->default_value({""}, ""), "directories to exclude")
        ("path,p", opt::value<std::vector<std::string>>()->default_value({"."}, "."), "directories to scan")
        ("recurse-level,r", opt::value<int>()->default_value(0),"recursion level for subdirectories scan, 0 = no recursion, -1 = unlimited")
        ("block,b", opt::value<size_t>()->default_value(256), "block size in bytes to read by")
        ("hash", opt::value<std::string>()->default_value("md5"), "hash function to use - md5, sha1 or crc32")
    ;

    opt::positional_options_description po;
    po.add("path", -1);

    opt::variables_map vm;

    try {
        // Parsing command line options and storing values to 'vm'
        opt::store(opt::command_line_parser(argc, argv).options(desc).positional(po).run(), vm);
    } catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    if (vm.count("help")) {
        std::cout << desc << "\n";
        return 1;
    }

    opt::notify(vm);

    FilesListBuilder builder;
    FilesList &fl = builder.add_path(vm["path"].as<std::vector<std::string>>())
                            .exclude(vm["exclude"].as<std::vector<std::string>>())
                            .recurse(vm["recurse-level"].as<int>())
                            .set_mask(vm["mask"].as<std::string>())
                            .set_size(vm["size"].as<size_t>())
                            .set_block_size(vm["block"].as<size_t>())
                            .set_hash(vm["hash"].as<std::string>())
                            .build();

    while(!fl().empty()) {
        auto samp_it = fl().begin(), it = samp_it;
        size_t matches{0};

        for(++it; it != fl().end();) {
            if(equal_files(*samp_it, *it)) {
                if(!matches++)
                    std::cout << samp_it->path << '\n';
                std::cout << it->path << '\n';
                it = fl().erase(it);
            } else ++it;
        }
        if(matches != 0 && !fl().empty())
            std::cout << '\n';
        fl().erase(samp_it);
    }

} /*main*/
