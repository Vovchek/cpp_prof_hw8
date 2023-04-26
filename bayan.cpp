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

#include "fileslist.h"
#include <boost/program_options.hpp>

namespace opt = boost::program_options;

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
        ("block,b", opt::value<size_t>()->default_value(128), "block size in bytes to read by")
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
        size_t count{0};

        for(++it; it != fl().end();) {
            ++count;
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
