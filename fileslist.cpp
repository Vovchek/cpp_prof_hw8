#include "fileslist.h"

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

template <typename Algo>
hash_type str_hash(const char *buffer, size_t buffer_size)
{
    Algo boost_hash;
    boost_hash.process_bytes(buffer, buffer_size);
    hash_type digest{sizeof(typename Algo::digest_type)};
    boost_hash.get_digest(reinterpret_cast<typename Algo::digest_type &>(digest[0]));
    return digest;
}

bool equal_files(FileStruct &file1, FileStruct &file2)
{
    if(file1.size() != file2.size())
        return false;

    file1.reset();
    file2.reset();

    boost::optional<hash_type> h1, h2;
    do {
        h1 = file1.hash();
        h2 = file2.hash();
        if(h1 != h2)
            return false;
    } while(h1 && h2);
    return true;
}
