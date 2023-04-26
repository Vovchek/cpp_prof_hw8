Bayan.exe searches for files duplicates within specified directories.
Files are compared by size first, then, if sizes match, by content.
File contents are fetched by blocks of size specified by --block option.
Hash function as per --hash option is used to pack blocks before comparing.

The allowed options are:
  -h [ --help ]                   produce help message
  -m [ --mask ] arg (='*.*')      files mask, must be single-quoted
  -s [ --size ] arg (=1)          minimum file size
  -x [ --exclude ] arg            directories to exclude
  -p [ --path ] arg (=.)          directories to scan
  -r [ --recurse-level ] arg (=0) recursion level for subdirectories scan, 0 =
                                  no recursion, -1 = unlimited
  -b [ --block ] arg (=128)       block size in bytes to read by
  --hash arg (=md5)               hash function to use - md5, sha1 or crc32

===========================================================================
problems, questions and todos:
- how to compose unit tests? what to test?
- localized charsets are displayed incorrectly, at least Unicode Cyrylic on Windows
- raw pointer used for buffer is not exception-safe, should use smart pointer instead
- code is not documented properly yet...
- is bintray still alive?
- how to use launch.json with VS Code to pass the parameters while debugging?
  I've created launch.json but it has no effect.