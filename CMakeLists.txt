cmake_minimum_required(VERSION 3.5)
project(bayan_proj)

set(Boost_ARCHITECTURE -x64)

find_package(Boost COMPONENTS program_options filesystem regex REQUIRED)
#find_package(Boost COMPONENTS unit_test_framework REQUIRED)

include_directories(${Boost_INCLUDE_DIR})

set(CMAKE_CXX_STANDARD 17)

add_executable(bayan bayan.cpp fileslist.cpp)

target_link_libraries(bayan
        ${Boost_LIBRARIES}
        )

set_target_properties(bayan PROPERTIES
       COMPILE_DEFINITIONS BOOST_REGEX_DYN_LINK
       )

install(TARGETS bayan RUNTIME DESTINATION bin)

set(CPACK_GENERATOR DEB)
set(CPACK_PACKAGE_VERSION_MAJOR "${PROJECT_VERSION_MAJOR}")
set(CPACK_PACKAGE_VERSION_MINOR "${PROJECT_VERSION_MINOR}")
set(CPACK_PACKAGE_VERSION_PATCH "${PROJECT_VERSION_PATCH}")
set(CPACK_PACKAGE_CONTACT vovchek@inbox.ru)      
include(CPack)
       