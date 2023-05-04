cmake_minimum_required(VERSION 3.5)

set(PATCH_VERSION "1" CACHE INTERNAL "Patch version")
set(PROJECT_VESRION 0.0.${PATCH_VERSION})
project(bayan VERSION ${PROJECT_VESRION})

set(Boost_ARCHITECTURE -x64)

set(Boost_USE_STATIC_LIBS   ON)

if(WIN32)
        find_package(Boost COMPONENTS program_options filesystem REQUIRED)
else()
        find_package(Boost COMPONENTS program_options filesystem regex REQUIRED)
endif()

include_directories(${Boost_INCLUDE_DIR})

set(CMAKE_CXX_STANDARD 17)

add_executable(bayan bayan.cpp fileslist.cpp)

target_link_libraries(bayan
        ${Boost_LIBRARIES}
        )

install(TARGETS bayan RUNTIME DESTINATION bin)

set(CPACK_GENERATOR DEB)
set(CPACK_PACKAGE_VERSION_MAJOR "${PROJECT_VERSION_MAJOR}")
set(CPACK_PACKAGE_VERSION_MINOR "${PROJECT_VERSION_MINOR}")
set(CPACK_PACKAGE_VERSION_PATCH "${PROJECT_VERSION_PATCH}")
set(CPACK_PACKAGE_CONTACT vovchek@inbox.ru)      
include(CPack)
       