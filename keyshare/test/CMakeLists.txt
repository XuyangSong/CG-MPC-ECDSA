cmake_minimum_required(VERSION 3.10)
project(test)

if("${KEYSHARE_DIR}" STREQUAL "")
  message(FATAL_ERROR "please define KEYSHARE_DIR")
else()
  message("using keyshare lib dir: " ${KEYSHARE_DIR})
endif()

find_library(GMP_LIBRARIES NAMES gmp libgmp)
find_library(GMPXX_LIBRARIES NAMES gmpxx libgmpxx)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -Wextra -Wfatal-errors")

add_executable(key_share_test key_share_test.cpp)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
  target_link_libraries(key_share_test ${KEYSHARE_DIR}/libkeyshare.a pthread dl ${GMP_LIBRARIES} ${GMPXX_LIBRARIES})
elseif(CMAKE_SYSTEM_NAME MATCHES "Darwin")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -framework Security")
  target_link_libraries(key_share_test ${KEYSHARE_DIR}/libkeyshare.a ${GMP_LIBRARIES} ${GMPXX_LIBRARIES})
else()
  target_link_libraries(key_share_test ${KEYSHARE_DIR}/libkeyshare.a ${GMP_LIBRARIES} ${GMPXX_LIBRARIES})
endif()