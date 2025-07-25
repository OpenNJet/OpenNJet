# Copyright (C) 2008 Sun Microsystems, Inc.
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

IF(SKIP_TESTS)
  RETURN()
ENDIF()

ENABLE_TESTING()

IF(WIN32 AND DEFINED ENV{TRAVIS})
  SET(Python3_EXECUTABLE c:/python312/python.exe)
  SET(Python3_FOUND TRUE)
ELSE()
  # Always use highest version number
  set(Python3_FIND_STRATEGY VERSION)
  find_package (Python3 COMPONENTS Interpreter)
ENDIF()

INCLUDE_DIRECTORIES(${CC_SOURCE_DIR}/include
                    ${CC_BINARY_DIR}/include
                    ${CC_SOURCE_DIR}/unittest/mytap
                    ${CC_SOURCE_DIR}/unittest/libmariadb)
ADD_DEFINITIONS(-DLIBMARIADB)

SET(API_TESTS "bulk1" "performance" "basic-t" "fetch" "charset" "logs" "cursor" "errors" "view" "ps" "ps_bugs" "sp" "result" "connection" "misc" "ps_new" "thread" "features-10_2")

IF($ENV{TRAVIS})
  ADD_DEFINITIONS("-DHAVE_TRAVIS=1")
ENDIF()

IF(WITH_DYNCOL)
  SET(API_TESTS ${API_TESTS} "dyncol")
ENDIF()

IF(NOT WIN32)
  SET(API_TESTS ${API_TESTS} "async")
ENDIF()

#exclude following tests from ctests, since we need to run them manually with different credentials
SET(MANUAL_TESTS "t_conc173" "rpl_api" "conc336") 
# Get finger print from server certificate
IF(WITH_SSL)
  IF(CERT_PATH AND NOT DEFINED ENV{TRAVIS})
    SET(API_TESTS ${API_TESTS} "ssl")
    IF(WIN32)
      STRING(REPLACE "\\" "\\\\" CERT_PATH ${CERT_PATH})
    ENDIF()
    ADD_DEFINITIONS(-DCERT_PATH="${CERT_PATH}")
  ENDIF()
ENDIF()

ADD_LIBRARY(ma_getopt ma_getopt.c)

IF(${Python3_FOUND})
  execute_process(COMMAND ${Python3_EXECUTABLE} -m pip show pyopenssl
                  RESULT_VARIABLE EXIT_CODE
                  OUTPUT_QUIET)
  if (${EXIT_CODE} EQUAL 0)
    SET(RUN_TLS 1)
  endif()
ENDIF()

IF(${RUN_TLS})
  CONFIGURE_FILE(${CC_SOURCE_DIR}/unittest/libmariadb/tls.c.in
                 ${CC_BINARY_DIR}/unittest/libmariadb/tls.c)

  ADD_EXECUTABLE(tls ${CC_BINARY_DIR}/unittest/libmariadb/tls.c)
  TARGET_LINK_LIBRARIES(tls cctap ma_getopt mariadbclient)
  ADD_TEST(tls ${EXECUTABLE_OUTPUT_PATH}/tls)
ENDIF()

FOREACH(API_TEST ${API_TESTS})
  IF (NOT TARGET ${API_TEST})
    ADD_EXECUTABLE(${API_TEST} ${API_TEST}.c)
  ENDIF()
  TARGET_LINK_LIBRARIES(${API_TEST} cctap ma_getopt mariadbclient)
  ADD_TEST(${API_TEST} ${EXECUTABLE_OUTPUT_PATH}/${API_TEST})
  IF(${API_TEST} STREQUAL "cursor" OR ${API_TEST} STREQUAL "ps_new")
    SET_TESTS_PROPERTIES(${API_TEST} PROPERTIES TIMEOUT 360)
  ELSE()
    SET_TESTS_PROPERTIES(${API_TEST} PROPERTIES TIMEOUT 180)
  ENDIF()
ENDFOREACH(API_TEST)


FOREACH(API_TEST ${MANUAL_TESTS})
  ADD_EXECUTABLE(${API_TEST} ${API_TEST}.c)
  TARGET_LINK_LIBRARIES(${API_TEST} cctap ma_getopt mariadbclient)
ENDFOREACH()

SET(ADDITIONAL_FILES "tls_server.py" "certs/server-cert.pem"
                     "certs/server-cert.crl" "certs/server-key.pem" "certs/cacert.pem")
FOREACH(FILE ${ADDITIONAL_FILES})
  CONFIGURE_FILE(${CC_SOURCE_DIR}/unittest/libmariadb/${FILE}
                 ${CC_BINARY_DIR}/unittest/libmariadb/${FILE}
                 COPYONLY)
ENDFOREACH()

