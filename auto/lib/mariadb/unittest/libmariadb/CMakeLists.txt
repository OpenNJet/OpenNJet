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


INCLUDE_DIRECTORIES(${CC_SOURCE_DIR}/include
                    ${CC_BINARY_DIR}/include
                    ${CC_SOURCE_DIR}/unittest/mytap
                    ${CC_SOURCE_DIR}/unittest/libmariadb)
ADD_DEFINITIONS(-DLIBMARIADB)

SET(API_TESTS "conc336" "bulk1" "performance" "basic-t" "fetch" "charset" "logs" "cursor" "errors" "view" "ps" "ps_bugs" "sp" "result" "connection" "misc" "ps_new" "thread" "features-10_2")
IF(WITH_DYNCOL)
  SET(API_TESTS ${API_TESTS} "dyncol")
ENDIF()

SET(API_TESTS ${API_TESTS} "async")

#exclude following tests from ctests, since we need to run them maually with different credentials
SET(MANUAL_TESTS "t_conc173" "rpl_api")
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
