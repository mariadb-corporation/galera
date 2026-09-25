#
SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Galera: a synchronous multi-master wsrep provider (replication engine)")
SET(CPACK_PACKAGE_DESCRIPTION "Galera is a fast synchronous multimaster wsrep provider (replication engine)
for transactional databases and similar applications. For more information
about wsrep API see https://github.com/codership/wsrep-API. For a description
of Galera replication engine see https://www.galeracluster.com.

Copyright 2007-2020 Codership Oy. All rights reserved. Use is subject to license terms under GPLv2 license.

This software comes with ABSOLUTELY NO WARRANTY. This is free software,
and you are welcome to modify and redistribute it under the GPLv2 license.")
SET(CPACK_PACKAGE_VERSION ${GALERA_VERSION_WSREP_API}.${GALERA_VERSION_MAJOR}.${GALERA_VERSION_MINOR})
SET(CPACK_PACKAGE_URL "http://mariadb.org")
SET(CPACK_PACKAGE_CONTACT "MariaDB Developers <developers@lists.mariadb.org>")
SET(CPACK_PACKAGE_VENDOR "MariaDB Foundation")
SET(CPACK_COMPONENTS_ALL "galera")
SET(CMAKE_INSTALL_DEFAULT_COMPONENT_NAME "galera")
#

if ("${GALERA_VERSION_EXTRA}" STREQUAL "")
   SET(GALERA_VERSION_FULL "${GALERA_VERSION_WSREP_API}.${GALERA_VERSION_MAJOR}.${GALERA_VERSION_MINOR}")
else()
   SET(GALERA_VERSION_FULL "${GALERA_VERSION_WSREP_API}.${GALERA_VERSION_MAJOR}.${GALERA_VERSION_MINOR}-${GALERA_VERSION_EXTRA}")
endif()

IF(NOT EXISTS ${CMAKE_SOURCE_DIR}/debian/changelog)
  EXECUTE_PROCESS(COMMAND date -R OUTPUT_VARIABLE BUILDDATE OUTPUT_STRIP_TRAILING_WHITESPACE)
  CONFIGURE_FILE(${CMAKE_SOURCE_DIR}/debian/changelog.in ${CMAKE_SOURCE_DIR}/debian/changelog @ONLY)
ENDIF()
