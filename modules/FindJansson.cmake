# - Find jansson
# Find the native Jansson includes and library
#
#  JANSSON_INCLUDE_DIR - where to find mysql.h, etc.
#  JANSSON_LIBRARIES   - List of libraries when using Jansson.
#  JANSSON_FOUND       - True if Jansson found.

IF (JANSSON_INCLUDE_DIR)
  # Already in cache, be silent
  SET(JANSSON_FIND_QUIETLY TRUE)
ENDIF (JANSSON_INCLUDE_DIR)

FIND_PATH(JANSSON_INCLUDE_DIR jansson.h
  /usr/local/include
  /usr/include
)

SET(JANSSON_NAMES jansson)
FIND_LIBRARY(JANSSON_LIBRARY
  NAMES ${JANSSON_NAMES}
  PATHS /usr/lib /usr/local/lib
  PATH_SUFFIXES jansson
)

IF (JANSSON_INCLUDE_DIR AND JANSSON_LIBRARY)
  SET(JANSSON_FOUND TRUE)
  SET( JANSSON_LIBRARIES ${JANSSON_LIBRARY} )
ELSE (JANSSON_INCLUDE_DIR AND JANSSON_LIBRARY)
  SET(JANSSON_FOUND FALSE)
  SET( JANSSON_LIBRARIES )
ENDIF (JANSSON_INCLUDE_DIR AND JANSSON_LIBRARY)

IF (JANSSON_FOUND)
  IF (NOT JANSSON_FIND_QUIETLY)
    MESSAGE(STATUS "Found Jansson: ${JANSSON_LIBRARY}")
  ENDIF (NOT JANSSON_FIND_QUIETLY)
ELSE (JANSSON_FOUND)
  IF (JANSSON_FIND_REQUIRED)
    MESSAGE(STATUS "Looked for Jansson libraries named ${JANSSON_NAMES}.")
    MESSAGE(FATAL_ERROR "Could NOT find Jansson library")
  ENDIF (JANSSON_FIND_REQUIRED)
ENDIF (JANSSON_FOUND)

MARK_AS_ADVANCED(
  JANSSON_FOUND
  JANSSON_LIBRARY
  JANSSON_INCLUDE_DIR
  )