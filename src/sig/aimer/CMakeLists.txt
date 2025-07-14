# SPDX-License-Identifier: MIT

set(_AIMER_OBJS "")

add_library(aimer_common OBJECT
  common/aes.c
  common/fips202.c
  common/rng.c
)

target_include_directories(aimer_common PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/common
)

if(OQS_ENABLE_SIG_aimer_128f)
  add_library(aimer_128f OBJECT
    sig_aimer_128f.c
    aimer_128f/aim2.c
    aimer_128f/field.c
    aimer_128f/hash.c
    aimer_128f/sign.c
    aimer_128f/tree.c
  )
  target_include_directories(aimer_128f PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/aimer_128f
    ${CMAKE_CURRENT_LIST_DIR}/common
  )
  list(APPEND _AIMER_OBJS $<TARGET_OBJECTS:aimer_128f>)
endif()

if(OQS_ENABLE_SIG_aimer_192f)
  add_library(aimer_192f OBJECT
    sig_aimer_192f.c
    aimer_192f/aim2.c
    aimer_192f/field.c
    aimer_192f/hash.c
    aimer_192f/sign.c
    aimer_192f/tree.c
  )
  target_include_directories(aimer_192f PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/aimer_192f
    ${CMAKE_CURRENT_LIST_DIR}/common
  )
  list(APPEND _AIMER_OBJS $<TARGET_OBJECTS:aimer_192f>)
endif()

if(OQS_ENABLE_SIG_aimer_256f)
  add_library(aimer_256f OBJECT
    sig_aimer_256f.c
    aimer_256f/aim2.c
    aimer_256f/field.c
    aimer_256f/hash.c
    aimer_256f/sign.c
    aimer_256f/tree.c
  )
  target_include_directories(aimer_256f PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/aimer_256f
    ${CMAKE_CURRENT_LIST_DIR}/common
  )
  list(APPEND _AIMER_OBJS $<TARGET_OBJECTS:aimer_256f>)
endif()

if(OQS_ENABLE_SIG_aimer_128s)
  add_library(aimer_128s OBJECT
    sig_aimer_128s.c
    aimer_128s/aim2.c
    aimer_128s/field.c
    aimer_128s/hash.c
    aimer_128s/sign.c
    aimer_128s/tree.c
  )
  target_include_directories(aimer_128s PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/aimer_128s
    ${CMAKE_CURRENT_LIST_DIR}/common
  )
  list(APPEND _AIMER_OBJS $<TARGET_OBJECTS:aimer_128s>)
endif()

if(OQS_ENABLE_SIG_aimer_192s)
  add_library(aimer_192s OBJECT
    sig_aimer_192s.c
    aimer_192s/aim2.c
    aimer_192s/field.c
    aimer_192s/hash.c
    aimer_192s/sign.c
    aimer_192s/tree.c
  )
  target_include_directories(aimer_192s PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/aimer_192s
    ${CMAKE_CURRENT_LIST_DIR}/common

  )
  list(APPEND _AIMER_OBJS $<TARGET_OBJECTS:aimer_192s>)
endif()

if(OQS_ENABLE_SIG_aimer_256s)
  add_library(aimer_256s OBJECT
    sig_aimer_256s.c
    aimer_256s/aim2.c
    aimer_256s/field.c
    aimer_256s/hash.c
    aimer_256s/sign.c
    aimer_256s/tree.c
  )
  target_include_directories(aimer_256s PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/aimer_256s
    ${CMAKE_CURRENT_LIST_DIR}/common

  )
  list(APPEND _AIMER_OBJS $<TARGET_OBJECTS:aimer_256s>)
endif()

list(APPEND _AIMER_OBJS $<TARGET_OBJECTS:aimer_common>)

set(AIMER_OBJS ${_AIMER_OBJS} PARENT_SCOPE)
