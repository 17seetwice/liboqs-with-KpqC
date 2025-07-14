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

if(OQS_ENABLE_SIG_aimer_128f_ref)
  add_library(aimer_128f_ref OBJECT
    sig_aimer_128f_ref.c
    aimer_128f_ref/aim2.c
    aimer_128f_ref/field.c
    aimer_128f_ref/hash.c
    aimer_128f_ref/sign.c
    aimer_128f_ref/tree.c
  )
  target_include_directories(aimer_128f_ref PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/aimer_128f_ref
    ${CMAKE_CURRENT_LIST_DIR}/common
  )
  list(APPEND _AIMER_OBJS $<TARGET_OBJECTS:aimer_128f_ref>)
endif()

if(OQS_ENABLE_SIG_aimer_192f_ref)
  add_library(aimer_192f_ref OBJECT
    sig_aimer_192f_ref.c
    aimer_192f_ref/aim2.c
    aimer_192f_ref/field.c
    aimer_192f_ref/hash.c
    aimer_192f_ref/sign.c
    aimer_192f_ref/tree.c
  )
  target_include_directories(aimer_192f_ref PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/aimer_192f_ref
    ${CMAKE_CURRENT_LIST_DIR}/common
  )
  list(APPEND _AIMER_OBJS $<TARGET_OBJECTS:aimer_192f_ref>)
endif()

list(APPEND _AIMER_OBJS $<TARGET_OBJECTS:aimer_common>)

set(AIMER_OBJS ${_AIMER_OBJS} PARENT_SCOPE)
