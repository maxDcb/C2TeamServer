if(NOT DEFINED DONUT_APLIB_ARCHIVE OR NOT EXISTS "${DONUT_APLIB_ARCHIVE}")
  message(FATAL_ERROR "DONUT_APLIB_ARCHIVE is missing")
endif()
if(NOT DEFINED C2_OBJCOPY)
  message(FATAL_ERROR "C2_OBJCOPY is required")
endif()

get_filename_component(ARCHIVE_DIRECTORY "${DONUT_APLIB_ARCHIVE}" DIRECTORY)
set(EMPTY_NOTE "${ARCHIVE_DIRECTORY}/empty-gnu-stack-note")
set(HARDENED_ARCHIVE "${DONUT_APLIB_ARCHIVE}.hardened")
file(WRITE "${EMPTY_NOTE}" "")
execute_process(
  COMMAND "${C2_OBJCOPY}"
    --add-section .note.GNU-stack=${EMPTY_NOTE}
    --set-section-flags .note.GNU-stack=noload,readonly
    "${DONUT_APLIB_ARCHIVE}" "${HARDENED_ARCHIVE}"
  COMMAND_ERROR_IS_FATAL ANY)
file(RENAME "${HARDENED_ARCHIVE}" "${DONUT_APLIB_ARCHIVE}")
file(REMOVE "${EMPTY_NOTE}")
