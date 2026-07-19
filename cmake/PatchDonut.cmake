if(NOT DEFINED DONUT_SOURCE)
  message(FATAL_ERROR "DONUT_SOURCE is required")
endif()

file(READ "${DONUT_SOURCE}/format.c" DONUT_FORMAT_SOURCE)
set(DONUT_BUGGY_BLOCK [=[
        pic = realloc(pic, len+rem);
        memcpy(p + len, uuid_null, rem);
        len+=rem;
]=])
set(DONUT_FIXED_BLOCK [=[
        void *resized = realloc(pic, len+rem);
        if(resized == NULL) {
            return -1;
        }
        pic = resized;
        p = (uint8_t*)pic;
        memcpy(p + len, uuid_null, rem);
        len+=rem;
]=])

string(FIND "${DONUT_FORMAT_SOURCE}" "${DONUT_BUGGY_BLOCK}" DONUT_BUG_LOCATION)
if(DONUT_BUG_LOCATION EQUAL -1)
  string(FIND "${DONUT_FORMAT_SOURCE}" "${DONUT_FIXED_BLOCK}" DONUT_FIXED_LOCATION)
  if(DONUT_FIXED_LOCATION EQUAL -1)
    message(FATAL_ERROR "Donut format.c does not match the reviewed source contract")
  endif()
else()
  string(REPLACE "${DONUT_BUGGY_BLOCK}" "${DONUT_FIXED_BLOCK}" DONUT_FORMAT_SOURCE "${DONUT_FORMAT_SOURCE}")
  file(WRITE "${DONUT_SOURCE}/format.c" "${DONUT_FORMAT_SOURCE}")
endif()

