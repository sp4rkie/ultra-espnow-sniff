idf_component_register(
    SRCS "ultra_espnow_sniff.c"
    INCLUDE_DIRS "."
)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} $ENV{OPTS_}")

message("-------------------------------------------------------------vvv-------------------------------------------------------------")
message("${CMAKE_C_FLAGS}")
message("-------------------------------------------------------------^^^-------------------------------------------------------------")

#
# buildit rebuilds OPTS_ for itself on the idf.py line, so the collector address cannot
# ride in there. take it from the environment instead, which buildit passes through:
#
#   export SNIFF_COLLECTOR=a.b.c.d      (see buildit.cfg)
#
if(DEFINED ENV{SNIFF_COLLECTOR})
    target_compile_definitions(${COMPONENT_LIB} PRIVATE SNIFF_COLLECTOR="$ENV{SNIFF_COLLECTOR}")
    message("SNIFF_COLLECTOR=$ENV{SNIFF_COLLECTOR}  (ethernet/TCP transport)")
endif()

if(DEFINED ENV{SNIFF_OTA_URL})
    target_compile_definitions(${COMPONENT_LIB} PRIVATE SNIFF_OTA_URL="$ENV{SNIFF_OTA_URL}")
    message("SNIFF_OTA_URL is set          (OTA over ethernet enabled)")
endif()

if(DEFINED ENV{SNIFF_NTP} AND NOT "$ENV{SNIFF_NTP}" STREQUAL "")
    target_compile_definitions(${COMPONENT_LIB} PRIVATE SNIFF_NTP="$ENV{SNIFF_NTP}")
    message("SNIFF_NTP=$ENV{SNIFF_NTP}")
endif()
