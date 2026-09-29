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
# the environment is read only when cmake configures, and nothing tells cmake that it changed:
# a new address in buildit.cfg went on compiling the old one into every image, which then dialled
# it after the OTA. so re-configure whenever a file these values come from changes
#
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/buildit.cfg")
if(EXISTS "${CMAKE_SOURCE_DIR}/../mcfg_local.h")
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/../mcfg_local.h")
endif()
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
