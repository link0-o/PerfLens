cmake_minimum_required(VERSION 3.20)
project(perflens_pthread_probe LANGUAGES C)

add_library(perflens-pthread-probe SHARED perflens_pthread_probe.c)
target_compile_features(perflens-pthread-probe PRIVATE c_std_11)
target_compile_definitions(
  perflens-pthread-probe
  PRIVATE _GNU_SOURCE=1 _FORTIFY_SOURCE=3
)
target_compile_options(
  perflens-pthread-probe
  PRIVATE
    -O2
    -fPIC
    -fvisibility=hidden
    -fstack-protector-strong
    -Wall
    -Wextra
    -Werror
    -Wpedantic
    -Wformat=2
    -Wconversion
    -Wshadow
    -Wstrict-prototypes
)
target_link_libraries(perflens-pthread-probe PRIVATE dl pthread)
target_link_options(
  perflens-pthread-probe
  PRIVATE
    "LINKER:-z,defs"
    "LINKER:-z,relro"
    "LINKER:-z,now"
    "LINKER:-z,noexecstack"
)
set_target_properties(
  perflens-pthread-probe
  PROPERTIES
    OUTPUT_NAME perflens-pthread-probe
    PREFIX lib
    NO_SONAME ON
)

include(GNUInstallDirs)
install(
  TARGETS perflens-pthread-probe
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/perflens
  PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
)
