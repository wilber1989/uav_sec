set(CMAKE_C_VISIBILITY_PRESET hidden)
add_compile_options(-g)

set(SMENABLE "off")
message("SM ENALBE IS ${SMENABLE}")

if(${SMENABLE} STREQUAL "on")
	add_compile_options(-DSMENABLE)
endif()

add_compile_options(-DINIT_SO_ENABLE)
add_compile_options(-fPIC)
SET (init_source init_so.c vc_key.c vc_se_crypt.c WBAC.c vc_platform.c)
add_library(initso SHARED ${init_source})

file (GLOB code_source "vc_*")
SET (code_source ${code_source};./WBAC.c)
message("deCORE_Crypto-S:${code_source}")

add_compile_options(-UINIT_SO_ENABLE)
#link_directories(../lib)
add_library(vccrypt SHARED ${code_source})
add_compile_options(-fPIC)
target_link_libraries(vccrypt mbedcrypto  mbedtls  mbedx509)

include_directories(../include)
install(TARGETS vccrypt initso
        LIBRARY DESTINATION lib
         PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
#STATIC SHARED
