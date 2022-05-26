#add_compile_options(-g)
add_compile_options(-fPIC)

include_directories(api)
include_directories(include)
include_directories(network)
include_directories(seprotocol)
include_directories(units)

file (GLOB_RECURSE code_src "*.c")
message("uav_src:${code_src}")

add_executable(uav_sec ${code_src})
target_link_libraries(uav_sec initso vccrypt m)

file (GLOB code_src_main "*.c")
list(REMOVE_ITEM code_src ${code_src_main})
message("uav_src without main:${code_src}")

add_library(vecentek SHARED ${code_src})
target_link_libraries(vecentek initso vccrypt m)

install(TARGETS vecentek uav_sec
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib 
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
