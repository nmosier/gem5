cmake_minimum_required(VERSION 3.10)

enable_language(ASM_NASM)
set(CMAKE_ASM_NASM_COMPILE_OBJECT "<CMAKE_ASM_NASM_COMPILER> <INCLUDES> <FLAGS> -o <OBJECT> <SOURCE>")
set(CMAKE_ASM_NASM_LINK_EXECUTABLE "ld <CMAKE_ASM_NASM_LINK_FLAGS> <LINK_FLAGS> <OBJECTS>  -o <TARGET> <LINK_LIBRARIES>")

# Create a compile option that operates on ASM_NASM files
# If the target has a property NASM_OBJ_FORMAT, use it, otherwise
# use the environment variable CMAKE_ASM_NASM_OBJECT_FORMAT
add_compile_options(
    "$<$<COMPILE_LANGUAGE:ASM_NASM>:-f $<IF:$<BOOL:$<TARGET_PROPERTY:NASM_OBJ_FORMAT>>, \
    $<TARGET_PROPERTY:NASM_OBJ_FORMAT>, ${CMAKE_ASM_NASM_OBJECT_FORMAT}>>"
)


# add_executable(kernel kernel.asm)
# set_target_properties(kernel PROPERTIES NASM_OBJ_FORMAT elf64)

project(gem5_pin_tools)

set(CMAKE_CXX_STANDARD 17)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
include(PinTool)

add_pin_tool(client client.cc bbv.cc)
# target_include_directories(client PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)

# add_executable(kernel kernel.c)
# target_link_options(kernel PRIVATE -static
#   -T ${CMAKE_SOURCE_DIR}/kernel.ld
#   -Wl,--verbose
#   -Wl,--no-relax
# )
# add_custom_command(OUTPUT kernel.asm.o
#   COMMAND nasm -felf64 -o kernel.asm.o kernel.asm
#   DEPENDS kernel.asm
# )
#
# add_custom_command(OUTPUT kernel
#   COMMAND ld -o kernel kernel.asm.o
# )
#
# add_custom_target(kernel_exe ALL DEPENDS kernel)

# set(kernel.asm PROPERTIES LANGUAGE ASM_NASM)
# add_executable(kernel kernel.asm)
# set_target_properties(kernel PROPERTIES NASM_OBJ_FORMAT elf64)

add_executable(kernel kernel.c printf.c syscall.c libc.c)
target_compile_options(kernel PRIVATE -ffreestanding -fPIC -Wall -pedantic -O1 -fcf-protection=none)
target_include_directories(kernel PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)
target_link_options(kernel PRIVATE -nostdlib -Wl,-e,main -static -T ${CMAKE_CURRENT_SOURCE_DIR}/kernel.ld -Wl,--no-relax)
set_target_properties(kernel PROPERTIES LINK_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/kernel.ld)



add_pin_tool(test test.cc)
