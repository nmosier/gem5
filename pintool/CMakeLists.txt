cmake_minimum_required(VERSION 3.10)

project(gem5_pin_tools)

set(CMAKE_CXX_STANDARD 17)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
include(PinTool)

add_pin_tool(Client client.cc message.cc)
target_include_directories(Client PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)
