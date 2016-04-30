cmake_minimum_required (VERSION 2.6)
project (proof_of_work C)
add_executable(proof_of_work_test program.c sha256.c)
set( CMAKE_EXPORT_COMPILE_COMMANDS 1 )

