cmake_minimum_required(VERSION 3.22.1)
project("avbsign" C)

add_library(avbsign SHARED avbsign_jni.c)
