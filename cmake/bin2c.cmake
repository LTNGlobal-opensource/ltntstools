# Equivalent of 'xxd -i': embed INPUT as a C array named NAME in OUTPUT.
#
#   cmake -DINPUT=<file> -DOUTPUT=<header> -DNAME=<symbol> -P bin2c.cmake
#
# Defines 'unsigned char NAME[]' and 'unsigned int NAME_len', matching the
# symbols xxd generates.

file(READ "${INPUT}" _hex HEX)
string(LENGTH "${_hex}" _len)
math(EXPR _len "${_len} / 2")

string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1, " _bytes "${_hex}")
string(REGEX REPLACE "((0x.., ){12})" "\\1\n  " _bytes "${_bytes}")

file(WRITE "${OUTPUT}.tmp"
  "unsigned char ${NAME}[] = {\n  ${_bytes}\n};\n"
  "unsigned int ${NAME}_len = ${_len};\n")
file(RENAME "${OUTPUT}.tmp" "${OUTPUT}")
