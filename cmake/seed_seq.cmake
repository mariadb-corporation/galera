#
# Copyright (C) 2020 Codership Oy <info@codership.com>
#
# Check for std::seed_seq which may not be implemented in all
# required platforms. It is missing at least from GCC 4.4.
#

check_cxx_source_compiles("
#include <random>
int main() { std::seed_seq seeds{1, 2}; }
" SEED_SEQ_OK)
if (SEED_SEQ_OK)
  add_definitions(-DHAVE_STD_SEED_SEQ)
endif()
