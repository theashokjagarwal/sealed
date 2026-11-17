CXX := g++
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra

all: sealed_fast_scanner

sealed_fast_scanner: sealed_fast_scanner.cpp
	$(CXX) $(CXXFLAGS) -o sealed_fast_scanner sealed_fast_scanner.cpp

clean:
	rm -f sealed_fast_scanner

.PHONY: all clean
