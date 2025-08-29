CXX = g++
CXXFLAGS = -std=c++20 -Wall -Wextra -O2

all: expurg-auditor

expurg-auditor: src/main.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

clean:
	rm -f expurg-auditor
