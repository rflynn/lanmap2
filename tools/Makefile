
CFLAGS = -W -Wall -Wno-unused -pedantic -I../src -ggdb
LDFLAGS = -ggdb

all: oui2insert os-graph

os-graph: os-graph.o nary.o ../src/csvread.o ../src/util.o


clean:
	$(RM) *.o os-graph oui2insert

