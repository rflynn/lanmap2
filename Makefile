
MAKE = make

all:
	$(MAKE) -C db
	$(MAKE) -C tools
	$(MAKE) -C src

clean:
	$(MAKE) -C tools clean
	$(MAKE) -C src clean

graph: db/db
	$(MAKE) -C graph graph

nuke-database:
	$(MAKE) -C db nuke-database

