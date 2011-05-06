
MAKE = make

all:
	$(MAKE) -C db
	$(MAKE) -C tools
	$(MAKE) -C src

clean:
	#$(MAKE) -C db clean
	$(MAKE) -C tools clean
	$(MAKE) -C src clean

nuke-database:
	$(MAKE) -C db nuke-database

