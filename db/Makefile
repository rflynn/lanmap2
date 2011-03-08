
SQLITE = sqlite3

all:
	./build-db.sh
	../tools/oui2insert < ../data/oui.txt | $(SQLITE) ./db

clean:
	$(RM) db

