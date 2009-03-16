-- ex: set ts=2 et:
require "sqlite3"

db = sqlite3.open("../db/db")

--db:exec[[ CREATE TABLE test (id, content) ]]

--stmt = db:prepare[[ INSERT INTO test VALUES (:key, :value) ]]

--stmt:bind{  key = 1,  value = "Hello World"    }:exec()
--stmt:bind{  key = 2,  value = "Hello Lua"      }:exec()
--stmt:bind{  key = 3,  value = "Hello Sqlite3"  }:exec()

for row in db:rows("SELECT * FROM hint") do
  print(row.id, row.contents)
end

