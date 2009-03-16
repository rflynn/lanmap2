SELECT
  ho.addr AS addr,
	a.addr,
  m.map AS map,
  m.maptype AS maptype,
  hi.contents,
	SUM(m.weight)
FROM host AS ho
JOIN host_addr AS a ON a.host_id = ho.id
JOIN hint hi ON hi.addr = a.addr
JOIN map m ON m.val = hi.contents
-- we really, really want
-- WHERE m.maptype = 'OS'
-- but it's 100x slower in sqlite3
-- why, god, why?
GROUP BY a.addr,
         m.map
--ORDER BY sum(m.weight) DESC
;
