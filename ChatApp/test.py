import sqlite3
conn = sqlite3.connect('networkTables.db')
conn.text_factory = str
curs = conn.cursor()



#curs.execute("DELETE  FROM sessionKeyTable")
#conn.commit()


# curs.execute("INSERT INTO sessionKeyTable (sessionKey, UUID) VALUES (?,?)", ("elma", "77F04F43B",))

#curs.execute("INSERT INTO routingTable (UUID, viaUUID, cost) VALUES (?,?,?)", ("865E62A4", "865E62A4", 0,))
curs.execute("UPDATE routingTable SET cost = 1 WHERE UUID = '865E62A4'")
#UPDATE table_name SET column1 = value1, column2 = value2...., columnN = valueN WHERE [condition];
conn.commit()
curs.execute("SELECT * FROM routingTable;")
print curs.fetchall()
