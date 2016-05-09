import sqlite3

#to have db in RAM
#db = sqlite3.connect(':memory:')
#to have db in disk
conn = sqlite3.connect('networkTables.db')

c = conn.cursor()
c.execute('''CREATE TABLE routingTable
    (UUID text PRIMARY KEY, viaUUID text, cost integer)''')

c.execute('''CREATE TABLE neighborTable
    (UUID text PRIMARY KEY, socket text)''')

c.execute('''CREATE TABLE sessionKeyTable
    (UUID text PRIMARY KEY, sessionKey text)''')

