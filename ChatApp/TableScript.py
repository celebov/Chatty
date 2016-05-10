import sqlite3
conn = sqlite3.connect('networkTables.db')
conn.text_factory = str
curs = conn.cursor()


# conn = sqlite3.connect('networkTables.db')
# c = conn.cursor()
# c.execute('''CREATE TABLE routingTable
#         (UUID text PRIMARY KEY, viaUUID text, cost integer)''')
#
# c.execute('''CREATE TABLE neighborTable
#         (UUID text PRIMARY KEY, socket text)''')
#
# c.execute('''CREATE TABLE sessionKeyTable
#         (UUID text PRIMARY KEY, sessionKey text)''')

def Get_RoutingTable(UUID):
    if UUID is not None:
        curs.execute("SELECT * FROM routingTable WHERE UUID = ?;", (UUID))
    else:
        curs.execute("SELECT * FROM routingTable;")
    return curs.fetchall()

def Get_Dump():
    data = "";
    for line in conn.iterdump():
        if line.startswith('INSERT INTO "routingTable"'):
            data = data + "\n" + line
    return data.replace('"',"\'")

def Import_Dump(data):
    for line in data:
        curs.execute(line)
    curs.execute("SELECT * FROM routingTable;")
    print curs.fetchall()

print Get_Dump()