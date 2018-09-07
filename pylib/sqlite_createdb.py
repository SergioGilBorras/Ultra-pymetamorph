import sqlite3

class sqlite_vt(object):

	def __init__(self):
		self.conn = sqlite3.connect("./vt_sqlite.db")

		self.c = self.conn.cursor()

	def create_table(self):
		self.c.execute("CREATE TABLE test_vt (filename TEXT PRIMARY KEY ,md5 TEXT ,md5_metamorph TEXT ,md5_metame TEXT ,md5_metamorph_metame TEXT ,vt_resource_metamorph TEXT ,vt_resource TEXT ,vt_resource_metame TEXT ,vt_resource_metamorph_metame TEXT ,positive INTEGER ,total INTEGER ,positive_metamorph INTEGER ,positive_metame INTEGER ,positive_metamorph_metame INTEGER )")

		self.conn.commit()


	def insert_filename(self ,val ,md5):
		self.c.execute("REPLACE INTO test_vt (filename, md5) VALUES (?,?)",[val,md5])

		self.conn.commit()


	def insert_md5_metamorph(self,key,val):
		self.c.execute("UPDATE test_vt SET md5_metamorph=? WHERE filename=?",[val,key])

		self.conn.commit()

	def insert_md5_metame(self,key,val):
		self.c.execute("UPDATE test_vt SET md5_metame=? WHERE filename=?",[val,key])

		self.conn.commit()


	def insert_md5_metamorph_metame(self,key,val):
		self.c.execute("UPDATE test_vt SET md5_metamorph_metame=? WHERE filename=?",[val,key])

		self.conn.commit()


	def insert_vt_resource(self,key,val):
		self.c.execute("UPDATE test_vt SET vt_resource=? WHERE filename=?",[val,key])

		self.conn.commit()


	def insert_vt_resource_metamorph(self,key,val,md5):
		self.c.execute("UPDATE test_vt SET vt_resource_metamorph=?, md5_metamorph=? WHERE filename=?",[val, md5, key])

		self.conn.commit()

	def insert_vt_resource_metame(self,key,val,md5):
		self.c.execute("UPDATE test_vt SET vt_resource_metame=?, md5_metame=? WHERE filename=?",[val, md5 ,key])

		self.conn.commit()


	def insert_vt_resource_metamorph_metame(self,key,val,md5):
		self.c.execute("UPDATE test_vt SET vt_resource_metamorph_metame=?, md5_metamorph_metame=? WHERE filename=?",[val, md5, key])

		self.conn.commit()


	def insert_positive_metamorph(self,key,val):
		self.c.execute("UPDATE test_vt SET positive_metamorph=? WHERE filename=?",[val,key])

		self.conn.commit()

	def insert_positive_metame(self,key,val):
		self.c.execute("UPDATE test_vt SET positive_metame=? WHERE filename=?",[val,key])

		self.conn.commit()


	def insert_positive_metamorph_metame(self,key,val):
		self.c.execute("UPDATE test_vt SET positive_metamorph_metame=? WHERE filename=?",[val,key])

		self.conn.commit()

	def insert_positive_total(self,key,pos,tot):
		self.c.execute("UPDATE test_vt SET positive=?, total=? WHERE filename=?",[pos,tot,key])

		self.conn.commit()

	def printme(self):

		for row in self.c.execute("SELECT COUNT(filename), SUM(100-((positive_metamorph*100)/positive))/COUNT(*), SUM(100-((positive_metame*100)/positive))/COUNT(*), SUM(100-((positive_metamorph_metame*100)/positive))/COUNT(*) FROM test_vt WHERE md5_metamorph!='' or md5='err'"):
			print(row)

	def printme1(self):

		for row in self.c.execute("SELECT 'Total:', COUNT(filename) FROM test_vt WHERE md5_metamorph!='' or md5='err' UNION SELECT 'pymetamorph:', COUNT(filename) FROM test_vt WHERE md5='err' UNION SELECT 'pymetamorph_metame:', COUNT(filename) FROM test_vt WHERE positive_metamorph_metame is NULL and (md5_metamorph!='' or md5='err') UNION SELECT 'metame:', COUNT(filename) FROM test_vt WHERE positive_metame  is NULL and (md5_metamorph!='' or md5='err') UNION SELECT 'comunes:', COUNT(filename) FROM test_vt WHERE positive_metame  is NULL and positive_metamorph_metame  is NULL and md5='err' "):
			print(row)

	def printme2(self):

		for row in self.c.execute("SELECT filename, total, positive, 100-((positive_metamorph*100)/positive), 100-((positive_metame*100)/positive), 100-((positive_metamorph_metame*100)/positive) FROM test_vt WHERE  md5='err'"):
			print(row)

	def res_plot_pymetamorph(self):
		res = []
		for row in self.c.execute("SELECT (100-((positive_metamorph*100)/positive))/1 as res1 FROM test_vt WHERE md5_metamorph!='' or md5='err'"):
			if row[0]==None:
				res.append(101)
			elif row[0]<0:
				res.append(-1)
			elif row[0]!=None:		
				res.append(row[0])
		return res

	def res_plot_metame(self):
		res = []
		for row in self.c.execute("SELECT (100-((positive_metame*100)/positive))/1 as res1 FROM test_vt WHERE md5_metamorph!='' or md5='err'"):
			if row[0]==None:
				res.append(101)
			elif row[0]<0:
				res.append(-1)
			elif row[0]!=None:		
				res.append(row[0])
		return res
	
	def res_plot_pymetamorph_metame(self):
		res = []
		for row in self.c.execute("SELECT (100-((positive_metamorph_metame*100)/positive))/1 as res1 FROM test_vt WHERE md5_metamorph!='' or md5='err'"):

			if row[0]==None:
				res.append(101)
			elif row[0]<0:
				res.append(-1)
			elif row[0]!=None:		
				res.append(row[0])
				
		return res

	def arregloERR(self,key):
		self.c.execute("UPDATE test_vt SET md5='err' WHERE filename=?",[key])

		self.conn.commit()


	
	def arreglo(self):
		self.c.execute("SELECT * FROM test_vt")
		for row in self.c.fetchall():
			self.c.execute("UPDATE test_vt SET vt_resource_metame=?, md5_metame=? WHERE filename=?",[row[3], row[7] ,row[0]])
			
			print(row)
			self.conn.commit()

	def get_iterator(self):
		self.c.execute("SELECT * FROM test_vt")
		return self.c.fetchall()

	def isInFilename(self, key):

		self.c.execute("SELECT * FROM test_vt WHERE filename=?",[key])
		return self.c.fetchone()
	
	def close(self):
		self.conn.close()
