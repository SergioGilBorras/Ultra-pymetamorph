from pylib.sqlite_createdb import sqlite_vt
from pylib.virusTotal import virustotal
import os
import hashlib
import time


class process_vt(object):
	def __init__(self):
		print("_init_.process_vt")

	def create_table(self):

		db=sqlite_vt()

		db.create_table()
		
		db.close()

	def printme(self):

		db=sqlite_vt()

		
		db.printme2()
		db.printme()
		
		db.close()


	def insert_fn(self):

		db=sqlite_vt()

		for ff in os.listdir("./muestras_simple"):
			if ".file" in ff:
				f_md5=self.md5("./muestras_simple/"+ff)			
				#print(ff, f_md5)
				dd=db.isInFilename(ff)
				if dd==None:
					db.insert_filename(ff, f_md5)

					vt=virustotal()

					json = vt.upfile("./muestras_simple/"+ff)
					print ff
					print "Resurce: ", json["resource"]
					print "Md5: ", json["md5"]
	
					db.insert_vt_resource(ff, json["resource"])
				elif dd[9]==None or dd[10]==None:
					vt=virustotal()

					json = vt.upfile("./muestras_simple/"+ff)
					print dd
					print "Resurce: ", json["resource"]
					print "Md5: ", json["md5"]
					db.insert_vt_resource(ff, json["resource"])
		db.close()

	def insert_fn_metame(self):

		db=sqlite_vt()
		con=0
		for ff in os.listdir("./muestras_simple/metame_default/"):
			if ".file" in ff:
				FGF = db.isInFilename(ff)
				#print("FGF:",FGF)
				if FGF[7] == None and con>0:
					vt=virustotal()
					print "File: ", ff, con
					
					json = vt.upfile("./muestras_simple/metame_default/"+ff)

					print "Resurce: ", json["resource"]
					print "Md5: ", json["md5"]
	
					db.insert_vt_resource_metame(ff, json["resource"], json["md5"])  
				if FGF[7] == None:
					print "File: ", ff, con
					con=con+1
		db.close()


	def insert_fn_metamorph(self):

		db=sqlite_vt()
		con=0
		for ff in os.listdir("./muestras_simple/pymetamorph_default/"):
			if ".file" in ff:
				FGF = db.isInFilename(ff)
				#print("FGF:",FGF)
				if FGF[5] == None and con>=0:
					vt=virustotal()
					print "File: ", ff, con
					
					json = vt.upfile("./muestras_simple/pymetamorph_default/"+ff)

					print "Resurce: ", json["resource"]
					print "Md5: ", json["md5"]
	
					db.insert_vt_resource_metamorph(ff, json["resource"], json["md5"])  
				if FGF[5] == None:
					print "File: ", ff, con
					con=con+1
		db.close()


	def insert_fn_metamorph_metame(self):

		db=sqlite_vt()
		con=0
		for ff in os.listdir("./muestras_simple/pymetamorph_metame_default/"):
			if ".file" in ff:
				FGF = db.isInFilename(ff)
				#print "FGF:",FGF
				if FGF[4] == None and con>=0:
					vt=virustotal()
					print "File: ", ff, con
					
					json = vt.upfile("./muestras_simple/pymetamorph_metame_default/"+ff)

					print "Resurce: ", json["resource"]
					print "Md5: ", json["md5"]
	
					db.insert_vt_resource_metamorph_metame(ff, json["resource"], json["md5"])  
				if FGF[4] == None:
					print "File: ", ff, con
					con=con+1
		db.close()


	def insert_vt_resource(self):

		db=sqlite_vt()

		for ff in db.get_iterator():
			if ff[6]!="" and ff[6]!=None and (ff[10]==None or ff[9]==None):
				print "Resurce: ", ff[6]
				vt=virustotal()
			
				json = vt.report(ff[6])
				if json!=None:
					print "Positives: ", json["positives"]
					print "Total: ", json["total"]
	
					db.insert_positive_total(ff[0], json["positives"], json["total"])
					time.sleep(16)
				else:
					time.sleep(60)
			elif(ff[10]==None or ff[9]==None):
				print "->File: ", ff
		db.close()

	def insert_vt_resource_metame(self):

		db=sqlite_vt()

		for ff in db.get_iterator():
			if ff[7]!="" and ff[7]!=None and ff[12]==None:
				print "Resurce: ", ff[7]
				vt=virustotal()
			
				json = vt.report(ff[7])
				if json!=None and json["response_code"]!=-2:
					print "File: ", ff[0]
					print "Positives: ", json["positives"]
				
					db.insert_positive_metame(ff[0], json["positives"])
					time.sleep(16)
				elif json!=None and json["response_code"]==-2:
					print json
					#json = vt.upfile("./muestras_simple/metame_default/"+ff[0])
					#print json					
					time.sleep(16)
				else:
					time.sleep(60)
		db.close()
	

	def insert_vt_resource_metamorph(self):

		db=sqlite_vt()

		for ff in db.get_iterator():
			if ff[5]!="" and ff[5]!=None and ff[11]==None:
				print "Resurce: ", ff[5]
				vt=virustotal()
			
				json = vt.report(ff[5])
				if json!=None and json["response_code"]!=-2:
					print "File: ", ff[0]
					print "Positives: ", json["positives"]
				
					db.insert_positive_metamorph(ff[0], json["positives"])
					time.sleep(16)
				elif json!=None and json["response_code"]==-2:
					print json
					#json = vt.upfile("./muestras_simple/pymetamorph_default/"+ff[0])
					#print json
					time.sleep(16)
				else:
					time.sleep(60)
		db.close()
	
	def insert_vt_resource_metamorph_metame(self):

		db=sqlite_vt()

		for ff in db.get_iterator():
			if ff[8]!="" and ff[8]!=None and ff[13]==None:
				print "Resurce: ", ff[8]
				vt=virustotal()
			
				json = vt.report(ff[8])
				if json!=None and json["response_code"]!=-2:
					print "File: ", ff[0]
					print "Positives: ", json["positives"]
				
					db.insert_positive_metamorph_metame(ff[0], json["positives"])
					time.sleep(16)
				elif json!=None and json["response_code"]==-2:
					print json
					#json = vt.upfile("./muestras_simple/pymetamorph_metame_default/"+ff[0])
					#print json
					time.sleep(16)
				else:
					time.sleep(60)
		db.close()
	
	def arreglo(self):

		db=sqlite_vt()
		db.arreglo()
		db.close()

	def md5(self,fname):
		hash_md5 = hashlib.md5()
		with open(fname, "rb") as f:
			for chunk in iter(lambda: f.read(4096), b""):
				hash_md5.update(chunk)
		return hash_md5.hexdigest()


if __name__ == '__main__':

	c=process_vt()
#	c.create_table()
	#c.insert_fn()
	#c.insert_fn_metame()
	c.insert_fn_metamorph()
	c.insert_fn_metamorph_metame()
	#c.insert_vt_resource()
	c.insert_vt_resource_metame()
	c.insert_vt_resource_metamorph()
	c.insert_vt_resource_metamorph_metame()
	c.printme()
	#c.arreglo()

