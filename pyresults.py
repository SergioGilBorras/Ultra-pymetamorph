from pylib.sqlite_createdb import sqlite_vt
import matplotlib.pyplot as plt

class results(object):
	def __init__(self):
		print("_init_.results")

	def plot_pymetamorph(self):
		db=sqlite_vt()
		plt.xlabel("Porcentaje de mejora en la evasion")
		plt.ylabel("Numero de Muestras")
		plt.title("Histograma para Ultra-pymetamorph")
		plt.grid(True)
		plt.hist(db.res_plot_pymetamorph(),102)
		plt.show()
		db.close()

	def plot_metame(self):
		db=sqlite_vt()
		plt.xlabel("Porcentaje de mejora en la evasion")
		plt.ylabel("Numero de Muestras")
		plt.title("Histograma para Metame")
		plt.grid(True)
		plt.hist(db.res_plot_metame(),102)
		plt.show()
		db.close()

	def plot_pymetamorph_metame(self):
		db=sqlite_vt()
		plt.xlabel("Porcentaje de mejora en la evasion")
		plt.ylabel("Numero de Muestras")
		plt.title("Histograma para Ultra-pymetamorph + Metame")
		plt.grid(True)
		plt.hist(db.res_plot_pymetamorph_metame(),102)
		plt.show()
		db.close()

	def printme(self):

		db=sqlite_vt()
		
		db.printme1()
		
		db.close()

if __name__ == '__main__':

	c=results()
	#c.plot_pymetamorph()
	#c.plot_metame()
	#c.plot_pymetamorph_metame()
	c.printme()
