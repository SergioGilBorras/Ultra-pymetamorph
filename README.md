# Ultra-pymetamorph (BETA)
Metamorphic engine in python and tools for it evaluation with virustotal.com

  #>python ultra-pymetamorph <Fichero a ofuscar>

    Para ejecutar el motor metamórfico necesitamos tener instaladas las librerias pefile, keystone y capstone.

# Herramientas para la evaluacion de las muestras
  Toda la información generada se almacena en una base de datos sqllite (vt_sqlite.db)

  #>python process_vt.py (Procesa las muestras contra virustotal.com)

  #>python pyresults.py (Muestras los resultados generados y genera graficas de los mismos)

# Script para procesar en lote las muestras

  #>metame_muestras.sh (Ejecuta todas las muestras originales contra el motor Metame)
	
  #>ultra-pymetamorph_metame_muestras.sh (Ejecuta todas las muestras ofuscadas con ultra-pymetamorph contra el motor Metame)
	
  #>ultra-pymetamorph_muestras.sh (Ejecuta todas las muestras originales contra el motor ultra-pymetamorph)
  
  #>get_muestras.sh (Unzip todas muestras)
	
  #>unzip_muestras.sh (Unzip todas muestras con password)
