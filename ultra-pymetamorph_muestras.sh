#!/bin/bash
conta=0
echo "RASTA" $(date -u) > ./log_pymetamorph.log
for file in ./muestras_simple/*.file
do
	filename=$( echo $file | cut -d'/' -f 3)
	if [ ! -f ./muestras_simple/pymetamorph_default/$filename ]; then
		size=$(stat -c%s "$file")		
		#echo "Muestra:" $conta ":" $filename
		#echo $size "Bytes"
		if (( $size < 400000 )) ; then
			#echo "::::RST::::"
			#echo "Muestra:" $conta ":" $filename
			#python arregloErr.py $filename 
			python pymetamorph_mod.py $file ./muestras_simple/pymetamorph_default/$filename #&>> ./log_pymetamorph.log
			let conta=conta+1
		fi
	fi
done
