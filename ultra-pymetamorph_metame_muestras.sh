#!/bin/bash
conta=0
echo "RASTA" $(date -u) > ./log_pymetamorph_metame.log
for file in ./muestras_simple/pymetamorph_default/*.file
do
	filename=$( echo $file | cut -d'/' -f 4)
	if [ ! -f ./muestras_simple/pymetamorph_metame_default/$filename ]; then
		echo "Muestra:" $conta ":" $filename
		echo $(stat -c%s "$file") "Bytes"
		metame -i $file -o ./muestras_simple/pymetamorph_metame_default/$filename &>> ./log_pymetamorph_metame.log
		let conta=conta+1
	fi
done
