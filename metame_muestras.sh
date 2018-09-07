#!/bin/bash
conta=0
echo "RASTA" $(date -u) > ./log_metame.log
for file in ./muestras_simple/*.file
do
	filename=$( echo $file | cut -d'/' -f 3)
	if [ ! -f ./muestras_simple/metame_default/$filename ]; then
		echo "Muestra:" $conta ":" $filename
		echo $(stat -c%s "$file") "Bytes"
		metame -i $file -o ./muestras_simple/metame_default/$filename &>> ./log_metame.log
		let conta=conta+1
	fi
done
