#!/bin/bash

for file in ./zippedMalware/*.zip
do
	unzip -P infected $file
done
