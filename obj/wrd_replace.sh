#/bin/bash
if [ $# -eq 0 ] 
then
	echo "no arguments supplied "
	echo "usage:"
	echo "$0 INPUT_FULE_NAME OLD_WORD NEW_WORD"
	exit 1
fi
## print everything out to a pipe for sed to replace and write to a temp file ##
sed -e "s:$2:$3:g" -i $1
exit #?
