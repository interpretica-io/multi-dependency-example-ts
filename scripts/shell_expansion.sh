echo 'cat <<END_OF_TEXT' >  temp.sh
cat "$1"                 >> temp.sh
echo 'END_OF_TEXT'       >> temp.sh
bash temp.sh > "$2"
rm temp.sh

