#!/bin/bash
#NOTE: the script won't work if sql_connection in nvp.ini has extra chars after db name

DB_PW="$1"
DB_NAME="$2"

if [ -z "$DB_PW" ]; then
    echo "Mysql password not specified. Will be prompted at command line"
    PW_OPT="-p"
else
    PW_OPT="--password="$DB_PW
fi

if [ -z "$DB_NAME" ]; then
   # Scan nvp configuration file
   DB_NAME=`find /etc/quantum/ -name nvp.ini | xargs grep -P '^(?<!#)sql_connection' | awk 'match($0,"/[^/]*$") {print substr($0, RSTART+1, RLENGTH)}'`
   if [ -z "$DB_NAME" ]; then
       echo "Warning: Unable to locate database name in configuration files"
       DB_NAME="nvp_quantum"
   fi
fi
echo "Using Database Name:"$DB_NAME
mysql -u root "$PW_OPT" -D "$DB_NAME" -e 'RENAME TABLE network_bindings TO nvp_network_bindings'
