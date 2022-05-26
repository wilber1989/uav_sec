make
export LD_LIBRARY_PATH=./:$LD_LIBRARY_PATH
SMFLAG=off
SMENB=
echo $SMFLAG
if [ "$SMFLAG" = "on" ]; then
	SMENB=-lcrypto
fi

echo "my--sm enable lib"
echo $SMENB

gcc -o tst main.c -g -L. -lvccrypt -L../lib -L../lib $SMENB -lmbedtls -lmbedcrypto -lmbedx509 -ldl -lpthread -Wl,-Map,mp.map


