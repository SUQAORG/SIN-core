#/usr/bin/bash
set -x
set -e

CUR_DIR=$(pwd)
SCRIPT_DIR=$CUR_DIR/$(dirname "$0")
BASE_DIR=$SCRIPT_DIR/../..
DEP_DIR=$BASE_DIR/depends
#declare -a hosts=("OSX64" "LIN64" "WIN64" "WIN32" "LINARM" "LINARMHF" "LINARM64")
declare -a hosts=("LIN64" "WIN64" "WIN32" "LINARM" "LINARMHF" "LINARM64")

OSX_SDK_URL=https://github.com/phracker/MacOSX-SDKs/releases/download/10.13/MacOSX10.11.sdk.tar.xz

OSX64_CONF=""
OSX64_HOST="x86_64-apple-darwin"
OSX64_MAKE="PLATF=x86-osx-64bit"

LIN64_CONF=""
LIN64_HOST="x86_64-linux-gnu"
LIN64_MAKE="PLATF=x86-linux-libc6-64bit"

WIN64_CONF=""
WIN64_HOST="x86_64-w64-mingw32"
WIN64_MAKE="PLATF=x86-windows-64bit"

WIN32_CONF=""
WIN32_HOST="i686-w64-mingw32"
WIN32_MAKE="PLATF=x86-windows-32bit"

LINARM_CONF=""
LINARM_HOST="arm-linux-gnueabi"
LINARM_MAKE="PLATF=armv5-armv6-linux-libc6-32bit"

LINARMHF_CONF=""
LINARMHF_HOST="arm-linux-gnueabihf"
LINARMHF_MAKE="PLATF=armv7-linux-libc6-32bit"

LINARM64_CONF=""
LINARM64_HOST="aarch64-linux-gnu"
LINARM64_MAKE="PLATF=armv8-linux-libc6-64bit"

if [ ! -f $SCRIPT_DIR/packages.flag ]; then
	sudo apt install build-essential libtool autotools-dev automake pkg-config bsdmainutils curl git ca-certificates curl librsvg2-bin libtiff-tools libtool automake faketime bsdmainutils cmake imagemagick libcap-dev libz-dev libbz2-dev python python-dev python-setuptools fonts-tuffy p7zip-full g++-mingw-w64-i686 gcc-mingw-w64-i686 mingw-w64-i686-dev g++-mingw-w64-x86-64 gcc-mingw-w64-x86-64 mingw-w64-x86-64-dev gcc-arm-linux-gnueabi g++-arm-linux-gnueabi gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf gcc-aarch64-linux-gnu g++-aarch64-linux-gnu gcc-i686-linux-gnu g++-i686-linux-gnu -y && touch $SCRIPT_DIR/packages.flag
fi

if [ ! -f $SCRIPT_DIR/alts.flag ]; then
	sudo update-alternatives --config i686-w64-mingw32-g++
	sudo update-alternatives --config i686-w64-mingw32-gcc
	sudo update-alternatives --config x86_64-w64-mingw32-g++
	sudo update-alternatives --config x86_64-w64-mingw32-gcc
	touch $SCRIPT_DIR/alts.flag
fi


if [ ! -f $SCRIPT_DIR/download.flag ]; then
	make -C $DEP_DIR download
	touch $SCRIPT_DIR/download.flag
fi

if [ ! -f $SCRIPT_DIR/osxsdk.flag ]; then
	cd $DEP_DIR
	wget --no-check-certificate $OSX_SDK_URL
	mkdir -p SDKs
	tar -xvf MacOSX10.11.sdk.tar.xz -C ./SDKs
	cd $CUR_DIR
	touch $SCRIPT_DIR/osxsdk.flag	
fi

for i in "${hosts[@]}"
do
	HOST=${i}_HOST
	make -C $DEP_DIR HOST=${!HOST} &
done

wait

#CORES=$(getconf _NPROCESSORS_ONLN)
CORES=4
cd $BASE_DIR
#./autogen.sh

for i in "${hosts[@]}"
do
	HOST=${i}_HOST
	CONF=${i}_CONF
	MAKE=${i}_MAKE
	#CONFIG_SITE=$(pwd)/depends/${!HOST}/share/config.site ./configure --disable-tests --disable-bench --prefix=$(pwd)/depends/${!HOST} ${!CONF} > /dev/null
	#make clean > /dev/null
	make deploy -j$CORES ${!MAKE}
done

cd $CUR_DIR
