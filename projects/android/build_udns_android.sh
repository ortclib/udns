#!/bin/sh

#Note [TBD] : There is no check for ndk-version
#Please use the ndk-version as per host machine for now

#Get the machine type
PROCTYPE=`uname -m`

if [ "$PROCTYPE" = "i686" ] || [ "$PROCTYPE" = "i386" ] || [ "$PROCTYPE" = "i586" ] ; then
        echo "Host machine : x86"
        ARCHTYPE="x86"
else
        echo "Host machine : x86_64"
        ARCHTYPE="x86_64"
fi

#Get the Host OS
HOST_OS=`uname -s`
case "$HOST_OS" in
    Darwin)
        HOST_OS=darwin
        ;;
    Linux)
        HOST_OS=linux
        ;;
esac

#NDK-path
if [[ $1 == *ndk* ]]; then
	echo "----------------- NDK Path is : $1 ----------------"
	Input=$1;
else
	echo "Please enter your android ndk path:"
	echo "For example:/home/astro/android-ndk-r8e"
	read Input
	echo "You entered:$Input"
fi

#Set path
echo "----------------- Exporting the android-ndk path ----------------"
export PATH=$PATH:$Input:$Input/toolchains/arm-linux-androideabi-4.4.3/prebuilt/$HOST_OS-$ARCHTYPE/bin

#create install directories
mkdir -p ./../../../build
mkdir -p ./../../../build/android

#udns module build
echo "------ Building udns v0.2 for ANDROID platform ------"
pushd `pwd`
mkdir -p ./../../../build/android/udns

rm -rf ./obj/*
export NDK_PROJECT_PATH=`pwd`
ndk-build APP_PLATFORM=android-9
popd

echo "-------- Installing udns libs -----"
cp -r ./obj/local/armeabi/lib* ./../../../build/android/udns/

#clean
rm -rf ./obj
