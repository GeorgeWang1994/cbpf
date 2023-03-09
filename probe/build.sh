mkdir -p ./build
cd build
cmake -DBUILD_DRIVER=OFF -DPROBE_VERSION=0.1.1dev ..
make
libKindlingPath="./src/libkindling.so"
if [ ! -f "$libKindlingPath" ]; then
  echo "compiler libkindling failed! exit!"
  exit
fi
echo "generate successfully"