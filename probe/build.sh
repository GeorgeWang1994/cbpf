mkdir -p ./build
cd build
# apt install libelf-dev
cmake -DBUILD_DRIVER=OFF -DPROBE_VERSION=0.1.1dev ..
make
libPath="./src/libevent.so"
if [ ! -f "libPath" ]; then
  echo "compiler lib failed! exit!"
  exit
fi
echo "generate successfully"