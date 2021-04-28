#!/bin/bash
#set -x
bash ./kill.sh
sleep 1

# args
parties=${1:-2}
build_type=${2:-"release"} # debug or release
curdir=$(pwd)

# compile first
cd ${curdir}
bash ./compile.sh ${build_type}

# distibuting
cd ${curdir}
test_dir=${curdir}/.test
rm -rf ${test_dir}
mkdir -p ${test_dir}

target_dir=${curdir}/target/${build_type}/examples
cp -f ${curdir}/configs/* ${target_dir}/

for ((i = 0; i < ${parties}; i++)); do
  party_dst_dir=${test_dir}/p${i}
  mkdir -p ${party_dst_dir}
  cp -f ${target_dir}/mpc_ecdsa_web ${party_dst_dir}/
  cp -f ${curdir}/configs/* ${party_dst_dir}/
done

# start http servers
host=$(hostname)
cd ${curdir}
http_port=8000
for ((i = 0; i < ${parties}; i++)); do
  cd ${test_dir}/p${i}
  ./mpc_ecdsa_web ${parties} ${i} ${http_port} config_${parties}pc.json >${test_dir}/${i}.log 2>&1 &
  echo -e "\n\033[35mPlease visit http://${host}:${http_port} or http://IP:${http_port}\033[0m\n"
  http_port=$((${http_port} + 1))
done

# show log
cd ${curdir}
tail -f ${test_dir}/0.log &
wait

exit 0
