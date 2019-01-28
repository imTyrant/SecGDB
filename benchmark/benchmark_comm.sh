#!/bin/bash
if [ ! -x "./benchmark_result/comm_size" ]; then
    mkdir "benchmark_result/comm_size"
fi

for i in 'wiki-Vote' 'email-Enron' 'email-EuAll' 'loc-gowalla_edges' 'com-youtube' 'wiki-Talk'
do
    if [ ! -x "./benchmark_result/comm_size/${i}.rst" ]; then
        touch "./benchmark_result/comm_size/${i}.rst"
    fi

    echo "Data set: "${i}
    ./a.out "./data/exh/"${i}".data" "./benchmark_result/comm_size/${i}.rst"
    echo "done!"
done