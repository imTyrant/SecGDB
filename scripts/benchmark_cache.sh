#!/bin/bash
if [ ! -x "./benchmark_result/cache" ]; then
    mkdir "benchmark_result/cache"
fi

for i in 'wiki-Vote' 'email-Enron' 'email-EuAll' 'loc-gowalla_edges' 'com-youtube' 'wiki-Talk'
do
    if [ ! -x "./benchmark_result/cache/${i}.rst" ]; then
        touch "./benchmark_result/cache/${i}.rst"
    fi

    echo "Data set: "${i}
    ./a.out "./data/exh/"${i}".data" "./benchmark_result/cache/${i}.rst"
    echo "done!"
done