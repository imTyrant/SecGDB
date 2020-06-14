#!/bin/bash
if [ ! -x "./benchmark_result/update" ]; then
    mkdir "benchmark_result/update"
fi

for i in 'wiki-Vote' 'email-Enron' 'email-EuAll' 'loc-gowalla_edges' 'com-youtube' 'wiki-Talk' 'web-Google' 
do
    if [ ! -x "./benchmark_result/update/${i}.xml" ]; then
        touch "./benchmark_result/update/${i}.xml"
    fi

    if [ ! -x "./benchmark_result/update/${i}" ]; then
        mkdir "./benchmark_result/update/${i}"
    fi

    echo "Data set: "${i}
    ./a.out "./data/exh/"${i}".data" "./benchmark_result/update/${i}.xml" "./benchmark_result/update/${i}"
    echo "done!"
done