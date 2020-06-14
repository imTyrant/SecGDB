#!/bin/bash
if [ ! -x "./benchmark_result/update" ]; then
    mkdir "benchmark_result/update"
fi

for i in 'wiki-Vote' 'email-Enron' 'email-EuAll' 'loc-gowalla_edges' 'com-youtube' 'wiki-Talk'
do
    if [ ! -x "./benchmark_result/test_set/${i}.data" ]; then
        touch "./benchmark_result/test_set/${i}.data"
    fi

    echo "Data set: "${i}
    ./a.out "./data/exh/"${i}".data" "./benchmark_result/test_set/${i}.data"
    echo "done!"
done