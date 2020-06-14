#!/bin/bash

if [ ! -x "./benchmark_result/dist" ]; then
    mkdir "benchmark_result/dist"
fi
for i in 'wiki-Vote' 'email-Enron' 'email-EuAll' 'loc-gowalla_edges' 'com-youtube' 'wiki-Talk'
do
    if [ ! -x "./benchmark_result/dist/${i}.xml" ]; then
        touch "./benchmark_result/dist/${i}.xml"
    fi
    echo "Data set: "${i}
    ./a.out "./data/exh/"${i}".data" "./benchmark_result/dist/${i}.xml" "./data/fake/${i}.data"
    echo "done!"
done