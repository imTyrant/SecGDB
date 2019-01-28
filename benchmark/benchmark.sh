#!/bin/bash
if [ ! -x "./benchmark_result/" ]; then
    mkdir "benchmark_result"
fi

for i in 'wiki-Vote' 'email-Enron' 'email-EuAll' 'loc-gowalla_edges' 'com-youtube' 'wiki-Talk' 'web-Google' 
do
    if [ ! -x "./benchmark_result/${i}.xml" ]; then
        touch "./benchmark_result/${i}.xml"
    fi
    echo "Data set: "${i}
    ./a.out "./data/exh/"${i}".data" "./benchmark_result/${i}.xml"
    echo "done!"
done