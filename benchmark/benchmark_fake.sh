#!/bin/bash
for j in '11' '12' '13' '14' '15' '16' '17' '18' '19' '20'
do
    cd "data/exh/"
    python "gen_fake_data.py"
    cd "../../"
    python "benchmark/ana_fake_data.py"
    if [ ! -x "./benchmark_result/fake${j}" ]; then
        mkdir "benchmark_result/fake${j}"
    fi
    for i in 'wiki-Vote' 'email-Enron' 'email-EuAll' 'loc-gowalla_edges' 'com-youtube' 'wiki-Talk'
    do
        if [ ! -x "./benchmark_result/fake${j}/${i}.xml" ]; then
            touch "./benchmark_result/fake${j}/${i}.xml"
        fi

        echo "Data set: "${i}
        ./a.out "./data/exh/"${i}".data" "./benchmark_result/fake${j}/${i}.xml" "./data/exh/fake_data/${i}.fake"
        echo "done!"
    done
done