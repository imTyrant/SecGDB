#!/bin/bash

function valid
{
    if [ $? -ne 0 ]; then
        exit 1
    fi
}

for it in `seq 1 1 10`; do
    echo "round ${it}"
    echo "friendship"
    ./build/main -e enc_graph -i ./.datasets/friendship/graph.txt -o ./benchmark_result/exp_friendship/
    valid
    echo "email"
    ./build/main -e enc_graph -i .datasets/arenas_email/graph.txt -o ./benchmark_result/exp_email/
    valid
done