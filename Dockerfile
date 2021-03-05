FROM ubuntu:18.04

RUN apt update \
    && apt install git -y \
    && apt install vim -y \
    && apt install build-essential -y \
    && apt install ocaml ocamlbuild  -y \
    && apt install cmake -y \
    && apt install xsltproc -y \
    && apt install libgcrypt20-dev -y \
    && apt install libgmp3-dev libgmp-dev -y \
    && apt install libssl-dev -y \
    && apt install libboost-dev libboost-system-dev libboost-filesystem-dev -y

COPY . /graphshield

