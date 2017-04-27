# Ristretto Processor Trace

## Intro

A library for tracing program execution and parsing the results for the purpose of detecting unexpected branches.

## Misc

	./a.out 2>ptfile
 	./ptdump --raw --lastip ptfile


ptdump source: https://github.com/01org/processor-trace

## ptdump abbreviations

TNT -- Conditional branch
TIP -- Indirect branches / function returns
TIP.PGE -- packet generation enabled
TIP.PGD -- packet generation disabled
FUP -- Asynchronous event locations
MODE.TSX -- transactional state

## Building

* Apply the ristretto-filters.patch to the following linux kernel commit:

    commit c154165e93b7f1ee9c63906fa200bc735098d47d
    Merge: 160062e19001 fc280fe87144
    Author: Linus Torvalds <torvalds@linux-foundation.org>
    Date:   Thu Apr 20 15:31:08 2017 -0700

    or fetch/build the ristretto branch from https://github.com/connojd/linux

* Build/install the kernel

* Run the following:
    cd ~/ristretto-pt
    git clone https://github.com/connojd/processor-trace.git
    git clone https://github.com/intelxed/xed.git
    git clone https://github.com/intelxed/mbuild.git

    mkdir build
    cd build
    ../xed/mfile.py

* processor-trace must be configured with cmake -DRISTRETTO_PT ..
