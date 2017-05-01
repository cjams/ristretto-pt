# Ristretto Processor Trace

## Intro

A library for tracing program execution and parsing the results for the purpose of detecting unexpected branches.

## ptdump abbreviations

TNT -- Conditional branch
TIP -- Indirect branches / function returns
TIP.PGE -- packet generation enabled
TIP.PGD -- packet generation disabled
FUP -- Asynchronous event locations
MODE.TSX -- transactional state

## Build

* Apply the ristretto-filters.patch to the following linux kernel commit:

    commit c154165e93b7f1ee9c63906fa200bc735098d47d
    Merge: 160062e19001 fc280fe87144
    Author: Linus Torvalds <torvalds@linux-foundation.org>
    Date:   Thu Apr 20 15:31:08 2017 -0700

    or fetch/build the ristretto branch from https://github.com/connojd/linux. Note
    that the patch assumes that IP filtering and CR3 filtering are supported
    on your machine.  To check, cat /sys/devices/intel_pt/caps/{cr3_filtering,ip_filtering}.
    If both return 1, you're good to go.

* Build/install the kernel and modules, then copy usr/include/linux/perf_event.h
  from the kernel build directory to ./include/perf_event.h

* Ensure cmake and python are in your PATH.

* To compile with debug output, export RISTRETTO_DEBUG=1. Then run the following:

    ./setup && make

* Notes

    Compiling with debug output will activate print statements throughout libipt and
    libristretto, as well as dump three files for debug inspection.  config_dump
    is the output of the config buffer, which is used by the decoder during decoding.
    config_dump should be identical to the trace_aux_dump file, which contains the trace from
    the kernel.  You may analyze these file with ptdump to ensure they look ok.  The last
    file is memfd_dump, which is the raw binary of the function/code block that is being
    executed forward-only. You can disassemble this to ensure it looks as expected.
