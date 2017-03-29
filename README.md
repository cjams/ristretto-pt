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



