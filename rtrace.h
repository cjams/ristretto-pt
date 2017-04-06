#ifndef RTRACE_H
#define RTRACE_H

void * ristretto_trace_start(unsigned long start, unsigned long end);
int ristretto_trace_stop(void * tr);
int ristretto_trace_parse(void * tr);
int ristretto_trace_cleanup(void * tr);

void * enforcement_start(void *tr, void *addr, long len);
void enforcement_stop(void *mtr);

#endif
