#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <asm/unistd.h>
#include <sys/mman.h>
#include <asm/msr.h>
#include <linux/hw_breakpoint.h>
#include <assert.h>

#include <rtrace.h>

/*
/sys/bus/event_source/devices/intel_pt/format/cyc:config:1
/sys/bus/event_source/devices/intel_pt/format/cyc_thresh:config:19-22
/sys/bus/event_source/devices/intel_pt/format/mtc:config:9
/sys/bus/event_source/devices/intel_pt/format/mtc_period:config:14-17
/sys/bus/event_source/devices/intel_pt/format/noretcomp:config:11
/sys/bus/event_source/devices/intel_pt/format/psb_period:config:24-27
/sys/bus/event_source/devices/intel_pt/format/tsc:config:10
*/
#define PT_CYC (1 << 1)
#define PT_MTC (1 << 9)
#define PT_TSC (1 << 10)
#define PT_NORETCOMP (1 << 11)

// pid == 0, cpu == -1  ::  measures calling process/thread on any CPU

int perf_event_open(struct perf_event_attr * attr, pid_t pid, int cpu, int group_fd, unsigned long flags);

int test_func(int i) {
  int inc = 0;
  for (; i < 10; i++) {
    if (i %2 == 0) inc++;
  }
  return inc;
}


//--------------------
// DUMP
//--------------------
int dump_hex(void * d)
{
  unsigned int * results = d;

  printf("0x%x 0x%x\n", results[0], results[1]);
  printf("0x%x 0x%x\n", results[2], results[3]);
  printf("0x%x 0x%x\n", results[4], results[5]);
  printf("0x%x 0x%x\n", results[6], results[7]);
  printf("0x%x 0x%x\n", results[8], results[9]);
  printf("0x%x 0x%x\n", results[10], results[11]);
  printf("0x%x 0x%x\n", results[12], results[13]);
  printf("0x%x 0x%x\n", results[14], results[15]);
  return 0;
}

struct perf_event_mmap_page * header;
void * base, * data, * aux;

int map_userspace(struct trace * trace)
{
  if (trace->fd < 0)
    return -1;
  trace->base = mmap(NULL, (1+8) * getpagesize(), PROT_WRITE, MAP_SHARED, trace->fd, 0);
  if (trace->base == MAP_FAILED)
    return -1;

  trace->header_size = 9 * getpagesize();
  trace->header = trace->base;
  trace->data = trace->base + trace->header->data_offset;
  trace->header->aux_size = 4 * getpagesize();
  printf("mmap data_offset: %llx\n", trace->header->data_offset);
  printf("mmap data_size: %llx\n", trace->header->data_size);
  printf("mmap data_head: %llx\n", trace->header->data_head);
  printf("mmap data_tail: %llx\n", trace->header->data_tail);

  printf("mmap aux_offset: %llx\n", trace->header->aux_offset);
  printf("mmap aux_size: %llx\n", trace->header->aux_size);
  printf("mmap aux_head: %llx\n", trace->header->aux_head);
  printf("mmap aux_tail: %llx\n", trace->header->aux_tail);

  trace->header->aux_offset = 9 * getpagesize();
  trace->aux = mmap(NULL, trace->header->aux_size, PROT_READ, MAP_SHARED, trace->fd, trace->header->aux_offset);
  if (trace->aux == MAP_FAILED) {
    printf("failed to map aux\n");
    return -1;
  }

  return 0;
}

int parse_event_header(void * head);

#define EVENT_TYPE_INTEL_BTS 0x6
#define EVENT_TYPE_INTEL_PT 0x7

int perf_event_init(struct perf_event_attr * pe)
{
  if (pe == NULL)
    return 1;
  memset(pe, 0, sizeof(struct perf_event_attr));

  pe->disabled = 1;
  pe->size = sizeof(struct perf_event_attr);
  pe->exclude_kernel = 1;
  pe->exclude_hv = 1;
  pe->exclude_idle = 1;
  pe->sample_id_all = 1;
  pe->read_format = PERF_FORMAT_ID;
  pe->precise_ip = 1;
  return 0;
}

int branch_trace_capture_init(struct perf_event_attr * pe)
{
  //struct perf_event_header * event_head;

  perf_event_init(pe);

  pe->type = EVENT_TYPE_INTEL_BTS;
  pe->sample_type = PERF_SAMPLE_BRANCH_STACK;
  pe->config = PERF_COUNT_HW_BRANCH_INSTRUCTIONS;
  //pe->branch_sample_type = PERF_SAMPLE_BRANCH_ANY;
  //sybts.bp_type = HW_BREAKPOINT_X;
  return 0;
}

int pt_capture_init(struct perf_event_attr * pe)
{
  perf_event_init(pe);
  pe->type = EVENT_TYPE_INTEL_PT;
  //pe->sample_type = PERF_SAMPLE_IP;
  pe->sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CPU | PERF_SAMPLE_IDENTIFIER | PERF_SAMPLE_ADDR;
  pe->config = PT_TSC | PT_NORETCOMP;
  // pe->config = PT_NORETCOMP | PERF_COUNT_HW_BRANCH_INSTRUCTIONS
  //pe->aux_watermark = 0x4000;
  return 0;
}

int init_trace(struct trace * trace, char *start, char *end)
{
  printf("%s\n", "Initializing trace capture");

  trace->event = malloc(sizeof(struct perf_event_attr));
  if (trace->event == NULL) return -1;

  //branch_trace_capture_init(trace->event);
  pt_capture_init(trace->event);

  trace->fd = syscall(__NR_perf_event_open, trace->event, 0, -1, -1, 0);
  if (trace->fd == -1) {
    perror("syscall errno:");
    free(trace->event);
    trace->event = NULL;
    return -1;
  }

  map_userspace(trace);

  trace->monitor = flow_monitor_alloc();
  if (trace->monitor == NULL) {
    fprintf(stderr, "ERROR: flow_monitor_alloc failed\n");
    ristretto_trace_cleanup(trace);
    return -1;
  }

  /* this has to be called once and only once in the process */
  xed_tables_init();

  return flow_monitor_start(trace, start, end);
}

int parse_event_headers(struct trace * trace)
{
  struct perf_event_header * event_head;
  struct perf_event_mmap_page * header = trace->header;

  event_head = (void*)header + (u64)header->data_offset;

  while ((void*)event_head < ((void*)header + header->data_offset + header->data_size) &&
	 event_head->type != 0) {
    parse_event_header(event_head);
    event_head = (void*)event_head + event_head->size;
  }
  return 0;
}

void * ristretto_trace_start(char *start, char *end)
{
  ssize_t ret;
  struct trace * trace;

  trace = calloc(1, sizeof(struct trace));
  if (trace == NULL) return NULL;

  if (init_trace(trace, start, end) < 0) {
    fprintf(stderr, "ERROR: init_trace");
    free(trace);
    return NULL;
  }

  ret = ioctl(trace->fd, PERF_EVENT_IOC_CR3_FILTER, 0);
  if (ret != 0) {
    perror("CR3 filter");
  } else {
    printf("%s", "Intel PT cr3 filter enabled\n");
  }

  ret = ioctl(trace->fd, PERF_EVENT_IOC_IP_FILTER_BASE, (u64)start);
  if (ret != 0) {
    perror("IP filter base");
  } else {
    printf("%s", "Intel PT IP filter base set\n");
  }

  ret = ioctl(trace->fd, PERF_EVENT_IOC_IP_FILTER_LIMIT, (u64)end);
  if (ret != 0) {
    perror("IP filter limit");
  } else {
    printf("%s", "Intel PT IP filter limit set\n");
  }

  ret = ioctl(trace->fd, PERF_EVENT_IOC_ENABLE, 0);
  if (ret != 0) {
    printf("ioctl enable: %ld %d\n", ret, errno);
  } else {
    printf("%s", "Intel PT enabled\n");
  }

  return trace;
}

int ristretto_trace_stop(void * tr)
{
  int ret;
  struct trace * trace = tr;
  if (trace == NULL) {
    printf("%s", "Failed to stop trace, NULL trace pointer\n");
    return 1;
  }

  ret = ioctl(trace->fd, PERF_EVENT_IOC_DISABLE, 0);
  if (ret != 0) {
    printf("ioctl disable: %d %d\n", ret, errno);
  } else {
    printf("Intel PT disabled\n");
  }
  return 0;
}

int ristretto_trace_parse(void * tr)
{
  int ret;
  int results[8] = {0};
  struct trace * trace = tr;
  struct perf_event_mmap_page * header;
  struct pt_config *config;

  if (trace == NULL) {
    printf("%s", "Failed to parse trace, NULL trace pointer\n");
    return -1;
  }

  ret = read(trace->fd, &results, 32);
  printf("read trace fd: ret %d result: 0x%x\n", ret, results[0]);

  parse_event_headers(trace);

  header = trace->header;

#ifdef RISTRETTO_DEBUG
  printf("==========================\n");
  printf("mmap data_offset: %llx\n", trace->header->data_offset);
  printf("mmap data_size: %llx\n", trace->header->data_size);
  printf("mmap data_head: %llx\n", trace->header->data_head);
  printf("mmap data_tail: %llx\n", trace->header->data_tail);

  printf("mmap aux_offset: %llx\n", trace->header->aux_offset);
  printf("mmap aux_size: %llx\n", trace->header->aux_size);
  printf("mmap aux_head: %llx\n", trace->header->aux_head);
  printf("mmap aux_tail: %llx\n", trace->header->aux_tail);

  int aux_dump = open("trace_aux_dump", DEBUG_FILE_FLAGS, DEBUG_FILE_MODE);
  write(aux_dump, trace->aux, trace->header->aux_head);
  close(aux_dump);
#endif

  config = trace->monitor->config;
  if (config == NULL) {
    fprintf(stderr, "NULL monitor->config\n");
    return -1;
  }

  config->end = config->begin + header->aux_head - 1;
  rmb();

  enforce_fwd_only(trace);

  return 0;
}

int ristretto_trace_cleanup(void * tr)
{
  struct trace * trace = tr;
  if (trace == NULL) {
    printf("%s", "Failed to cleanup trace, NULL trace pointer\n");
    return 1;
  }

  flow_monitor_cleanup(trace->monitor);
  close(trace->fd);
  munmap(trace->header, trace->header_size);
  munmap(trace->aux, trace->header->aux_size);
  free(trace->event);
  free(trace);

  return 0;
}

//-----------------------------------
//
//-----------------------------------
int main_test(int argc, char ** argv)
{
  int fd, reti, inc;
  ssize_t ret;
  int results[8] = {0};
  u64 pmcr;

  struct trace trace = {0};
  struct perf_event_header * event_head;
  //struct perf_event_attr attr;
  //struct perf_event_mmap_page mmap_page;

//  init_trace(&trace);

  /*
  reti = ioctl(fd, PERF_EVENT_IOC_RESET, 0);
  if (reti != 0) {
    printf("ioctl reset: %d, %d\n", reti, errno);
  }
  */

  //  ENABLE
  reti = ioctl(trace.fd, PERF_EVENT_IOC_ENABLE, 0);

  if (reti != 0) {
    printf("ioctl enable: %d %d\n", reti, errno);
  } else {
    printf("Intel PT enabled\n");
  }

  //printf("test_func ADDR 0x%lx\n", (u64)test_func);
  test_func(3);

  //pmcr = read_pmc(header);
  //printf("PMCR: %lx\n", pmcr);

  //  DISABLE
  ioctl(trace.fd, PERF_EVENT_IOC_DISABLE, 0);
  if (reti != 0) {
    printf("ioctl reset: %d %d\n", reti, errno);
  } else {
    printf("Intel PT disabled\n");
  }

  ret = read(trace.fd, &results, 32);
  printf("read trace fd: ret %ld result: 0x%x\n", ret, results[0]);

  //printf("base\n");
  //dump_hex(base);

  printf("data_head %llx\n", trace.header->data_head);
  printf("data_offset %llx\n", trace.header->data_offset);
  printf("data_size %llx\n", trace.header->data_size);

  parse_event_headers(&trace);

  printf("aux head: %llx, tail: %llx, offset: %llx, size: %llx\n", trace.header->aux_head, trace.header->aux_tail, trace.header->aux_offset, trace.header->aux_size);
  printf("AUX\n");
  header = trace.header;

  do {
    int i = 0;
    char * ad = trace.aux;
    for ( i = 0; i < header->aux_head; i+=16) {
      printf("0x%lx 0x%lx\n", *(u64*)&ad[i], *(u64*)&ad[i+8]);
    }
  } while (0);

  // copy raw bytes for analysis
  /*
  do {
    char * ad = trace.aux;
    fwrite(ad, 1, header->aux_head, stderr);
  } while (0);
  */
  close(fd);
  return 0;
}


int parse_event_header(void * head)
{
  struct perf_event_header * event_head = head;
  char * data = (void*)&event_head[1];

  //printf("event_head type: %d misc: %d size: %d\n", event_head->type, event_head->misc, event_head->size);
  switch(event_head->type) {

  case PERF_RECORD_ITRACE_START:
    {
      u32 * pid = (u32 *)&event_head[1];
      u32 * tid = &(pid[1]);
      printf("ITRACE START -- pid: %d(%x) tid: %d(%x)\n", *pid, *pid, *tid, *tid);
      dump_hex(tid);
      break;
    }
  case PERF_RECORD_AUX:
    {
      u64 * aux_offset = (u64 *)&event_head[1];
      u64 * aux_size = &(aux_offset[1]);
      u64 * flags = &(aux_size[1]);
      struct sample_id * sample = (void*)&(flags[1]);
      // flags PERF_AUX_FLAG_TRUNCATED = 1, PERF_AUX_FLAG_OVERWRITE = 2
      printf("RECORD_AUX -- offset: %lx, size: %lx, flags %lx\n", *aux_offset, *aux_size, *flags);
      dump_hex(sample);
      break;
    }
  default:
    printf("EVENT_HEADER_DEFAULT %x\n", event_head->type);
    break;
  }
  event_head = (void*)event_head + event_head->size;
  dump_hex(event_head);
  return 0;
}
