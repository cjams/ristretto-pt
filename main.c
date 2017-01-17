#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <sys/mman.h>
#include <asm/msr.h>
#include <linux/hw_breakpoint.h>
#include "cyc.h"

typedef unsigned int u32;
typedef unsigned long int u64;
typedef long int s64;

#define rmb()asm volatile("lfence":::"memory")

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
/*
struct perf_event_attr {
  .type
  .size
  .config
  .sample_period
   //.sample_freq
  .sample_type
  .read_format

  .disabled
  .inherit
  .pinned
  .exclusive
  .exclude_user
  .exclude_kernel
  .exclude_hv
  .exclude_idle
  .mmap
  .comm
  .freq
  .inherit_stat
  .enable_on_exec
  .task
  .watermark
  .precise_ip
  .mmap_data
  .sample_id_all
  .exclude_host
  .exclude_guest
  .exclude_callchain_kernel
  .exclude_callchain_user
  .mmap2
  .comm_exec
  .use_clockid

  .wakeup_events
   //.wakeup_watermark

  .bp_type

  .bp_addr
   //.config2

  .branch_sample_type
  .sample_regs_user
  .sample_stack_user
  .clockid
  .sample_regs_intr
  .aux_watermark
  
};
*/
int test_func(int i) {
  int inc = 0;
  for (1; i < 10; i++) {
    if (i %2 == 0) inc++;
  }
  return inc;
}

/*
perf_event_header 

misc

PERF_RECORD_MISC_CPUMODE_MASK
PERF_RECORD_MISC_CPUMODE_UNKNOWN
PERF_RECORD_MISC_KERNEL
PERF_RECORD_MISC_USER
PERF_RECORD_MISC_HYPERVISOR
PERF_RECORD_MISC_GUEST_KERNEL
PERF_RECORD_MISC_GUEST_USER
PERF_RECORD_MISC_MMAP_DATA
PERF_RECORD_MISC_COMM_EXEC
PERF_RECORD_MISC_EXACT_IP
PERF_RECORD_MISC_EXT_RESERVED

types

PERF_RECORD_MMAP
PERF_RECORD_LOST
PERF_RECORD_COMM
PERF_RECORD_EXIT
PERF_RECORD_THROTTLE/UNTHROTTLE
PERF_RECORD_FORK
PERF_RECORD_READ
PERF_RECORD_SAMPLE
PERF_RECORD_MMAP2
PERF_RECORD_AUX
PERF_RECORD_ITRACE_START
*/
struct perf_event_mmap_page * header;
void * base, * data, * aux;

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

static u64 rdpmc(unsigned int counter)
{
  unsigned int low, high; 
  asm volatile("rdpmc" : "=a" (low), "=d" (high) : "c" (counter));
  return low | ((u64)high) << 32;
}

static unsigned long long read_pmc(struct perf_event_mmap_page * pc)
{
  u32 seq, time_mult, time_shift, index, width;
  u64 count, enabled, running;
  u64 cyc, time_offset;
  s64 pmc = 0;

  do {
    seq = pc->lock;
    rmb();
    enabled = pc->time_enabled;
    running = pc->time_running;

    if (pc->cap_user_time && enabled != running) {
      cyc = get_cycles();//rdtsc();
      time_offset = pc->time_offset;
      time_mult = pc->time_mult;
      time_shift = pc->time_shift;
    }
    index = pc->index;
    count = pc->offset;
    if (pc->cap_user_rdpmc && index) {
      width = pc->pmc_width;
      pmc = rdpmc(index-1);
    }
    rmb();
  } while (pc->lock != seq);
  return pmc;
}

int map_userspace(int fd)
{
  base = mmap(NULL, (1+8) * getpagesize(), PROT_WRITE, MAP_SHARED, fd, 0);
  if (base == MAP_FAILED)
    return -1;

  header = base;
  data = base + header->data_offset;
  header->aux_size = 4 * getpagesize();
  printf("mmap data_offset: %llx\n", header->data_offset);
  printf("mmap data_size: %llx\n", header->data_size);
  printf("mmap aux_offset: %llx\n", header->aux_offset);
  header->aux_offset = 9 * getpagesize();
  aux = mmap(NULL, header->aux_size, PROT_READ, MAP_SHARED, fd, header->aux_offset);
  if (aux == MAP_FAILED) {
    printf("failed to map aux\n");
    return -1;
  }
  
  
  return 0;
}

int parse_event_header(void * head);

int main(int argc, char ** argv)
{
  int fd, reti, inc;
  long long count = 0;
  ssize_t ret;
  int results[8] = {0};
  u64 pmcr;
  struct perf_event_header * event_head;
  struct perf_event_attr attr;
  struct perf_event_mmap_page mmap_page;

  memset(&attr, 0, sizeof(struct perf_event_attr));
  
  attr.type = 0x7;
  attr.size = sizeof(struct perf_event_attr);
  attr.config = PT_TSC | PT_NORETCOMP;//1024; //PERF_COUNT_HW_BRANCH_INSTRUCTIONS;
  // attr.sample_type = PERF_SAMPLE_IP; // PERF_SAMPLE_ADDR, PERF_SAMPLE_BRANCH_STACK, PERF_SAMPLE_IDENTIFIER
  attr.exclude_kernel = 1;
  attr.exclude_hv = 1;
  attr.exclude_idle = 1;
  attr.disabled = 1;
  attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CPU | PERF_SAMPLE_IDENTIFIER;
  attr.sample_id_all = 1;
  attr.read_format = PERF_FORMAT_ID;
  attr.precise_ip = 0;
  //attr.bp_type = HW_BREAKPOINT_X;
  
  fd = syscall(__NR_perf_event_open, &attr, 0, -1, -1, 0);
  //  fd = perf_event_open(&attr, 0, -1, 0, 0);
  if (fd == -1) {
    printf("syscall error: %d\n", errno);
  }

  map_userspace(fd);

  //dump_hex(base);
  /*
  reti = ioctl(fd, PERF_EVENT_IOC_RESET, 0);
  if (reti != 0) {
    printf("ioctl reset: %d, %d\n", reti, errno);
  }
  */
  //  dump_hex


  //----------------------------------------
  //  ENABLE
  //----------------------------------------
  reti = ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  //test_func(3);
  if (reti != 0) {
    printf("ioctl enable: %d %d\n", reti, errno);
  }
  else {
    printf("Intel PT enabled\n");
  }
  
  //printf("ADDR OF TEST %lx\n", test_func);
  printf("Measuring instruction count for this printf %s\n", "test");

  //pmcr = read_pmc(header);
  //printf("PMCR: %lx\n", pmcr);

  //----------------------------------------
  //  DISABLE
  //----------------------------------------
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  if (reti != 0) {
    printf("ioctl reset: %d %d\n", reti, errno);
  }

  ret = read(fd, &results, 32);
  
  printf("Used %lld instructions. ret:%ld\n", count, ret);
  printf("0x%x 0x%x\n", results[0], results[1]);
  printf("0x%x 0x%x\n", results[2], results[3]);
  printf("0x%x 0x%x\n", results[4], results[5]);
  printf("0x%x 0x%x\n", results[6], results[7]);
  //printf("base\n");
  //dump_hex(base);
  
  
  printf("data_head %llx\n", header->data_head);
  printf("data_offset %llx\n", header->data_offset);
  printf("data_size %llx\n", header->data_size);

  event_head = (void*)header + (u64)header->data_offset;

  while ((void*)event_head < ((void*)header + header->data_offset + header->data_size) &&
	 event_head->type != 0) {
    parse_event_header(event_head);
    event_head = (void*)event_head + event_head->size;
  }
  /*
  printf("type %x\n", event_head->type);
  printf("misc: %x size: %x\n", event_head->misc, event_head->size);

  event_head = (void*)event_head + event_head->size;
  //event_head = aux;
  dump_hex((void*)event_head);
  printf("type %x\n", event_head->type);
  printf("misc: %x size: %x\n", event_head->misc, event_head->size);
  */

  printf("aux head: %llx, tail: %llx, offset: %llx, size: %llx\n", header->aux_head, header->aux_tail, header->aux_offset, header->aux_size);
  printf("AUX\n");
  do {
    int i = 0;
    char * ad = aux;
    for ( i = 0; i < header->aux_head; i+=16) {
      printf("0x%lx 0x%lx\n", *(u64*)&ad[i], *(u64*)&ad[i+8]);
    }
  } while (0);

  do {
    char * ad = aux;
    fwrite(ad, 1, header->aux_head, stderr);
  } while (0);
  /*
  dump_hex((void*)aux);
  dump_hex((void*)aux + 128);
  dump_hex((void*)aux + header->aux_size);
  dump_hex((void*)aux + header->aux_size + 64);
  */
  close(fd);
}


int parse_event_header(void * head)
{
  struct perf_event_header * event_head = head;
  char * data = (void*)&event_head[1];
  
  printf("event_head type: %d misc: %d size: %d\n", event_head->type, event_head->misc, event_head->size);
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
      printf("RECORD_AUX -- offset: %lx, size: %lx, flags %lx\n", *aux_offset, *aux_size, *flags);
      dump_hex(sample);
      break;
    }
  default:
    printf("EVENT_HEADER_DEFAULT\n");
    break;
  }
  //event_head = (void*)event_head + event_head->size;
  //dump_hex(event_head);
}
