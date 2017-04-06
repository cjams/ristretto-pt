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
#include <pthread.h>
#include <intel-pt.h>
#include <assert.h>
#include <signal.h>
#include "cyc.h"

#include "/home/srdavos/src/linux/usr/include/linux/perf_event.h"

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

struct trace {
  struct perf_event_attr * event;
  struct perf_event_mmap_page * header;
  void * base;
  void * data;
  void * aux;
  int fd;
};

struct flow_monitor {
    /* Data for reconstructing control-flow */
    struct pt_insn_decoder *decoder;
    struct pt_config *config;
    struct pt_image *image;
    struct pt_image_section_cache *iscache;
    const struct trace *trace;

    /* Data for the file backing the code section */
    uint64_t foffset;
    uint64_t fsize;
    uint64_t fbase;
    char *fname;
    int codefd; /* fd for code thats executing forward-only */
    int isid;

    /* thread that decodes trace online and enforces forward-only */
    pthread_t *thread;

    /* start & end addresses for forward-only execution */
    uint64_t fwdstart;
    uint64_t fwdend;
};

extern void diagnose_insn(const char *errtype, struct pt_insn_decoder *decoder,
			  struct pt_insn *insn, int errcode);

// pid == 0, cpu == -1  ::  measures calling process/thread on any CPU

int perf_event_open(struct perf_event_attr * attr, pid_t pid, int cpu, int group_fd, unsigned long flags);

int test_func(int i) {
  int inc = 0;
  for (1; i < 10; i++) {
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
}

//int alloc_aux_buffer(struct trace * trace)
//{
//
//}

int init_trace(struct trace * trace)
{
  printf("%s\n", "Initializing trace capture");

  trace->event = malloc(sizeof(struct perf_event_attr));
  if (trace->event == NULL) return 1;

  //branch_trace_capture_init(trace->event);
  pt_capture_init(trace->event);

  trace->fd = syscall(__NR_perf_event_open, trace->event, 0, -1, -1, 0);
  if (trace->fd == -1) {
    perror("syscall errno:\n");
    printf("syscall error: %d\n", errno);
  }

  map_userspace(trace);

//  alloc_aux_buffer(trace);

  return 0;
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
}

void * ristretto_trace_start(unsigned long start, unsigned long end)
{
  ssize_t ret;
  struct trace * trace;
  trace = malloc(sizeof(struct trace));

  if (trace == NULL) return NULL;
  memset(trace, 0, sizeof(struct trace));

  init_trace(trace);

  ret = ioctl(trace->fd, PERF_EVENT_IOC_CR3_FILTER, 0);
  if (ret != 0) {
    perror("CR3 filter");
  } else {
    printf("%s", "Intel PT cr3 filter enabled\n");
  }

  ret = ioctl(trace->fd, PERF_EVENT_IOC_IP_FILTER_BASE, start);
  if (ret != 0) {
    perror("IP filter base");
  } else {
    printf("%s", "Intel PT IP filter base set\n");
  }

  ret = ioctl(trace->fd, PERF_EVENT_IOC_IP_FILTER_LIMIT, end);
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
  unsigned long trace_data;

  if (trace == NULL) {
    printf("%s", "Failed to parse trace, NULL trace pointer\n");
    return 1;
  }

  ret = read(trace->fd, &results, 32);
  printf("read trace fd: ret %d result: 0x%x\n", ret, results[0]);

  parse_event_headers(trace);

  header = trace->header;

  printf("==========================\n");
  printf("mmap data_offset: %llx\n", trace->header->data_offset);
  printf("mmap data_size: %llx\n", trace->header->data_size);
  printf("mmap data_head: %llx\n", trace->header->data_head);
  printf("mmap data_tail: %llx\n", trace->header->data_tail);

  printf("mmap aux_offset: %llx\n", trace->header->aux_offset);
  printf("mmap aux_size: %llx\n", trace->header->aux_size);
  printf("mmap aux_head: %llx\n", trace->header->aux_head);
  printf("mmap aux_tail: %llx\n", trace->header->aux_tail);

  do {
    char * ad = trace->aux;
    trace_data = header->aux_head;
    rmb();
    fwrite(ad, 1, trace_data, stderr);
  } while (0);

  return 0;
}

int ristretto_trace_cleanup(void * tr)
{
  struct trace * trace = tr;
  if (trace == NULL) {
    printf("%s", "Failed to cleanup trace, NULL trace pointer\n");
    return 1;
  }
  close(trace->fd);
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

  init_trace(&trace);

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
}

void init_iscache(struct pt_image_section_cache **iscache)
{
    *iscache = pt_iscache_alloc(NULL);

    if (!*iscache) {
        fprintf(stderr, "ERROR: pt_iscache_alloc() failed.\n");
    }
}

void init_image(struct pt_image **img)
{
    *img = pt_image_alloc(NULL);

    if (!*img) {
        fprintf(stderr, "ERROR: pt_image_alloc() failed.\n");
    }
}

void init_config(struct pt_config **config, struct trace *tr)
{
    *config = calloc(1, sizeof(struct pt_config));

    if (!*config) {
        fprintf(stderr, "ERROR: calloc(1, sizeof(struct pt_config)) failed.\n");
        return;
    }

    pt_config_init(*config);
    (*config)->begin = tr->aux;

    /*
     * aux->head is constantly changing at this point, so we set to
     * end = aux + aux_size
     */
    (*config)->end = (uint8_t *)tr->aux + tr->header->aux_size - 1;
}

void init_decoder(struct pt_insn_decoder **dec, struct pt_config *config)
{
    *dec = pt_insn_alloc_decoder(config);

    if (!*dec) {
        fprintf(stderr, "ERROR: pt_insn_alloc_decoder() failed.\n");
    }
}

int sync_decoder(struct pt_insn_decoder *dec)
{
    int ret;

    ret = pt_insn_sync_forward(dec);

    if (ret < 0) {
        fprintf(stderr, "ERROR: pt_insn_sync_forward: ret = %d\n", ret);
    }

    return ret;
}

int init_block_file(const uint8_t *addr, long len, struct flow_monitor *mon)
{
    int ret, fd, isid;
    uint64_t foffset, base;

    assert(len > 0);

    foffset = base = 0;
    mon->fname = "__ris_fwd_only__";
    fd = open(mon->fname, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        perror("ERROR: init_block_file:");
        return fd;
    }

    if ((ret = write(fd, addr, len)) != len) {
        fprintf(stderr,
            "WARNING: wrote %d bytes but %ld were requested", ret, len);
        goto end;
    }

    isid = pt_iscache_add_file(mon->iscache, mon->fname, foffset, len, base);
    if (isid < 0) {
        fprintf(stderr, "ERROR: pt_iscache_add_file failed");
	goto end;
    }

    ret = pt_image_add_cached(mon->image, mon->iscache, isid, NULL);
    if (ret < 0) {
        fprintf(stderr, "ERROR: pt_image_add_cached failed");
        goto end;
    }

    mon->fsize = (uint64_t)len;
    mon->foffset = mon->fbase = 0;
    mon->isid = isid;
    mon->codefd = fd;
    return fd;

end:
    close(fd); return -1;
}

void close_file(int fd)
{
    if (fd >= 0) {
        close(fd);
    }
}


void free_flow_monitor(struct flow_monitor *mon)
{
    assert(mon != NULL);

    close_file(mon->codefd);
    pt_iscache_free(mon->iscache);
    pt_image_free(mon->image);
    pt_insn_free_decoder(mon->decoder);

    if (mon->config) free(mon->config);
    if (mon->thread) free(mon->thread);

    free(mon);
}

/**
 * @mtr - flow_monitor
 */
void * enforce_fwd_only(void *mtr)
{
    uint64_t sync, new_sync, addr;
    struct flow_monitor *mon = mtr;
    int ret;

    sync = 0ull;
    addr = mon->fwdstart;
    while(1) {
        struct pt_insn insn;

        ret = pt_insn_sync_forward(mon->decoder);
        if (ret < 0) {
            if (ret == -pte_eos) {
                fprintf(stderr, "pt_insn_sync_forward: ret = pte_eos\n");
                break;
            }

            diagnose_insn("sync error", mon->decoder, &insn, ret);
            ret = pt_insn_get_offset(mon->decoder, &new_sync);
            if (ret < 0 || new_sync <= sync) {
                break;
            }

            sync = new_sync;
            continue;
        }

        while(1) {
            ret = pt_insn_next(mon->decoder, &insn, sizeof(insn));
            if (ret < 0) {
                if (ret == -pte_eos) {
                    fprintf(stderr, "pt_insn_next: ret = pte_eos\n");
                    return (void *)0;
                }

                fprintf(stderr, "pt_insn_next: ret = %d\n", ret * -1);
                break;
            }

            if (addr > insn.ip) {
                fprintf(stderr, "FATAL: forward-only violation detected\n");
                return (void *)pthread_kill(pthread_self(), SIGKILL);
            }

            if (insn.ip >= mon->fwdend) {
                fprintf(stdout, "DEBUG: insn.ip: %lu fwdend: %lu",
                    insn.ip, mon->fwdend);
                fprintf(stdout, "DEBUG: Leaving flow monitor thread");
                return (void *)0;
            }

            fprintf(stdout, "DEBUG: insn.ip: %lu fwdend: %lu",
                insn.ip, mon->fwdend);
            addr = insn.ip;
        }
    }

    fprintf(stdout, "DEBUG: ret: %d", ret * -1);
    return (void *)ret;
}

/**
 * @tr - read-only pt trace
 * @addr - address of code block that requires forward-only execution
 * @len - length of code block that requires forward-only execution
 */
void * enforcement_start(void *tr, void *addr, long len)
{
    int ret;
    struct flow_monitor *mtr = NULL;

    mtr = calloc(1, sizeof(struct flow_monitor));
    if (!mtr) {
        fprintf(stderr, "ERROR: calloc(1, sizeof(struct flow_monitor)) failed");
        return NULL;
    }

    init_iscache(&mtr->iscache);
    init_image(&mtr->image);
    init_config(&mtr->config, tr);
    init_decoder(&mtr->decoder, mtr->config);

    if (!(mtr->iscache && mtr->image && mtr->config && mtr->decoder)) {
        goto end;
    }

    if (init_block_file(addr, len, mtr) < 0) {
        goto end;
    }

    ret = pt_insn_set_image(mtr->decoder, mtr->image);
    if  (ret < 0) {
        goto end;
    }

//    ret = sync_decoder(decoder);
//    if (ret < 0) {
//        goto end;
//    }
    mtr->thread = calloc(1, sizeof(pthread_t));
    if (!mtr->thread) {
        fprintf(stderr, "ERROR: calloc(1, sizeof(pthread_t)) failed");
        goto end;
    }

    mtr->trace = tr;
    mtr->fwdstart = (uint64_t)addr;
    mtr->fwdend = mtr->fwdstart + len - 1;

    if (pthread_create(mtr->thread, NULL, enforce_fwd_only, (void *)mtr) < 0) {
        printf("pthread_create failed: ret = %d, errno = %d\n", ret, errno);
        goto end;
    }

    return mtr;

end:
    free_flow_monitor(mtr);
    return NULL;
}

void enforcement_stop(void *mtr)
{
    assert(mtr != NULL);

    /* for now we just tear everything down */
    free_flow_monitor((struct flow_monitor *)mtr);
}
