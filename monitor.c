#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <asm/unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <intel-pt.h>
#include <assert.h>
#include <signal.h>

#include "rtrace.h"
#include "pt_ild.h"
#include "ptxed.h"

extern void diagnose_insn(const char *errtype, struct pt_insn_decoder *decoder,
    struct pt_insn *insn, int errcode);

extern void print_insn(const struct pt_insn *insn, xed_state_t *xed,
    const struct ptxed_options *options, uint64_t offset, uint64_t time);

static struct pt_image_section_cache* init_iscache()
{
    struct pt_image_section_cache *iscache = NULL;

    iscache = pt_iscache_alloc(NULL);
    if (iscache == NULL) {
        fprintf(stderr, "ERROR: pt_iscache_alloc() failed.\n");
    }

    return iscache;
}

static struct pt_image* init_image()
{
    struct pt_image *img = NULL;

    img = pt_image_alloc(NULL);
    if (img == NULL) {
        fprintf(stderr, "ERROR: pt_image_alloc() failed.\n");
    }

    return img;
}

static struct pt_config* init_config(struct trace *tr)
{
    struct pt_config *config = NULL;

    config = calloc(1, sizeof(struct pt_config));
    if (config == NULL) {
        fprintf(stderr, "ERROR: calloc(1, sizeof(struct pt_config)) failed.\n");
        return NULL;
    }

    pt_config_init(config);
    config->begin = tr->aux;
    config->end = (uint8_t *)tr->aux + tr->header->aux_size - 1;

    return config;
}

static struct pt_insn_decoder* init_decoder(struct pt_config *config)
{
    struct pt_insn_decoder *dec = NULL;

    dec = pt_insn_alloc_decoder(config);
    if (dec == NULL) {
        fprintf(stderr, "ERROR: pt_insn_alloc_decoder() failed.\n");
    }

    return dec;
}

static int sync_decoder(struct pt_insn_decoder *dec)
{
    int ret;

    ret = pt_insn_sync_forward(dec);
    if (ret < 0) {
        fprintf(stderr, "ERROR: pt_insn_sync_forward: ret = %d\n", ret);
    }

    return ret;
}

static int init_block_file(struct flow_monitor *mon)
{
    int ret, fd, isid;
    long len;

    len = mon->fwdend - mon->fwdstart + 1;
    assert(mon->fwdend > mon->fwdstart && len > 0);

    mon->foffset = 0;
    mon->fname = "fwd_only_code";
    fd = syscall(__NR_memfd_create, mon->fname, 0);
    if (fd < 0) {
        perror("ERROR: memfd_create:");
        return fd;
    }

    if ((ret = write(fd, mon->addr, len)) != len) {
        fprintf(stderr, "WARNING: wrote %d bytes but %ld were requested", ret, len);
        goto end;
    }

    mon->fsize = (u64)len;
    lseek(fd, mon->foffset, SEEK_SET);

    isid = pt_iscache_add_file_fd(mon->iscache, mon->fname, mon->foffset, len, mon->fwdstart, fd);
    if (isid < 0) {
        fprintf(stderr, "ERROR: pt_iscache_add_file_fd failed: isid == %d\n", isid);
	goto end;
    }

    mon->isid = isid;
    ret = pt_image_add_cached(mon->image, mon->iscache, mon->isid, NULL);
    if (ret < 0) {
        fprintf(stderr, "ERROR: pt_image_add_cached failed");
        goto end;
    }

    mon->codefd = fd;
    return fd;

end:
    close(fd); return -1;
}

static void close_file(int fd)
{
    if (fd >= 0) {
        close(fd);
    }
}

void flow_monitor_free(struct flow_monitor *mtr)
{
    free(mtr);
}

void flow_monitor_cleanup(struct flow_monitor *mtr)
{
    close_file(mtr->codefd);
    pt_iscache_free(mtr->iscache);
    pt_image_free(mtr->image);
    pt_insn_free_decoder(mtr->decoder);
    free(mtr->config);
    flow_monitor_free(mtr);
}

/**
 * @mtr - address of struct flow_monitor
 */
int enforce_fwd_only(struct trace *tr)
{
    printf("Executing enforce_fwd_only...\n");

    xed_state_t xed;
    u64 sync, addr, offset;
    int ret;
    struct ptxed_options options;
    struct flow_monitor *mtr = tr->monitor;
    struct stat st;

    xed_state_zero(&xed);
    sync = 0ull;
    offset = 0ull;
    addr = mtr->fwdstart;
    char memfd_buf[64];

    options.dont_print_insn = 0;
    options.quiet = 0;
    options.att_format = 1;

    int config_dump = open("config_dump", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    if (config_dump == -1)
        perror("ERROR opening config_dump");

    write(config_dump, tr->monitor->config->begin, tr->monitor->config->end - tr->monitor->config->begin + 1);
    close(config_dump);

    fstat(tr->monitor->codefd, &st);
    printf("offset of codefd: %ld\n", lseek(tr->monitor->codefd, 0, SEEK_CUR));
    printf("size   of codefd: %ld\n", st.st_size);

    read(tr->monitor->codefd, memfd_buf, 64);
    int memfd_dump = open("memfd_dump", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    if (memfd_dump == -1)
        perror("ERROR opening memfd_dump");

    write(memfd_dump, memfd_buf, 64);
    close(memfd_dump);

    while(1) {
        struct pt_insn insn;

        insn.ip = 0ull;
        ret = pt_insn_sync_forward(mtr->decoder);
        if (ret < 0) {
            u64 new_sync;

            if (ret == -pte_eos) {
                fprintf(stderr, "pt_insn_sync_forward: ret = pte_eos\n");
                break;
            }

            diagnose_insn("sync error", mtr->decoder, &insn, ret);

            ret = pt_insn_get_offset(mtr->decoder, &new_sync);
            if (ret < 0 || new_sync <= sync) {
                break;
            }

            sync = new_sync;
            continue;
        }

        while(1) {
            ret = pt_insn_next(mtr->decoder, &insn, sizeof(insn));
            if (ret < 0) {
                fprintf(stderr, "pt_insn_next: ret = %d\n", ret * -1);
                break;
            }

            ret = pt_insn_get_offset(mtr->decoder, &offset);
            if (ret < 0) {
                fprintf(stderr, "pt_insn_get_offset: ret = %d\n", ret * -1);
                break;
            }

            fprintf(stdout, "  insn.ip == %lu\n", insn.ip);
            fprintf(stdout, "  addr    == %lu\n", addr);
            fprintf(stdout, "  offset  == %lu\n", offset);

            print_insn(&insn, &xed, &options, offset, 0);

            if (addr > insn.ip) {
                fprintf(stderr, "FATAL: forward-only violation detected\n");
                exit(1);
            }

            if (insn.ip >= mtr->fwdend) {
                fprintf(stdout, "DEBUG (insn.ip >= mtr->fwdend): insn.ip: %lu fwdend: %lu\n",
                    insn.ip, mtr->fwdend);
                return 0;
            }

            addr = insn.ip;
        }
    }

    fprintf(stdout, "DEBUG: ret: %d\n", ret * -1);
    return 0;
}

struct flow_monitor* flow_monitor_alloc()
{
    struct flow_monitor *mtr = NULL;

    mtr = calloc(1, sizeof(struct flow_monitor));
    if (mtr == NULL) {
        fprintf(stderr, "ERROR: calloc(1, struct flow_monitor)) failed");
    }

    return mtr;
}

/**
 * @tr - read-only pt trace
 * @addr - address of code block that requires forward-only execution
 * @len - length of code block that requires forward-only execution
 */
int flow_monitor_start(struct trace *tr, char *start, char *end)
{
    int ret;

    struct flow_monitor *mtr = tr->monitor;
    mtr->iscache = init_iscache();
    mtr->image = init_image();
    mtr->config = init_config(tr);
    mtr->decoder = init_decoder(mtr->config);

    if (!(mtr->iscache && mtr->image && mtr->config && mtr->decoder)) {
        goto err;
    }

    mtr->addr = start;
    mtr->fwdstart = (unsigned long)start;
    mtr->fwdend = (unsigned long)end;

    if (init_block_file(mtr) < 0) {
        goto err;
    }

    ret = pt_insn_set_image(mtr->decoder, mtr->image);
    if  (ret < 0) {
        goto err;
    }

    return 0;

err:
    pt_iscache_free(mtr->iscache);
    pt_image_free(mtr->image);
    pt_insn_free_decoder(mtr->decoder);
    free(mtr->config);
    return -1;
}

void __attribute__((constructor)) init(void)
{
    pt_ild_init();
}
