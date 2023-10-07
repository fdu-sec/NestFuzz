#ifndef _AFL_FUZZ_H_
#define _AFL_FUZZ_H_
#include "android-ashmem.h"
#define MESSAGES_TO_STDOUT

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define _FILE_OFFSET_BITS 64

#include <ctype.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include "alloc-inl.h"
#include "cJSON.h"
#include "chunk.h"
#include "config.h"
#include "debug.h"
#include "hash.h"
#include "hashMap.h"
#include "types.h"
#include "structure_mutation.h"

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
#include <sys/sysctl.h>
#endif /* __APPLE__ || __FreeBSD__ || __OpenBSD__ */

/* For systems that have sched_setaffinity; right now just Linux, but one
   can hope... */

#ifdef __linux__
#define HAVE_AFFINITY 1
#endif /* __linux__ */

#ifndef SIMPLE_FILES
#define CASE_PREFIX "id:"
#else
#define CASE_PREFIX "id_"
#endif /* ^!SIMPLE_FILES */


/* A toggle to export some variables when building as a library. Not very
   useful for the general public. */

#ifdef AFL_LIB
#define EXP_ST
#else
#define EXP_ST static
#endif /* ^AFL_LIB */

/* Lots of globals, but mostly for the status UI and other things where it
   really makes no sense to haul them around as function parameters. */

extern u8 *in_dir,   /* Input directory with test cases  */
    *out_file,       /* File to fuzz, if any             */
    *out_dir,        /* Working & output directory       */
    *sync_dir,       /* Synchronization directory        */
    *sync_id,        /* Fuzzer ID                        */
    *use_banner,     /* Display banner                   */
    *in_bitmap,      /* Input bitmap                     */
    *doc_path,       /* Path to documentation dir        */
    *target_path,    /* Path to target binary            */
    *orig_cmdline,   /* Original command line            */
    *file_extension; /* Extension of .cur_input          */

extern u64 total_mutation;
extern u64 interest_mutation;
extern u64 increase_mutation;

extern u32 exec_tmout; /* Configurable exec timeout (ms)   */
extern u32 hang_tmout; /* Timeout used for hang det (ms)   */

extern u64 mem_limit; /* Memory cap for child (MB)        */

extern u32 cpu_to_bind; /* id of free CPU core to bind      */

extern u32 stats_update_freq; /* Stats update frequency (execs)   */

extern u64 save_enum_number;
extern u64* cur_mutator;
extern Boolean save_mutator;

extern u8 skip_deterministic, /* Skip deterministic stages?       */
    force_deterministic,      /* Force deterministic stages?      */
    use_splicing,             /* Recombine input files?           */
    dumb_mode,                /* Run in non-instrumented mode?    */
    score_changed,            /* Scoring for favorites changed?   */
    kill_signal,              /* Signal that killed the child     */
    resuming_fuzz,            /* Resuming an older fuzzing job?   */
    timeout_given,            /* Specific timeout given?          */
    cpu_to_bind_given,        /* Specified cpu_to_bind given?     */
    not_on_tty,               /* stdout is not a tty              */
    term_too_small,           /* terminal dimensions too small    */
    uses_asan,                /* Target uses ASAN?                */
    no_forkserver,            /* Disable forkserver?              */
    crash_mode,               /* Crash mode! Yeah!                */
    in_place_resume,          /* Attempt in-place resume?         */
    auto_changed,             /* Auto-generated tokens changed?   */
    no_cpu_meter_red,         /* Feng shui on the status screen   */
    no_arith,                 /* Skip most arithmetic ops         */
    shuffle_queue,            /* Shuffle input queue?             */
    bitmap_changed,       /* Time to update bitmap?           */
    qemu_mode,                /* Running in QEMU mode?            */
    skip_requested,           /* Skip request, via SIGUSR1        */
    run_over10m,              /* Run time over 10 minutes?        */
    persistent_mode,          /* Running in persistent mode?      */
    deferred_mode,            /* Deferred forkserver mode?        */
    fast_cal;                 /* Try to calibrate faster?         */

extern s32 out_fd,       /* Persistent fd for out_file       */
    dev_urandom_fd, /* Persistent fd for /dev/urandom   */
    dev_null_fd,    /* Persistent fd for /dev/null      */
    fsrv_ctl_fd,         /* Fork server control pipe (write) */
    fsrv_st_fd;          /* Fork server status pipe (read)   */

extern s32 forksrv_pid, /* PID of the fork server           */
    child_pid,     /* PID of the fuzzed program        */
    out_dir_fd;    /* FD of the lock file              */

extern u8* trace_bits; /* SHM with instrumentation bitmap  */

extern u8 virgin_bits[MAP_SIZE], /* Regions yet untouched by fuzzing */
    virgin_tmout[MAP_SIZE],      /* Bits we haven't seen in tmouts   */
    virgin_crash[MAP_SIZE];      /* Bits we haven't seen in crashes  */

extern u8 var_bytes[MAP_SIZE]; /* Bytes that appear to be variable */

extern s32 shm_id; /* ID of the SHM region             */

extern volatile u8 stop_soon, /* Ctrl-C pressed?                  */
    clear_screen,         /* Window resized?                  */
    child_timed_out;          /* Traced process timed out?        */

extern u32 queued_paths, /* Total number of queued testcases */
    queued_variable,     /* Testcases with variable behavior */
    queued_at_start,     /* Total number of initial inputs   */
    queued_discovered,   /* Items discovered during this run */
    queued_imported,     /* Items imported via -S            */
    queued_favored,      /* Paths deemed favorable           */
    queued_with_cov,     /* Paths with new coverage bytes    */
    pending_not_fuzzed,  /* Queued but not done yet          */
    pending_favored,     /* Pending favored paths            */
    cur_skipped_paths,   /* Abandoned inputs in cur cycle    */
    cur_depth,           /* Current path depth               */
    max_depth,           /* Max path depth                   */
    useless_at_start,    /* Number of useless starting paths */
    var_byte_count,      /* Bitmap bytes with var behavior   */
    current_entry,       /* Current queue entry ID           */
    havoc_div;       /* Cycle count divisor for havoc    */

extern u64 total_crashes, /* Total number of crashes          */
    unique_crashes,       /* Crashes with unique signatures   */
    total_tmouts,         /* Total number of timeouts         */
    unique_tmouts,        /* Timeouts with unique signatures  */
    unique_hangs,         /* Hangs with unique signatures     */
    total_execs,          /* Total execve() calls             */
    slowest_exec_ms,      /* Slowest testcase non hang in ms  */
    start_time,           /* Unix start time (ms)             */
    last_path_time,       /* Time for most recent path (ms)   */
    last_crash_time,      /* Time for most recent crash (ms)  */
    last_hang_time,       /* Time for most recent hang (ms)   */
    last_crash_execs,     /* Exec counter at last crash       */
    queue_cycle,          /* Queue round counter              */
    cycles_wo_finds,      /* Cycles without any new paths     */
    trim_execs,           /* Execs done to trim input files   */
    bytes_trim_in,        /* Bytes coming into the trimmer    */
    bytes_trim_out,       /* Bytes coming outa the trimmer    */
    blocks_eff_total,     /* Blocks subject to effector maps  */
    blocks_eff_select;    /* Blocks selected as fuzzable      */

extern u32 subseq_tmouts; /* Number of timeouts in a row      */

extern u8 *stage_name, /* Name of the current fuzz stage   */
    *stage_short,               /* Short stage name                 */
    *syncing_party;             /* Currently syncing with...        */

extern s32 stage_cur, stage_max; /* Stage progression                */
extern s32 splicing_with;   /* Splicing with which test case?   */

extern u32 master_id, master_max; /* Master instance job splitting    */

extern u32 syncing_case; /* Syncing with case #...           */

extern s32 stage_cur_byte, /* Byte offset of current stage op  */
    stage_cur_val;         /* Value used for stage op          */

extern u8 stage_val_type; /* Value type (STAGE_VAL_*)         */

extern u64 stage_finds[32], /* Patterns found per fuzz stage    */
    stage_cycles[32];       /* Execs per fuzz stage             */

extern u32 rand_cnt; /* Random number counter            */

extern u64 total_cal_us, /* Total calibration time (us)      */
    total_cal_cycles;    /* Total calibration cycles         */

extern u64 total_bitmap_size, /* Total bit count for all bitmaps  */
    total_bitmap_entries;     /* Number of bitmaps counted        */

extern s32 cpu_core_count; /* CPU core count                   */

#ifdef HAVE_AFFINITY

extern s32 cpu_aff; /* Selected CPU core                */

#endif /* HAVE_AFFINITY */

extern FILE* plot_file; /* Gnuplot output file              */

struct queue_entry {
  u8* fname; /* File name for the test case      */
  u32 len;   /* Input length                     */

  u8* format_file;   /* Format file name of the test case*/
  u32 format_len;    /* Format file length               */

  u8* track_file;   /* Track file name of the test case */
  u32 track_len;    /* Track file length                */

  u64* par_mutators;
  u64* my_mutators;

  u8 cal_failed,    /* Calibration failed?              */
      trim_done,    /* Trimmed?                         */
      was_inferred,
      was_fuzzed,   /* Had any fuzzing done yet?        */
      passed_det,   /* Deterministic stages passed?     */
      has_new_cov,  /* Triggers new coverage?           */
      var_behavior, /* Variable behavior?               */
      favored,      /* Currently favored?               */
      fs_redundant; /* Marked as redundant in the fs?   */

  u32 bitmap_size, /* Number of bits set in bitmap     */
      exec_cksum;  /* Checksum of the execution trace  */

  u64 exec_us,  /* Execution time (us)              */
      handicap, /* Number of queue cycles behind    */
      depth;    /* Path depth                       */

  u8* trace_mini; /* Trace bytes, if kept             */
  u32 tc_ref;     /* Trace bytes ref count            */

  struct queue_entry *next, /* Next element, if any             */
      *next_100;            /* 100 elements ahead               */
};

struct queue_entry *queue, /* Fuzzing queue (linked list)      */
    *queue_cur,                   /* Current offset within the queue  */
    *queue_top,                   /* Top of the list                  */
    *q_prev100;                   /* Previous 100 marker              */

struct queue_entry*
    top_rated[MAP_SIZE]; /* Top entries for bitmap bytes     */

struct extra_data {
  u8* data;    /* Dictionary token data            */
  u32 len;     /* Dictionary token length          */
  u32 hit_cnt; /* Use count in the corpus          */
};

extern struct extra_data* extras; /* Extra tokens to fuzz with        */
extern u32 extras_cnt;            /* Total number of tokens read      */

extern struct extra_data* a_extras; /* Automatically selected extras    */
extern u32 a_extras_cnt;            /* Total number of tokens available */

extern u8* (*post_handler)(u8* buf, u32* len);

/* Interesting values, as per config.h */

extern s8  interesting_8[INTERESTING_8_LEN];
extern s16 interesting_16[INTERESTING_8_LEN + INTERESTING_16_LEN];
extern s32
    interesting_32[INTERESTING_8_LEN + INTERESTING_16_LEN + INTERESTING_32_LEN];

/* Fuzzing stages */

enum {
  /* 00 */ STAGE_FLIP1,
  /* 01 */ STAGE_FLIP2,
  /* 02 */ STAGE_FLIP4,
  /* 03 */ STAGE_FLIP8,
  /* 04 */ STAGE_FLIP16,
  /* 05 */ STAGE_FLIP32,
  /* 06 */ STAGE_ARITH8,
  /* 07 */ STAGE_ARITH16,
  /* 08 */ STAGE_ARITH32,
  /* 09 */ STAGE_INTEREST8,
  /* 10 */ STAGE_INTEREST16,
  /* 11 */ STAGE_INTEREST32,
  /* 12 */ STAGE_EXTRAS_UO,
  /* 13 */ STAGE_EXTRAS_UI,
  /* 14 */ STAGE_EXTRAS_AO,
  /* 15 */ STAGE_HAVOC,
  /* 16 */ STAGE_SPLICE,
  /* 17 */ STAGE_STRUCT_HAVOC,
  /* 18 */ STAGE_STRUCT_DESCRIB,
  /* 19 */ STAGE_STRUCT_AWARE,
  /* 20 */ STAGE_STRUCT_SPLICE
};

/* Stage value types */

enum {
  /* 00 */ STAGE_VAL_NONE,
  /* 01 */ STAGE_VAL_LE,
  /* 02 */ STAGE_VAL_BE
};

/* Execution status fault codes */

enum {
  /* 00 */ FAULT_NONE,
  /* 01 */ FAULT_TMOUT,
  /* 02 */ FAULT_CRASH,
  /* 03 */ FAULT_ERROR,
  /* 04 */ FAULT_NOINST,
  /* 05 */ FAULT_NOBITS
};

/* init.c */

void check_if_tty(void);
void fix_up_sync(void);
void bind_to_free_cpu(void);
void check_crash_handling(void);
void check_cpu_governor(void);
void setup_post(void);
void setup_shm(void);
void setup_dirs_fds(void);
void read_testcases(void);
void pivot_inputs(void);
void find_timeout(void);
void setup_stdio_file(void);
void check_binary(u8 *fname);
u32  find_start_position(void);

/* stats.c */

void fix_up_banner(u8 *name);
void show_stats(void);
void show_init_stats(void);
void write_stats_file(double bitmap_cvg, double stability, double eps);

/* bitmap.c */

void read_bitmap(u8 *fname);
void write_bitmap(void);
void init_count_class16(void);
u8  has_new_bits(u8* virgin_map);
void update_bitmap_score(struct queue_entry *q);
u8   save_if_interesting(char** argv, void* mem, u32 len, u8 fault, Chunk* tree, Track *track);
u32  calculate_score(struct queue_entry *q);
#ifdef __x86_64__
void classify_counts(u64 *mem);
#else
void classify_counts(u32 *mem);
#endif
u32 count_bits(u8 *mem);
u32 count_bytes(u8 *mem);
u32 count_non_255_bytes(u8 *mem);

/* extras.c */

void load_auto(void);
void load_extras(u8 *dir);
void save_auto(void);
void maybe_add_auto(u8 *mem, u32 len);
void destroy_extras(void);

/* queue.c */

void mark_as_det_done(struct queue_entry *q);
void mark_as_variable(struct queue_entry *q);
void mark_as_redundant(struct queue_entry* q, u8 state);
void cull_queue(void);
void add_to_queue(u8* fname, u8* format_file, u8* track_file, u32 len, u8 passed_det);
void destroy_queue(void);
void sync_fuzzers(char** argv);

/* utils.c */

u8 *   DI(u64 val);
u8 *   DF(double val);
u8 *   DMS(u64 val);
u8 *   DTD(u64 cur_ms, u64 event_ms);
u64    get_cur_time(void);
u64    get_cur_time_us(void);
void   shuffle_ptrs(void **ptrs, u32 cnt);
void   locate_diffs(u8 *ptr1, u8 *ptr2, u32 len, s32 *first, s32 *last);
u32    choose_block_len(u32 limit);
void   write_to_testcase(void *mem, u32 len);
void   link_or_copy(u8 *old_path, u8 *new_path);
u8     delete_files(u8 *path, u8 *prefix);
double get_runnable_processes(void);
void   get_core_count(void);
u32 UR(u32 limit);

/* run.c */

void perform_dry_run();
void init_forkserver(char** argv);
u8   run_target(char** argv, u32 timeout);
u8   common_fuzz_stuff(char** argv, u8* out_buf, u32 len, Chunk* tree, Track *track);

/* pre_fuzz.c */

u8 trim_case(char** argv, struct queue_entry* q, u8* in_buf,
                    Chunk *tree);
u8 calibrate_case(char** argv, struct queue_entry* q, u8* use_mem,
                         u32 handicap, u8 from_queue);

/* fuzz_one.c */
cJSON* parse_json(const u8* format_file);
Chunk *parse_struture_file(u8 *path);
Track* parse_constraint_file(u8* path);
void delete_block(Chunk* head, HashMap map, uint32_t delete_from,
                  uint32_t delete_len);
cJSON* tree_to_json(Chunk* chunk_head);
Chunk *json_to_tree(cJSON* json_head);
cJSON *track_to_json(Track *track);
void free_tree(Chunk *tree, Boolean recurse);
u8 fuzz_one();

/* signals.c */

void setup_signal_handlers(void);

#endif