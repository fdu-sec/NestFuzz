#include "afl-fuzz.h"

u64 save_enum_number = 100;
u64* cur_mutator = NULL;
Boolean save_mutator = False;

u8 *in_dir, 
    *out_file,     
    *out_dir,      
    *sync_dir,     
    *sync_id,      
    *use_banner,   
    *in_bitmap,    
    *doc_path,     
    *target_path,  
    *orig_cmdline,
    *file_extension;

u32 exec_tmout = EXEC_TIMEOUT;
u32 hang_tmout = EXEC_TIMEOUT;

u64 mem_limit = MEM_LIMIT;

u32 cpu_to_bind = 0;

u32 stats_update_freq = 1;

u8 skip_deterministic,
    force_deterministic,     
    use_splicing,            
    dumb_mode,               
    score_changed,           
    kill_signal,             
    resuming_fuzz,           
    timeout_given,           
    cpu_to_bind_given,       
    not_on_tty,              
    term_too_small,          
    uses_asan,               
    no_forkserver,           
    crash_mode,              
    in_place_resume,         
    auto_changed,            
    no_cpu_meter_red,        
    no_arith,                
    shuffle_queue,           
    bitmap_changed = 1,      
    qemu_mode,               
    skip_requested,          
    run_over10m,             
    persistent_mode,         
    deferred_mode,           
    fast_cal;                

s32 out_fd,
    dev_urandom_fd = -1, 
    dev_null_fd = -1, 
    fsrv_ctl_fd,  
    fsrv_st_fd; 

s32 forksrv_pid, 
    child_pid = -1,     
    out_dir_fd = -1;    

u8* trace_bits; 

u8 virgin_bits[MAP_SIZE], 
    virgin_tmout[MAP_SIZE],      
    virgin_crash[MAP_SIZE];      

u8 var_bytes[MAP_SIZE]; 

s32 shm_id; 

volatile u8 stop_soon, 
    clear_screen = 1,         
    child_timed_out;          

u32 queued_paths, 
    queued_variable,     
    queued_at_start,     
    queued_discovered,   
    queued_imported,     
    queued_favored,      
    queued_with_cov,     
    pending_not_fuzzed,  
    pending_favored,     
    cur_skipped_paths,   
    cur_depth,           
    max_depth,           
    useless_at_start,    
    var_byte_count,      
    current_entry,       
    havoc_div = 1;       

u64 total_crashes, 
    unique_crashes,       
    total_tmouts,         
    unique_tmouts,        
    unique_hangs,         
    total_execs,          
    slowest_exec_ms,      
    start_time,           
    last_path_time,       
    last_crash_time,      
    last_hang_time,       
    last_crash_execs,     
    queue_cycle,          
    cycles_wo_finds,      
    trim_execs,           
    bytes_trim_in,        
    bytes_trim_out,       
    blocks_eff_total,     
    blocks_eff_select;    

u32 subseq_tmouts; 

u8 *stage_name = "init", 
    *stage_short,               
    *syncing_party;             

s32 stage_cur, stage_max; 
s32 splicing_with = -1;   

u32 master_id, master_max; 

u32 syncing_case; 

s32 stage_cur_byte, 
    stage_cur_val;         

u8 stage_val_type; 

u64 stage_finds[32], 
    stage_cycles[32];       

u32 rand_cnt; 

u64 total_cal_us, 
    total_cal_cycles;    

u64 total_bitmap_size, 
    total_bitmap_entries;     

s32 cpu_core_count;

#ifdef HAVE_AFFINITY

s32 cpu_aff = -1; 

#endif 

FILE* plot_file;

struct queue_entry *queue, 
    *queue_cur,                   /* Current offset within the queue  */
    *queue_top,                   /* Top of the list                  */
    *q_prev100;                   /* Previous 100 marker              */

struct queue_entry*
    top_rated[MAP_SIZE]; 

struct extra_data* extras; /* Extra tokens to fuzz with        */
u32 extras_cnt;            /* Total number of tokens read      */

struct extra_data* a_extras; /* Automatically selected extras    */
u32 a_extras_cnt;            /* Total number of tokens available */

u8* (*post_handler)(u8* buf, u32* len);

/* Interesting values, as per config.h */

s8 interesting_8[] = {INTERESTING_8};
s16 interesting_16[] = {INTERESTING_8, INTERESTING_16};
s32 interesting_32[] = {INTERESTING_8, INTERESTING_16, INTERESTING_32};

u64 total_mutation;
u64 interest_mutation;
u64 increase_mutation;