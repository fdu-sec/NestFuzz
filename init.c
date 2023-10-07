#include "afl-fuzz.h"

/* Get rid of shared memory (atexit handler). */

static void remove_shm(void) { shmctl(shm_id, IPC_RMID, NULL); }

/* Configure shared memory and virgin_bits. This is called at startup. */

void setup_shm(void) {
  u8* shm_str;

  if (!in_bitmap) memset(virgin_bits, 255, MAP_SIZE);

  memset(virgin_tmout, 255, MAP_SIZE);
  memset(virgin_crash, 255, MAP_SIZE);

  shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);

  if (shm_id < 0) PFATAL("shmget() failed");

  atexit(remove_shm);

  shm_str = alloc_printf("%d", shm_id);

  /* If somebody is asking us to fuzz instrumented binaries in dumb mode,
     we don't want them to detect instrumentation, since we won't be sending
     fork server commands. This should be replaced with better auto-detection
     later on, perhaps? */

  if (!dumb_mode) setenv(SHM_ENV_VAR, shm_str, 1);

  ck_free(shm_str);

  trace_bits = shmat(shm_id, NULL, 0);

  if (trace_bits == (void*)-1) PFATAL("shmat() failed");
}
/* Load postprocessor, if available. */

void setup_post(void) {
  void* dh;
  u8* fn = getenv("AFL_POST_LIBRARY");
  u32 tlen = 6;

  if (!fn) return;

  ACTF("Loading postprocessor from '%s'...", fn);

  dh = dlopen(fn, RTLD_NOW);
  if (!dh) FATAL("%s", dlerror());

  post_handler = dlsym(dh, "afl_postprocess");
  if (!post_handler) FATAL("Symbol 'afl_postprocess' not found.");

  /* Do a quick test. It's better to segfault now than later =) */

  post_handler("hello", &tlen);

  OKF("Postprocessor installed successfully.");
}

/* Read all testcases from the input directory, then queue them for testing.
   Called at startup. */

void read_testcases(void) {
  struct dirent** nl;
  s32 nl_cnt;
  u32 i;
  u8* fn;

  /* Auto-detect non-in-place resumption attempts. */

  fn = alloc_printf("%s/queue", in_dir);
  if (!access(fn, F_OK))
    in_dir = fn;
  else
    ck_free(fn);

  ACTF("Scanning '%s'...", in_dir);

  /* We use scandir() + alphasort() rather than readdir() because otherwise,
     the ordering  of test cases would vary somewhat randomly and would be
     difficult to control. */

  nl_cnt = scandir(in_dir, &nl, NULL, alphasort);

  if (nl_cnt < 0) {
    if (errno == ENOENT || errno == ENOTDIR)

      SAYF("\n" cLRD "[-] " cRST
           "The input directory does not seem to be valid - try again. The "
           "fuzzer needs\n"
           "    one or more test case to start with - ideally, a small file "
           "under 1 kB\n"
           "    or so. The cases must be stored as regular files directly in "
           "the input\n"
           "    directory.\n");

    PFATAL("Unable to open '%s'", in_dir);
  }

  if (shuffle_queue && nl_cnt > 1) {
    ACTF("Shuffling queue...");
    shuffle_ptrs((void**)nl, nl_cnt);
  }

  for (i = 0; i < nl_cnt; i++) {
    /* skip .json file */
    u8* file_type;
    file_type = strrchr(nl[i]->d_name, '.');
    if (file_type != NULL && strcmp(file_type, ".json") == 0) {
      free(nl[i]);
      continue;
    }
    /* skip .track file */
    if(file_type != NULL && strcmp(file_type, ".track") == 0) {
      free(nl[i]);
      continue;
    }
    /* skip .track file */
    if (file_type != NULL && strcmp(file_type, ".log") == 0) {
      free(nl[i]);
      continue;
    }

    struct stat st;

    u8* fn = alloc_printf("%s/%s", in_dir, nl[i]->d_name);
    u8* dfn =
        alloc_printf("%s/.state/deterministic_done/%s", in_dir, nl[i]->d_name);
    u8* format_file = alloc_printf("%s/%s.json", in_dir, nl[i]->d_name);
    u8* track_file = alloc_printf("%s/%s.track", in_dir, nl[i]->d_name);

    u8 passed_det = 0;

    free(nl[i]); /* not tracked */

    if (lstat(fn, &st) || access(fn, R_OK)) PFATAL("Unable to access '%s'", fn);

    /* This also takes care of . and .. */

    if (!S_ISREG(st.st_mode) || !st.st_size || strstr(fn, "/README.txt")) {
      ck_free(fn);
      ck_free(dfn);
      ck_free(format_file);
      continue;
    }

    if (st.st_size > MAX_FILE)
      FATAL("Test case '%s' is too big (%s, limit is %s)", fn, DMS(st.st_size),
            DMS(MAX_FILE));

    /* Check for metadata that indicates that deterministic fuzzing
       is complete for this entry. We don't want to repeat deterministic
       fuzzing when resuming aborted scans, because it would be pointless
       and probably very time-consuming. */

    if (!access(dfn, F_OK)) passed_det = 1;
    ck_free(dfn);

    // if (access(format_file, F_OK) || access(format_file, R_OK)) {
    //   ck_free(format_file);
    // }
    if (access(format_file, R_OK)) {
      ck_free(format_file);
      format_file = NULL;
    }

    if (access(track_file, R_OK)) {
      ck_free(track_file);
      track_file = NULL;
    }
    add_to_queue(fn, format_file, track_file, st.st_size, passed_det);
  }

  free(nl); /* not tracked */

  if (!queued_paths) {
    SAYF("\n" cLRD "[-] " cRST
         "Looks like there are no valid test cases in the input directory! The "
         "fuzzer\n"
         "    needs one or more test case to start with - ideally, a small "
         "file under\n"
         "    1 kB or so. The cases must be stored as regular files directly "
         "in the\n"
         "    input directory.\n");

    FATAL("No usable test cases in '%s'", in_dir);
  }

  last_path_time = 0;
  queued_at_start = queued_paths;
}

/* Do a PATH search and find target binary to see that it exists and
   isn't a shell script - a common and painful mistake. We also check for
   a valid ELF header and for evidence of AFL instrumentation. */

void check_binary(u8* fname) {
  u8* env_path = 0;
  struct stat st;

  s32 fd;
  u8* f_data;
  u32 f_len = 0;

  ACTF("Validating target binary...");

  if (strchr(fname, '/') || !(env_path = getenv("PATH"))) {
    target_path = ck_strdup(fname);
    if (stat(target_path, &st) || !S_ISREG(st.st_mode) ||
        !(st.st_mode & 0111) || (f_len = st.st_size) < 4)
      FATAL("Program '%s' not found or not executable", fname);

  } else {
    while (env_path) {
      u8 *cur_elem, *delim = strchr(env_path, ':');

      if (delim) {
        cur_elem = ck_alloc(delim - env_path + 1);
        memcpy(cur_elem, env_path, delim - env_path);
        delim++;

      } else
        cur_elem = ck_strdup(env_path);

      env_path = delim;

      if (cur_elem[0])
        target_path = alloc_printf("%s/%s", cur_elem, fname);
      else
        target_path = ck_strdup(fname);

      ck_free(cur_elem);

      if (!stat(target_path, &st) && S_ISREG(st.st_mode) &&
          (st.st_mode & 0111) && (f_len = st.st_size) >= 4)
        break;

      ck_free(target_path);
      target_path = 0;
    }

    if (!target_path) FATAL("Program '%s' not found or not executable", fname);
  }

  if (getenv("AFL_SKIP_BIN_CHECK")) return;

  /* Check for blatant user errors. */

  if ((!strncmp(target_path, "/tmp/", 5) && !strchr(target_path + 5, '/')) ||
      (!strncmp(target_path, "/var/tmp/", 9) && !strchr(target_path + 9, '/')))
    FATAL("Please don't keep binaries in /tmp or /var/tmp");

  fd = open(target_path, O_RDONLY);

  if (fd < 0) PFATAL("Unable to open '%s'", target_path);

  f_data = mmap(0, f_len, PROT_READ, MAP_PRIVATE, fd, 0);

  if (f_data == MAP_FAILED) PFATAL("Unable to mmap file '%s'", target_path);

  close(fd);

  if (f_data[0] == '#' && f_data[1] == '!') {
    SAYF("\n" cLRD "[-] " cRST
         "Oops, the target binary looks like a shell script. Some build "
         "systems will\n"
         "    sometimes generate shell stubs for dynamically linked programs; "
         "try static\n"
         "    library mode (./configure --disable-shared) if that's the "
         "case.\n\n"

         "    Another possible cause is that you are actually trying to use a "
         "shell\n"
         "    wrapper around the fuzzed component. Invoking shell can slow "
         "down the\n"
         "    fuzzing process by a factor of 20x or more; it's best to write "
         "the wrapper\n"
         "    in a compiled language instead.\n");

    FATAL("Program '%s' is a shell script", target_path);
  }

#ifndef __APPLE__

  if (f_data[0] != 0x7f || memcmp(f_data + 1, "ELF", 3))
    FATAL("Program '%s' is not an ELF binary", target_path);

#else

  if (f_data[0] != 0xCF || f_data[1] != 0xFA || f_data[2] != 0xED)
    FATAL("Program '%s' is not a 64-bit Mach-O binary", target_path);

#endif /* ^!__APPLE__ */

  if (!qemu_mode && !dumb_mode &&
      !memmem(f_data, f_len, SHM_ENV_VAR, strlen(SHM_ENV_VAR) + 1)) {
    SAYF(
        "\n" cLRD "[-] " cRST
        "Looks like the target binary is not instrumented! The fuzzer depends "
        "on\n"
        "    compile-time instrumentation to isolate interesting test cases "
        "while\n"
        "    mutating the input data. For more information, and for tips on "
        "how to\n"
        "    instrument binaries, please see %s/README.\n\n"

        "    When source code is not available, you may be able to leverage "
        "QEMU\n"
        "    mode support. Consult the README for tips on how to enable this.\n"

        "    (It is also possible to use afl-fuzz as a traditional, \"dumb\" "
        "fuzzer.\n"
        "    For that, you can use the -n option - but expect much worse "
        "results.)\n",
        doc_path);

    FATAL("No instrumentation detected");
  }

  if (qemu_mode &&
      memmem(f_data, f_len, SHM_ENV_VAR, strlen(SHM_ENV_VAR) + 1)) {
    SAYF("\n" cLRD "[-] " cRST
         "This program appears to be instrumented with afl-gcc, but is being "
         "run in\n"
         "    QEMU mode (-Q). This is probably not what you want - this setup "
         "will be\n"
         "    slow and offer no practical benefits.\n");

    FATAL("Instrumentation found in -Q mode");
  }

  if (memmem(f_data, f_len, "libasan.so", 10) ||
      memmem(f_data, f_len, "__msan_init", 11))
    uses_asan = 1;

  /* Detect persistent & deferred init signatures in the binary. */

  if (memmem(f_data, f_len, PERSIST_SIG, strlen(PERSIST_SIG) + 1)) {
    OKF(cPIN "Persistent mode binary detected.");
    setenv(PERSIST_ENV_VAR, "1", 1);
    persistent_mode = 1;

  } else if (getenv("AFL_PERSISTENT")) {
    WARNF("AFL_PERSISTENT is no longer supported and may misbehave!");
  }

  if (memmem(f_data, f_len, DEFER_SIG, strlen(DEFER_SIG) + 1)) {
    OKF(cPIN "Deferred forkserver binary detected.");
    setenv(DEFER_ENV_VAR, "1", 1);
    deferred_mode = 1;

  } else if (getenv("AFL_DEFER_FORKSRV")) {
    WARNF("AFL_DEFER_FORKSRV is no longer supported and may misbehave!");
  }

  if (munmap(f_data, f_len)) PFATAL("unmap() failed");
}

/* Check if we're on TTY. */

void check_if_tty(void) {
  struct winsize ws;

  if (getenv("AFL_NO_UI")) {
    OKF("Disabling the UI because AFL_NO_UI is set.");
    not_on_tty = 1;
    return;
  }

  if (ioctl(1, TIOCGWINSZ, &ws)) {
    if (errno == ENOTTY) {
      OKF("Looks like we're not running on a tty, so I'll be a bit less "
          "verbose.");
      not_on_tty = 1;
    }

    return;
  }
}

#ifdef HAVE_AFFINITY

/* Build a list of processes bound to specific cores. Returns -1 if nothing
   can be found. Assumes an upper bound of 4k CPUs. */

void bind_to_free_cpu(void) {
  DIR* d;
  struct dirent* de;
  cpu_set_t c;

  u8 cpu_used[4096] = {0};
  u32 i;

  if (cpu_core_count < 2) return;

  if (getenv("AFL_NO_AFFINITY")) {
    WARNF("Not binding to a CPU core (AFL_NO_AFFINITY set).");
    return;
  }

  d = opendir("/proc");

  if (!d) {
    WARNF("Unable to access /proc - can't scan for free CPU cores.");
    return;
  }

  ACTF("Checking CPU core loadout...");

  /* Introduce some jitter, in case multiple AFL tasks are doing the same
     thing at the same time... */

  usleep(R(1000) * 250);

  /* Scan all /proc/<pid>/status entries, checking for Cpus_allowed_list.
     Flag all processes bound to a specific CPU using cpu_used[]. This will
     fail for some exotic binding setups, but is likely good enough in almost
     all real-world use cases. */

  while ((de = readdir(d))) {
    u8* fn;
    FILE* f;
    u8 tmp[MAX_LINE];
    u8 has_vmsize = 0;

    if (!isdigit(de->d_name[0])) continue;

    fn = alloc_printf("/proc/%s/status", de->d_name);

    if (!(f = fopen(fn, "r"))) {
      ck_free(fn);
      continue;
    }

    while (fgets(tmp, MAX_LINE, f)) {
      u32 hval;

      /* Processes without VmSize are probably kernel tasks. */

      if (!strncmp(tmp, "VmSize:\t", 8)) has_vmsize = 1;

      if (!strncmp(tmp, "Cpus_allowed_list:\t", 19) && !strchr(tmp, '-') &&
          !strchr(tmp, ',') && sscanf(tmp + 19, "%u", &hval) == 1 &&
          hval < sizeof(cpu_used) && has_vmsize) {
        cpu_used[hval] = 1;
        break;
      }
    }

    ck_free(fn);
    fclose(f);
  }

  closedir(d);
  if (cpu_to_bind_given) {
    if (cpu_to_bind >= cpu_core_count)
      FATAL("The CPU core id to bind should be between 0 and %u",
            cpu_core_count - 1);

    if (cpu_used[cpu_to_bind])
      FATAL("The CPU core #%u to bind is not free!", cpu_to_bind);

    i = cpu_to_bind;

  } else {
    for (i = 0; i < cpu_core_count; i++)
      if (!cpu_used[i]) break;
  }

  if (i == cpu_core_count) {
    SAYF("\n" cLRD "[-] " cRST
         "Uh-oh, looks like all %u CPU cores on your system are allocated to\n"
         "    other instances of afl-fuzz (or similar CPU-locked tasks). "
         "Starting\n"
         "    another fuzzer on this machine is probably a bad plan, but if "
         "you are\n"
         "    absolutely sure, you can set AFL_NO_AFFINITY and try again.\n",
         cpu_core_count);

    FATAL("No more free CPU cores");
  }

  OKF("Found a free CPU core, binding to #%u.", i);

  cpu_aff = i;

  CPU_ZERO(&c);
  CPU_SET(i, &c);

  if (sched_setaffinity(0, sizeof(c), &c)) PFATAL("sched_setaffinity failed");
}

#endif /* HAVE_AFFINITY */

/* Delete the temporary directory used for in-place session resume. */

static void nuke_resume_dir(void) {
  u8* fn;

  fn = alloc_printf("%s/_resume/.state/deterministic_done", out_dir);
  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/_resume/.state/auto_extras", out_dir);
  if (delete_files(fn, "auto_")) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/_resume/.state/redundant_edges", out_dir);
  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/_resume/.state/variable_behavior", out_dir);
  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/_resume/.state", out_dir);
  if (rmdir(fn) && errno != ENOENT) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/_resume", out_dir);
  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  return;

dir_cleanup_failed:

  FATAL("_resume directory cleanup failed");
}

/* Delete fuzzer output directory if we recognize it as ours, if the fuzzer
   is not currently running, and if the last run time isn't too great. */

static void maybe_delete_out_dir(void) {
  FILE* f;
  u8* fn = alloc_printf("%s/fuzzer_stats", out_dir);

  /* See if the output directory is locked. If yes, bail out. If not,
     create a lock that will persist for the lifetime of the process
     (this requires leaving the descriptor open).*/

  out_dir_fd = open(out_dir, O_RDONLY);
  if (out_dir_fd < 0) PFATAL("Unable to open '%s'", out_dir);

#ifndef __sun

  if (flock(out_dir_fd, LOCK_EX | LOCK_NB) && errno == EWOULDBLOCK) {
    SAYF("\n" cLRD "[-] " cRST
         "Looks like the job output directory is being actively used by "
         "another\n"
         "    instance of afl-fuzz. You will need to choose a different %s\n"
         "    or stop the other process first.\n",
         sync_id ? "fuzzer ID" : "output location");

    FATAL("Directory '%s' is in use", out_dir);
  }

#endif /* !__sun */

  f = fopen(fn, "r");

  if (f) {
    u64 start_time, last_update;

    if (fscanf(f,
               "start_time     : %llu\n"
               "last_update    : %llu\n",
               &start_time, &last_update) != 2)
      FATAL("Malformed data in '%s'", fn);

    fclose(f);

    /* Let's see how much work is at stake. */

    if (!in_place_resume && last_update - start_time > OUTPUT_GRACE * 60) {
      SAYF("\n" cLRD "[-] " cRST
           "The job output directory already exists and contains the results "
           "of more\n"
           "    than %u minutes worth of fuzzing. To avoid data loss, afl-fuzz "
           "will *NOT*\n"
           "    automatically delete this data for you.\n\n"

           "    If you wish to start a new session, remove or rename the "
           "directory manually,\n"
           "    or specify a different output location for this job. To resume "
           "the old\n"
           "    session, put '-' as the input directory in the command line "
           "('-i -') and\n"
           "    try again.\n",
           OUTPUT_GRACE);

      FATAL("At-risk data found in '%s'", out_dir);
    }
  }

  ck_free(fn);

  /* The idea for in-place resume is pretty simple: we temporarily move the old
     queue/ to a new location that gets deleted once import to the new queue/
     is finished. If _resume/ already exists, the current queue/ may be
     incomplete due to an earlier abort, so we want to use the old _resume/
     dir instead, and we let rename() fail silently. */

  if (in_place_resume) {
    u8* orig_q = alloc_printf("%s/queue", out_dir);

    in_dir = alloc_printf("%s/_resume", out_dir);

    rename(orig_q, in_dir); /* Ignore errors */

    OKF("Output directory exists, will attempt session resume.");

    ck_free(orig_q);

  } else {
    OKF("Output directory exists but deemed OK to reuse.");
  }

  ACTF("Deleting old session data...");

  /* Okay, let's get the ball rolling! First, we need to get rid of the entries
     in <out_dir>/.synced/.../id:*, if any are present. */

  if (!in_place_resume) {
    fn = alloc_printf("%s/.synced", out_dir);
    if (delete_files(fn, NULL)) goto dir_cleanup_failed;
    ck_free(fn);
  }

  /* Next, we need to clean up <out_dir>/queue/.state/ subdirectories: */

  fn = alloc_printf("%s/queue/.state/deterministic_done", out_dir);
  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/queue/.state/auto_extras", out_dir);
  if (delete_files(fn, "auto_")) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/queue/.state/redundant_edges", out_dir);
  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/queue/.state/variable_behavior", out_dir);
  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  /* Then, get rid of the .state subdirectory itself (should be empty by now)
     and everything matching <out_dir>/queue/id:*. */

  fn = alloc_printf("%s/queue/.state", out_dir);
  if (rmdir(fn) && errno != ENOENT) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/queue", out_dir);
  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  /* All right, let's do <out_dir>/crashes/id:* and <out_dir>/hangs/id:*. */

  if (!in_place_resume) {
    fn = alloc_printf("%s/crashes/README.txt", out_dir);
    unlink(fn); /* Ignore errors */
    ck_free(fn);
  }

  fn = alloc_printf("%s/crashes", out_dir);

  /* Make backup of the crashes directory if it's not empty and if we're
     doing in-place resume. */

  if (in_place_resume && rmdir(fn)) {
    time_t cur_t = time(0);
    struct tm* t = localtime(&cur_t);

#ifndef SIMPLE_FILES

    u8* nfn = alloc_printf("%s.%04u-%02u-%02u-%02u:%02u:%02u", fn,
                           t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                           t->tm_hour, t->tm_min, t->tm_sec);

#else

    u8* nfn = alloc_printf("%s_%04u%02u%02u%02u%02u%02u", fn, t->tm_year + 1900,
                           t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min,
                           t->tm_sec);

#endif /* ^!SIMPLE_FILES */

    rename(fn, nfn); /* Ignore errors. */
    ck_free(nfn);
  }

  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/hangs", out_dir);

  /* Backup hangs, too. */

  if (in_place_resume && rmdir(fn)) {
    time_t cur_t = time(0);
    struct tm* t = localtime(&cur_t);

#ifndef SIMPLE_FILES

    u8* nfn = alloc_printf("%s.%04u-%02u-%02u-%02u:%02u:%02u", fn,
                           t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                           t->tm_hour, t->tm_min, t->tm_sec);

#else

    u8* nfn = alloc_printf("%s_%04u%02u%02u%02u%02u%02u", fn, t->tm_year + 1900,
                           t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min,
                           t->tm_sec);

#endif /* ^!SIMPLE_FILES */

    rename(fn, nfn); /* Ignore errors. */
    ck_free(nfn);
  }

  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  /* And now, for some finishing touches. */

  if (file_extension) {
    fn = alloc_printf("%s/.cur_input.%s", out_dir, file_extension);

  } else {
    fn = alloc_printf("%s/.cur_input", out_dir);
  }
  if (unlink(fn) && errno != ENOENT) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/fuzz_bitmap", out_dir);
  if (unlink(fn) && errno != ENOENT) goto dir_cleanup_failed;
  ck_free(fn);

  if (!in_place_resume) {
    fn = alloc_printf("%s/fuzzer_stats", out_dir);
    if (unlink(fn) && errno != ENOENT) goto dir_cleanup_failed;
    ck_free(fn);
  }

  fn = alloc_printf("%s/plot_data", out_dir);
  if (unlink(fn) && errno != ENOENT) goto dir_cleanup_failed;
  ck_free(fn);

  OKF("Output dir cleanup successful.");

  /* Wow... is that all? If yes, celebrate! */

  return;

dir_cleanup_failed:

  SAYF("\n" cLRD "[-] " cRST
       "Whoops, the fuzzer tried to reuse your output directory, but bumped "
       "into\n"
       "    some files that shouldn't be there or that couldn't be removed - "
       "so it\n"
       "    decided to abort! This happened while processing this path:\n\n"

       "    %s\n\n"
       "    Please examine and manually delete the files, or specify a "
       "different\n"
       "    output location for the tool.\n",
       fn);

  FATAL("Output directory cleanup failed");
}

/* Prepare output directories and fds. */

void setup_dirs_fds(void) {
  u8* tmp;
  s32 fd;

  ACTF("Setting up output directories...");

  if (sync_id && mkdir(sync_dir, 0700) && errno != EEXIST)
    PFATAL("Unable to create '%s'", sync_dir);

  if (mkdir(out_dir, 0700)) {
    if (errno != EEXIST) PFATAL("Unable to create '%s'", out_dir);

    maybe_delete_out_dir();

  } else {
    if (in_place_resume)
      FATAL("Resume attempted but old output directory not found");

    out_dir_fd = open(out_dir, O_RDONLY);

#ifndef __sun

    if (out_dir_fd < 0 || flock(out_dir_fd, LOCK_EX | LOCK_NB))
      PFATAL("Unable to flock() output directory.");

#endif /* !__sun */
  }

  /* Queue directory for any starting & discovered paths. */

  tmp = alloc_printf("%s/queue", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* Top-level directory for queue metadata used for session
     resume and related tasks. */

  tmp = alloc_printf("%s/queue/.state/", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* Directory for flagging queue entries that went through
     deterministic fuzzing in the past. */

  tmp = alloc_printf("%s/queue/.state/deterministic_done/", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* Directory with the auto-selected dictionary entries. */

  tmp = alloc_printf("%s/queue/.state/auto_extras/", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* The set of paths currently deemed redundant. */

  tmp = alloc_printf("%s/queue/.state/redundant_edges/", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* The set of paths showing variable behavior. */

  tmp = alloc_printf("%s/queue/.state/variable_behavior/", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* Sync directory for keeping track of cooperating fuzzers. */

  if (sync_id) {
    tmp = alloc_printf("%s/.synced/", out_dir);

    if (mkdir(tmp, 0700) && (!in_place_resume || errno != EEXIST))
      PFATAL("Unable to create '%s'", tmp);

    ck_free(tmp);
  }

  /* All recorded crashes. */

  tmp = alloc_printf("%s/crashes", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* All recorded hangs. */

  tmp = alloc_printf("%s/hangs", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* Generally useful file descriptors. */

  dev_null_fd = open("/dev/null", O_RDWR);
  if (dev_null_fd < 0) PFATAL("Unable to open /dev/null");

  dev_urandom_fd = open("/dev/urandom", O_RDONLY);
  if (dev_urandom_fd < 0) PFATAL("Unable to open /dev/urandom");

  /* Gnuplot output file. */

  tmp = alloc_printf("%s/plot_data", out_dir);
  fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  plot_file = fdopen(fd, "w");
  if (!plot_file) PFATAL("fdopen() failed");

  fprintf(plot_file,
          "# unix_time, cycles_done, cur_path, paths_total, "
          "pending_total, pending_favs, map_size, unique_crashes, "
          "unique_hangs, max_depth, execs_per_sec, total_mutation, "
          "interest_mutation, increase_mutation\n");
  /* ignore errors */
}

/* Setup the output file for fuzzed data, if not using -f. */

void setup_stdio_file(void) {
  u8* fn;
  if (file_extension) {
    fn = alloc_printf("%s/.cur_input.%s", out_dir, file_extension);

  } else {
    fn = alloc_printf("%s/.cur_input", out_dir);
  }

  unlink(fn); /* Ignore errors */

  out_fd = open(fn, O_RDWR | O_CREAT | O_EXCL, 0600);

  if (out_fd < 0) PFATAL("Unable to create '%s'", fn);

  ck_free(fn);
}

/* Make sure that core dumps don't go to a program. */

void check_crash_handling(void) {
#ifdef __APPLE__

  /* Yuck! There appears to be no simple C API to query for the state of
     loaded daemons on MacOS X, and I'm a bit hesitant to do something
     more sophisticated, such as disabling crash reporting via Mach ports,
     until I get a box to test the code. So, for now, we check for crash
     reporting the awful way. */

  if (system("launchctl list 2>/dev/null | grep -q '\\.ReportCrash$'")) return;

  SAYF(
      "\n" cLRD "[-] " cRST
      "Whoops, your system is configured to forward crash notifications to an\n"
      "    external crash reporting utility. This will cause issues due to "
      "the\n"
      "    extended delay between the fuzzed binary malfunctioning and this "
      "fact\n"
      "    being relayed to the fuzzer via the standard waitpid() API.\n\n"
      "    To avoid having crashes misinterpreted as timeouts, please run the\n"
      "    following commands:\n\n"

      "    SL=/System/Library; PL=com.apple.ReportCrash\n"
      "    launchctl unload -w ${SL}/LaunchAgents/${PL}.plist\n"
      "    sudo launchctl unload -w ${SL}/LaunchDaemons/${PL}.Root.plist\n");

  if (!getenv("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"))
    FATAL("Crash reporter detected");

#else

  /* This is Linux specific, but I don't think there's anything equivalent on
   *BSD, so we can just let it slide for now. */

  s32 fd = open("/proc/sys/kernel/core_pattern", O_RDONLY);
  u8 fchar;

  if (fd < 0) return;

  ACTF("Checking core_pattern...");

  if (read(fd, &fchar, 1) == 1 && fchar == '|') {
    SAYF(
        "\n" cLRD "[-] " cRST
        "Hmm, your system is configured to send core dump notifications to an\n"
        "    external utility. This will cause issues: there will be an "
        "extended delay\n"
        "    between stumbling upon a crash and having this information "
        "relayed to the\n"
        "    fuzzer via the standard waitpid() API.\n\n"

        "    To avoid having crashes misinterpreted as timeouts, please log in "
        "as root\n"
        "    and temporarily modify /proc/sys/kernel/core_pattern, like so:\n\n"

        "    echo core >/proc/sys/kernel/core_pattern\n");

    if (!getenv("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"))
      FATAL("Pipe at the beginning of 'core_pattern'");
  }

  close(fd);

#endif /* ^__APPLE__ */
}

/* Check CPU governor. */

void check_cpu_governor(void) {
  FILE* f;
  u8 tmp[128];
  u64 min = 0, max = 0;

  if (getenv("AFL_SKIP_CPUFREQ")) return;

  f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor", "r");
  if (!f) return;

  ACTF("Checking CPU scaling governor...");

  if (!fgets(tmp, 128, f)) PFATAL("fgets() failed");

  fclose(f);

  if (!strncmp(tmp, "perf", 4)) return;

  f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_min_freq", "r");

  if (f) {
    if (fscanf(f, "%llu", &min) != 1) min = 0;
    fclose(f);
  }

  f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq", "r");

  if (f) {
    if (fscanf(f, "%llu", &max) != 1) max = 0;
    fclose(f);
  }

  if (min == max) return;

  SAYF("\n" cLRD "[-] " cRST
       "Whoops, your system uses on-demand CPU frequency scaling, adjusted\n"
       "    between %llu and %llu MHz. Unfortunately, the scaling algorithm in "
       "the\n"
       "    kernel is imperfect and can miss the short-lived processes spawned "
       "by\n"
       "    afl-fuzz. To keep things moving, run these commands as root:\n\n"

       "    cd /sys/devices/system/cpu\n"
       "    echo performance | tee cpu*/cpufreq/scaling_governor\n\n"

       "    You can later go back to the original state by replacing "
       "'performance' with\n"
       "    'ondemand'. If you don't want to change the settings, set "
       "AFL_SKIP_CPUFREQ\n"
       "    to make afl-fuzz skip this check - but expect some performance "
       "drop.\n",
       min / 1024, max / 1024);

  FATAL("Suboptimal CPU scaling governor");
}

/* Validate and fix up out_dir and sync_dir when using -S. */

void fix_up_sync(void) {
  u8* x = sync_id;

  if (dumb_mode) FATAL("-S / -M and -n are mutually exclusive");

  if (skip_deterministic) {
    if (force_deterministic)
      FATAL("use -S instead of -M -d");
    else
      FATAL("-S already implies -d");
  }

  while (*x) {
    if (!isalnum(*x) && *x != '_' && *x != '-')
      FATAL("Non-alphanumeric fuzzer ID specified via -S or -M");

    x++;
  }

  if (strlen(sync_id) > 32) FATAL("Fuzzer ID too long");

  x = alloc_printf("%s/%s", out_dir, sync_id);

  sync_dir = out_dir;
  out_dir = x;

  if (!force_deterministic) {
    skip_deterministic = 1;
    use_splicing = 1;
  }
}

/* Create hard links for input test cases in the output directory, choosing
   good names and pivoting accordingly. */

void pivot_inputs(void) {
  struct queue_entry* q = queue;
  u32 id = 0;

  ACTF("Creating hard links for all input files...");

  while (q) {
    u8 *nfn, *rsl = strrchr(q->fname, '/');
    u32 orig_id;

    if (!rsl)
      rsl = q->fname;
    else
      rsl++;

      /* If the original file name conforms to the syntax and the recorded
         ID matches the one we'd assign, just use the original file name.
         This is valuable for resuming fuzzing runs. */


    if (!strncmp(rsl, CASE_PREFIX, 3) &&
        sscanf(rsl + 3, "%06u", &orig_id) == 1 && orig_id == id) {
      u8* src_str;
      u32 src_id;

      resuming_fuzz = 1;
      nfn = alloc_printf("%s/queue/%s", out_dir, rsl);

      /* Since we're at it, let's also try to find parent and figure out the
         appropriate depth for this entry. */

      src_str = strchr(rsl + 3, ':');

      if (src_str && sscanf(src_str + 1, "%06u", &src_id) == 1) {
        struct queue_entry* s = queue;
        while (src_id-- && s) s = s->next;
        if (s) q->depth = s->depth + 1;

        if (max_depth < q->depth) max_depth = q->depth;
      }

    } else {
      /* No dice - invent a new name, capturing the original one as a
         substring. */

#ifndef SIMPLE_FILES

      u8* use_name = strstr(rsl, ",orig:");

      if (use_name)
        use_name += 6;
      else
        use_name = rsl;
      nfn = alloc_printf("%s/queue/id:%06u,orig:%s", out_dir, id, use_name);

#else

      nfn = alloc_printf("%s/queue/id_%06u", out_dir, id);

#endif /* ^!SIMPLE_FILES */
    }

    /* Pivot to the new queue entry. */

    link_or_copy(q->fname, nfn);
    ck_free(q->fname);
    q->fname = nfn;

    if(q->format_file) {
      nfn = alloc_printf("%s.json", nfn);
      link_or_copy(q->format_file, nfn);
      ck_free(q->format_file);
      q->format_file = nfn;
    }

    if(q->track_file) {
      nfn = alloc_printf("%s.track", q->fname);
      link_or_copy(q->track_file, nfn);
      ck_free(q->track_file);
      q->track_file = nfn;
    }

    /* Make sure that the passed_det value carries over, too. */

    if (q->passed_det) mark_as_det_done(q);

    q = q->next;
    id++;
  }

  if (in_place_resume) nuke_resume_dir();
}

/* When resuming, try to find the queue position to start from. This makes sense
   only when resuming, and when we can find the original fuzzer_stats. */

u32 find_start_position(void) {
  static u8 tmp[4096]; /* Ought to be enough for anybody. */

  u8 *fn, *off;
  s32 fd, i;
  u32 ret;

  if (!resuming_fuzz) return 0;

  if (in_place_resume)
    fn = alloc_printf("%s/fuzzer_stats", out_dir);
  else
    fn = alloc_printf("%s/../fuzzer_stats", in_dir);

  fd = open(fn, O_RDONLY);
  ck_free(fn);

  if (fd < 0) return 0;

  i = read(fd, tmp, sizeof(tmp) - 1);
  (void)i; /* Ignore errors */
  close(fd);

  off = strstr(tmp, "cur_path          : ");
  if (!off) return 0;

  ret = atoi(off + 20);
  if (ret >= queued_paths) ret = 0;
  return ret;
}


/* The same, but for timeouts. The idea is that when resuming sessions without
   -t given, we don't want to keep auto-scaling the timeout over and over
   again to prevent it from growing due to random flukes. */

void find_timeout(void) {
  static u8 tmp[4096]; /* Ought to be enough for anybody. */

  u8 *fn, *off;
  s32 fd, i;
  u32 ret;

  if (!resuming_fuzz) return;

  if (in_place_resume)
    fn = alloc_printf("%s/fuzzer_stats", out_dir);
  else
    fn = alloc_printf("%s/../fuzzer_stats", in_dir);

  fd = open(fn, O_RDONLY);
  ck_free(fn);

  if (fd < 0) return;

  i = read(fd, tmp, sizeof(tmp) - 1);
  (void)i; /* Ignore errors */
  close(fd);

  off = strstr(tmp, "exec_timeout      : ");
  if (!off) return;

  ret = atoi(off + 20);
  if (ret <= 4) return;

  exec_tmout = ret;
  timeout_given = 3;
}

