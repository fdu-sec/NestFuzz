/*
  Copyright 2013 Google LLC All rights reserved.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

/*
   american fuzzy lop - fuzzer code
   --------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   This is the real deal: the program takes an instrumented binary and
   attempts a variety of basic fuzzing tricks, paying close attention to
   how they affect the execution path.

*/

#define AFL_MAIN
#include "afl-fuzz.h"



/* Display usage hints. */

static void usage(u8* argv0) {
  SAYF(
      "\n%s [ options ] -- /path/to/fuzzed_app [ ... ]\n\n"

      "Required parameters:\n\n"

      "  -i dir        - input directory with test cases\n"
      "  -o dir        - output directory for fuzzer findings\n\n"

      "Execution control settings:\n\n"

      "  -f file       - location read by the fuzzed program (stdin)\n"
      "  -t msec       - timeout for each run (auto-scaled, 50-%u ms)\n"
      "  -m megs       - memory limit for child process (%u MB)\n"
      "  -Q            - use binary-only instrumentation (QEMU mode)\n\n"

      "Fuzzing behavior settings:\n\n"

      "  -d            - quick & dirty mode (skips deterministic steps)\n"
      "  -n            - fuzz without instrumentation (dumb mode)\n"
      "  -x dir        - optional fuzzer dictionary (see README)\n\n"

      "Other stuff:\n\n"

      "  -T text       - text banner to show on the screen\n"
      "  -M / -S id    - distributed mode (see parallel_fuzzing.txt)\n"
      "  -C            - crash exploration mode (the peruvian rabbit thing)\n"
      "  -V            - show version number and exit\n\n"
      "  -b cpu_id     - bind the fuzzing process to the specified CPU core\n\n"

      "For additional tips, please consult %s/README.\n\n",

      argv0, EXEC_TIMEOUT, MEM_LIMIT, doc_path);

  exit(1);
}

/* Check ASAN options. */

static void check_asan_opts(void) {
  u8* x = getenv("ASAN_OPTIONS");

  if (x) {
    if (!strstr(x, "abort_on_error=1"))
      FATAL("Custom ASAN_OPTIONS set without abort_on_error=1 - please fix!");

    if (!strstr(x, "symbolize=0"))
      FATAL("Custom ASAN_OPTIONS set without symbolize=0 - please fix!");
  }

  x = getenv("MSAN_OPTIONS");

  if (x) {
    if (!strstr(x, "exit_code=" STRINGIFY(MSAN_ERROR)))
      FATAL("Custom MSAN_OPTIONS set without exit_code=" STRINGIFY(
          MSAN_ERROR) " - please fix!");

    if (!strstr(x, "symbolize=0"))
      FATAL("Custom MSAN_OPTIONS set without symbolize=0 - please fix!");
  }
}

/* Detect @@ in args. */

EXP_ST void detect_file_args(char** argv) {
  u32 i = 0;
  u8* cwd = getcwd(NULL, 0);

  if (!cwd) PFATAL("getcwd() failed");

  while (argv[i]) {
    u8* aa_loc = strstr(argv[i], "@@");

    if (aa_loc) {
      u8 *aa_subst, *n_arg;

      /* If we don't have a file name chosen yet, use a safe default. */

      if (!out_file) {
        if (file_extension)
          out_file = alloc_printf("%s/.cur_input.%s", out_dir, file_extension);
        else
          out_file = alloc_printf("%s/.cur_input", out_dir);
      }

      /* Be sure that we're always using fully-qualified paths. */

      if (out_file[0] == '/')
        aa_subst = out_file;
      else
        aa_subst = alloc_printf("%s/%s", cwd, out_file);

      /* Construct a replacement argv value. */

      *aa_loc = 0;
      n_arg = alloc_printf("%s%s%s", argv[i], aa_subst, aa_loc + 2);
      argv[i] = n_arg;
      *aa_loc = '@';

      if (out_file[0] != '/') ck_free(aa_subst);
    }

    i++;
  }

  free(cwd); /* not tracked */
}

/* Rewrite argv for QEMU. */

static char** get_qemu_argv(u8* own_loc, char** argv, int argc) {
  char** new_argv = ck_alloc(sizeof(char*) * (argc + 4));
  u8 *tmp, *cp, *rsl, *own_copy;

  /* Workaround for a QEMU stability glitch. */

  setenv("QEMU_LOG", "nochain", 1);

  memcpy(new_argv + 3, argv + 1, sizeof(char*) * argc);

  new_argv[2] = target_path;
  new_argv[1] = "--";

  /* Now we need to actually find the QEMU binary to put in argv[0]. */

  tmp = getenv("AFL_PATH");

  if (tmp) {
    cp = alloc_printf("%s/afl-qemu-trace", tmp);

    if (access(cp, X_OK)) FATAL("Unable to find '%s'", tmp);

    target_path = new_argv[0] = cp;
    return new_argv;
  }

  own_copy = ck_strdup(own_loc);
  rsl = strrchr(own_copy, '/');

  if (rsl) {
    *rsl = 0;

    cp = alloc_printf("%s/afl-qemu-trace", own_copy);
    ck_free(own_copy);

    if (!access(cp, X_OK)) {
      target_path = new_argv[0] = cp;
      return new_argv;
    }

  } else
    ck_free(own_copy);

  if (!access(BIN_PATH "/afl-qemu-trace", X_OK)) {
    target_path = new_argv[0] = ck_strdup(BIN_PATH "/afl-qemu-trace");
    return new_argv;
  }

  SAYF("\n" cLRD "[-] " cRST
       "Oops, unable to find the 'afl-qemu-trace' binary. The binary must be "
       "built\n"
       "    separately by following the instructions in qemu_mode/README.qemu. "
       "If you\n"
       "    already have the binary installed, you may need to specify "
       "AFL_PATH in the\n"
       "    environment.\n\n"

       "    Of course, even without QEMU, afl-fuzz can still work with "
       "binaries that are\n"
       "    instrumented at compile time with afl-gcc. It is also possible to "
       "use it as a\n"
       "    traditional \"dumb\" fuzzer by specifying '-n' in the command "
       "line.\n");

  FATAL("Failed to locate 'afl-qemu-trace'.");
}

/* Make a copy of the current command line. */

static void save_cmdline(u32 argc, char** argv) {
  u32 len = 1, i;
  u8* buf;

  for (i = 0; i < argc; i++) len += strlen(argv[i]) + 1;

  buf = orig_cmdline = ck_alloc(len);

  for (i = 0; i < argc; i++) {
    u32 l = strlen(argv[i]);

    memcpy(buf, argv[i], l);
    buf += l;

    if (i != argc - 1) *(buf++) = ' ';
  }

  *buf = 0;
}

#ifndef AFL_LIB

/* Main entry point */

int main(int argc, char** argv) {
  s32 opt;
  u64 prev_queued = 0;
  u32 sync_interval_cnt = 0, seek_to;
  u8* extras_dir = 0;
  u8 mem_limit_given = 0;
  u8 exit_1 = !!getenv("AFL_BENCH_JUST_ONE");
  char** use_argv;

  struct timeval tv;
  struct timezone tz;

  SAYF(cCYA "afl-fuzz " cBRI VERSION cRST " by <lcamtuf@google.com>\n");

  doc_path = access(DOC_PATH, F_OK) ? "docs" : DOC_PATH;

  gettimeofday(&tv, &tz);
  srandom(tv.tv_sec ^ tv.tv_usec ^ getpid());

  while ((opt = getopt(argc, argv, "+i:o:f:m:b:t:T:dnCB:S:M:x:e:QV")) > 0)

    switch (opt) {
      case 'i': /* input dir */

        if (in_dir) FATAL("Multiple -i options not supported");
        in_dir = optarg;

        if (!strcmp(in_dir, "-")) in_place_resume = 1;

        break;

      case 'o': /* output dir */

        if (out_dir) FATAL("Multiple -o options not supported");
        out_dir = optarg;
        break;

      case 'M': { /* master sync ID */

        u8* c;

        if (sync_id) FATAL("Multiple -S or -M options not supported");
        sync_id = ck_strdup(optarg);

        if ((c = strchr(sync_id, ':'))) {
          *c = 0;

          if (sscanf(c + 1, "%u/%u", &master_id, &master_max) != 2 ||
              !master_id || !master_max || master_id > master_max ||
              master_max > 1000000)
            FATAL("Bogus master ID passed to -M");
        }

        force_deterministic = 1;

      }

      break;

      case 'S':

        if (sync_id) FATAL("Multiple -S or -M options not supported");
        sync_id = ck_strdup(optarg);
        break;

      case 'f': /* target file */

        if (out_file) FATAL("Multiple -f options not supported");
        out_file = optarg;
        break;

      case 'x': /* dictionary */

        if (extras_dir) FATAL("Multiple -x options not supported");
        extras_dir = optarg;
        break;

      case 't': { /* timeout */

        u8 suffix = 0;

        if (timeout_given) FATAL("Multiple -t options not supported");

        if (sscanf(optarg, "%u%c", &exec_tmout, &suffix) < 1 ||
            optarg[0] == '-')
          FATAL("Bad syntax used for -t");

        if (exec_tmout < 5) FATAL("Dangerously low value of -t");

        if (suffix == '+')
          timeout_given = 2;
        else
          timeout_given = 1;

        break;
      }

      case 'm': { /* mem limit */

        u8 suffix = 'M';

        if (mem_limit_given) FATAL("Multiple -m options not supported");
        mem_limit_given = 1;

        if (!strcmp(optarg, "none")) {
          mem_limit = 0;
          break;
        }

        if (sscanf(optarg, "%llu%c", &mem_limit, &suffix) < 1 ||
            optarg[0] == '-')
          FATAL("Bad syntax used for -m");

        switch (suffix) {
          case 'T':
            mem_limit *= 1024 * 1024;
            break;
          case 'G':
            mem_limit *= 1024;
            break;
          case 'k':
            mem_limit /= 1024;
            break;
          case 'M':
            break;

          default:
            FATAL("Unsupported suffix or bad syntax for -m");
        }

        if (mem_limit < 5) FATAL("Dangerously low value of -m");

        if (sizeof(rlim_t) == 4 && mem_limit > 2000)
          FATAL("Value of -m out of range on 32-bit systems");

      }

      break;

      case 'b': { /* bind CPU core */

        if (cpu_to_bind_given) FATAL("Multiple -b options not supported");
        cpu_to_bind_given = 1;

        if (sscanf(optarg, "%u", &cpu_to_bind) < 1 || optarg[0] == '-')
          FATAL("Bad syntax used for -b");

        break;
      }

      case 'd': /* skip deterministic */

        if (skip_deterministic) FATAL("Multiple -d options not supported");
        skip_deterministic = 1;
        use_splicing = 1;
        break;

      case 'B': /* load bitmap */

        /* This is a secret undocumented option! It is useful if you find
           an interesting test case during a normal fuzzing process, and want
           to mutate it without rediscovering any of the test cases already
           found during an earlier run.

           To use this mode, you need to point -B to the fuzz_bitmap produced
           by an earlier run for the exact same binary... and that's it.

           I only used this once or twice to get variants of a particular
           file, so I'm not making this an official setting. */

        if (in_bitmap) FATAL("Multiple -B options not supported");

        in_bitmap = optarg;
        read_bitmap(in_bitmap);
        break;

      case 'C': /* crash mode */

        if (crash_mode) FATAL("Multiple -C options not supported");
        crash_mode = FAULT_CRASH;
        break;

      case 'n': /* dumb mode */

        if (dumb_mode) FATAL("Multiple -n options not supported");
        if (getenv("AFL_DUMB_FORKSRV"))
          dumb_mode = 2;
        else
          dumb_mode = 1;

        break;

      case 'T': /* banner */

        if (use_banner) FATAL("Multiple -T options not supported");
        use_banner = optarg;
        break;

      case 'Q': /* QEMU mode */

        if (qemu_mode) FATAL("Multiple -Q options not supported");
        qemu_mode = 1;

        if (!mem_limit_given) mem_limit = MEM_LIMIT_QEMU;

        break;

      case 'V': /* Show version number */

        /* Version number has been printed already, just quit. */
        exit(0);

      case 'e':
        if (file_extension) FATAL("Multiple -e options not supported");
        file_extension = optarg;

        break;

      default:

        usage(argv[0]);
    }

  if (optind == argc || !in_dir || !out_dir) usage(argv[0]);

  setup_signal_handlers();
  check_asan_opts();

  if (sync_id) fix_up_sync();

  if (!strcmp(in_dir, out_dir))
    FATAL("Input and output directories can't be the same");

  if (dumb_mode) {
    if (crash_mode) FATAL("-C and -n are mutually exclusive");
    if (qemu_mode) FATAL("-Q and -n are mutually exclusive");
  }

  if (file_extension)
    OKF("Using the %s extension for the input file", file_extension);

  if (getenv("AFL_NO_FORKSRV")) no_forkserver = 1;
  if (getenv("AFL_NO_CPU_RED")) no_cpu_meter_red = 1;
  if (getenv("AFL_NO_ARITH")) no_arith = 1;
  if (getenv("AFL_SHUFFLE_QUEUE")) shuffle_queue = 1;
  if (getenv("AFL_FAST_CAL")) fast_cal = 1;

  if (getenv("AFL_HANG_TMOUT")) {
    hang_tmout = atoi(getenv("AFL_HANG_TMOUT"));
    if (!hang_tmout) FATAL("Invalid value of AFL_HANG_TMOUT");
  }

  if (dumb_mode == 2 && no_forkserver)
    FATAL("AFL_DUMB_FORKSRV and AFL_NO_FORKSRV are mutually exclusive");

  if (getenv("AFL_PRELOAD")) {
    setenv("LD_PRELOAD", getenv("AFL_PRELOAD"), 1);
    setenv("DYLD_INSERT_LIBRARIES", getenv("AFL_PRELOAD"), 1);
  }

  if (getenv("AFL_LD_PRELOAD"))
    FATAL("Use AFL_PRELOAD instead of AFL_LD_PRELOAD");

  save_cmdline(argc, argv);

  fix_up_banner(argv[optind]);

  check_if_tty();

  get_core_count();

#ifdef HAVE_AFFINITY
  bind_to_free_cpu();
#endif /* HAVE_AFFINITY */

  check_crash_handling();
  check_cpu_governor();

  setup_post();
  setup_shm();
  init_count_class16();

  setup_dirs_fds();
  read_testcases();
  load_auto();
  pivot_inputs();

  if (extras_dir) load_extras(extras_dir);

  if (!timeout_given) find_timeout();

  detect_file_args(argv + optind + 1);

  if (!out_file) setup_stdio_file();

  check_binary(argv[optind]);

  start_time = get_cur_time();

  if (qemu_mode)
    use_argv = get_qemu_argv(argv[0], argv + optind, argc - optind);
  else
    use_argv = argv + optind;

  perform_dry_run(use_argv);

  cull_queue();

  show_init_stats();

  seek_to = find_start_position();

  write_stats_file(0, 0, 0);
  save_auto();

  if (stop_soon) goto stop_fuzzing;

  /* Woop woop woop */

  if (!not_on_tty) {
    sleep(4);
    start_time += 4000;
    if (stop_soon) goto stop_fuzzing;
  }

  while (1) {
    u8 skipped_fuzz;

    cull_queue();

    if (!queue_cur) {
      queue_cycle++;
      current_entry = 0;
      cur_skipped_paths = 0;
      queue_cur = queue;

      while (seek_to) {
        current_entry++;
        seek_to--;
        queue_cur = queue_cur->next;
      }

      show_stats();

      if (not_on_tty) {
        ACTF("Entering queue cycle %llu.", queue_cycle);
        fflush(stdout);
      }

      /* If we had a full queue cycle with no new finds, try
         recombination strategies next. */

      if (queued_paths == prev_queued) {
        if (use_splicing)
          cycles_wo_finds++;
        else
          use_splicing = 1;

      } else
        cycles_wo_finds = 0;

      prev_queued = queued_paths;

      if (sync_id && queue_cycle == 1 && getenv("AFL_IMPORT_FIRST"))
        sync_fuzzers(use_argv);
    }

    skipped_fuzz = fuzz_one(use_argv);

    if (!stop_soon && sync_id && !skipped_fuzz) {
      if (!(sync_interval_cnt++ % SYNC_INTERVAL)) sync_fuzzers(use_argv);
    }

    if (!stop_soon && exit_1) stop_soon = 2;

    if (stop_soon) break;

    queue_cur = queue_cur->next;
    current_entry++;
  }

  if (queue_cur) 
    show_stats();

  /* If we stopped programmatically, we kill the forkserver and the current
     runner. If we stopped manually, this is done by the signal handler. */
  if (stop_soon == 2) {
    if (child_pid > 0) kill(child_pid, SIGKILL);
    if (forksrv_pid > 0) kill(forksrv_pid, SIGKILL);
  }
  /* Now that we've killed the forkserver, we wait for it to be able to get
   * rusage stats. */
  if (waitpid(forksrv_pid, NULL, 0) <= 0) {
    WARNF("error waitpid\n");
  }

  write_bitmap();
  write_stats_file(0, 0, 0);
  save_auto();

stop_fuzzing:

  SAYF(CURSOR_SHOW cLRD "\n\n+++ Testing aborted %s +++\n" cRST,
       stop_soon == 2 ? "programmatically" : "by user");

  /* Running for more than 30 minutes but still doing first cycle? */

  if (queue_cycle == 1 && get_cur_time() - start_time > 30 * 60 * 1000) {
    SAYF("\n" cYEL "[!] " cRST
         "Stopped during the first cycle, results may be incomplete.\n"
         "    (For info on resuming, see %s/README.)\n",
         doc_path);
  }

  fclose(plot_file);
  destroy_queue();
  destroy_extras();
  ck_free(target_path);
  ck_free(sync_id);

  alloc_report();

  OKF("We're done here. Have a nice day!\n");

  exit(0);
}

#endif /* !AFL_LIB */
