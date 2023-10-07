#include "afl-fuzz.h"

/* Examine map coverage. Called once, for first test case. */

static void check_map_coverage(void) {
  u32 i;

  if (count_bytes(trace_bits) < 100) return;

  for (i = (1 << (MAP_SIZE_POW2 - 1)); i < MAP_SIZE; i++)
    if (trace_bits[i]) return;

  WARNF("Recompile binary with newer version of afl to improve coverage!");
}

/* Perform dry run of all test cases to confirm that the app is working as
   expected. This is done only for the initial inputs, and only once. */

void perform_dry_run(char** argv) {
  struct queue_entry* q = queue;
  u32 cal_failures = 0;
  u8* skip_crashes = getenv("AFL_SKIP_CRASHES");

  while (q) {
    u8* use_mem;
    u8 res;
    s32 fd;

    u8* fn = strrchr(q->fname, '/') + 1;

    ACTF("Attempting dry run with '%s'...", fn);

    fd = open(q->fname, O_RDONLY);
    if (fd < 0) PFATAL("Unable to open '%s'", q->fname);

    use_mem = ck_alloc_nozero(q->len);

    if (read(fd, use_mem, q->len) != q->len)
      FATAL("Short read from '%s'", q->fname);

    close(fd);

    res = calibrate_case(argv, q, use_mem, 0, 1);
    ck_free(use_mem);

    if (stop_soon) return;

    if (res == crash_mode || res == FAULT_NOBITS)
      SAYF(cGRA "    len = %u, map size = %u, exec speed = %llu us\n" cRST,
           q->len, q->bitmap_size, q->exec_us);

    switch (res) {
      case FAULT_NONE:

        if (q == queue) check_map_coverage();

        if (crash_mode) FATAL("Test case '%s' does *NOT* crash", fn);

        break;

      case FAULT_TMOUT:

        if (timeout_given) {
          /* The -t nn+ syntax in the command line sets timeout_given to '2' and
             instructs afl-fuzz to tolerate but skip queue entries that time
             out. */

          if (timeout_given > 1) {
            WARNF("Test case results in a timeout (skipping)");
            q->cal_failed = CAL_CHANCES;
            cal_failures++;
            break;
          }

          SAYF("\n" cLRD "[-] " cRST
               "The program took more than %u ms to process one of the initial "
               "test cases.\n"
               "    Usually, the right thing to do is to relax the -t option - "
               "or to delete it\n"
               "    altogether and allow the fuzzer to auto-calibrate. That "
               "said, if you know\n"
               "    what you are doing and want to simply skip the unruly test "
               "cases, append\n"
               "    '+' at the end of the value passed to -t ('-t %u+').\n",
               exec_tmout, exec_tmout);

          FATAL("Test case '%s' results in a timeout", fn);

        } else {
          SAYF("\n" cLRD "[-] " cRST
               "The program took more than %u ms to process one of the initial "
               "test cases.\n"
               "    This is bad news; raising the limit with the -t option is "
               "possible, but\n"
               "    will probably make the fuzzing process extremely slow.\n\n"

               "    If this test case is just a fluke, the other option is to "
               "just avoid it\n"
               "    altogether, and find one that is less of a CPU hog.\n",
               exec_tmout);

          FATAL("Test case '%s' results in a timeout", fn);
        }

      case FAULT_CRASH:

        if (crash_mode) break;

        if (skip_crashes) {
          WARNF("Test case results in a crash (skipping)");
          q->cal_failed = CAL_CHANCES;
          cal_failures++;
          break;
        }

        if (mem_limit) {
          SAYF("\n" cLRD "[-] " cRST
               "Oops, the program crashed with one of the test cases provided. "
               "There are\n"
               "    several possible explanations:\n\n"

               "    - The test case causes known crashes under normal working "
               "conditions. If\n"
               "      so, please remove it. The fuzzer should be seeded with "
               "interesting\n"
               "      inputs - but not ones that cause an outright crash.\n\n"

               "    - The current memory limit (%s) is too low for this "
               "program, causing\n"
               "      it to die due to OOM when parsing valid files. To fix "
               "this, try\n"
               "      bumping it up with the -m setting in the command line. "
               "If in doubt,\n"
               "      try something along the lines of:\n\n"

#ifdef RLIMIT_AS
               "      ( ulimit -Sv $[%llu << 10]; /path/to/binary [...] "
               "<testcase )\n\n"
#else
               "      ( ulimit -Sd $[%llu << 10]; /path/to/binary [...] "
               "<testcase )\n\n"
#endif /* ^RLIMIT_AS */

               "      Tip: you can use http://jwilk.net/software/recidivm to "
               "quickly\n"
               "      estimate the required amount of virtual memory for the "
               "binary. Also,\n"
               "      if you are using ASAN, see %s/notes_for_asan.txt.\n\n"

#ifdef __APPLE__

               "    - On MacOS X, the semantics of fork() syscalls are "
               "non-standard and may\n"
               "      break afl-fuzz performance optimizations when running "
               "platform-specific\n"
               "      binaries. To fix this, set AFL_NO_FORKSRV=1 in the "
               "environment.\n\n"

#endif /* __APPLE__ */

               "    - Least likely, there is a horrible bug in the fuzzer. If "
               "other options\n"
               "      fail, poke <lcamtuf@coredump.cx> for troubleshooting "
               "tips.\n",
               DMS(mem_limit << 20), mem_limit - 1, doc_path);

        } else {
          SAYF("\n" cLRD "[-] " cRST
               "Oops, the program crashed with one of the test cases provided. "
               "There are\n"
               "    several possible explanations:\n\n"

               "    - The test case causes known crashes under normal working "
               "conditions. If\n"
               "      so, please remove it. The fuzzer should be seeded with "
               "interesting\n"
               "      inputs - but not ones that cause an outright crash.\n\n"

#ifdef __APPLE__

               "    - On MacOS X, the semantics of fork() syscalls are "
               "non-standard and may\n"
               "      break afl-fuzz performance optimizations when running "
               "platform-specific\n"
               "      binaries. To fix this, set AFL_NO_FORKSRV=1 in the "
               "environment.\n\n"

#endif /* __APPLE__ */

               "    - Least likely, there is a horrible bug in the fuzzer. If "
               "other options\n"
               "      fail, poke <lcamtuf@coredump.cx> for troubleshooting "
               "tips.\n");
        }

        FATAL("Test case '%s' results in a crash", fn);

      case FAULT_ERROR:

        FATAL("Unable to execute target application ('%s')", argv[0]);

      case FAULT_NOINST:

        FATAL("No instrumentation detected");

      case FAULT_NOBITS:

        useless_at_start++;

        if (!in_bitmap && !shuffle_queue)
          WARNF("No new instrumentation output, test case may be useless.");

        break;
    }

    if (q->var_behavior) WARNF("Instrumentation output varies across runs.");

    q = q->next;
  }

  if (cal_failures) {
    if (cal_failures == queued_paths)
      FATAL("All test cases time out%s, giving up!",
            skip_crashes ? " or crash" : "");

    WARNF("Skipped %u test cases (%0.02f%%) due to timeouts%s.", cal_failures,
          ((double)cal_failures) * 100 / queued_paths,
          skip_crashes ? " or crashes" : "");

    if (cal_failures * 5 > queued_paths)
      WARNF(cLRD "High percentage of rejected test cases, check settings!");
  }

  OKF("All test cases processed.");
}

/* Spin up fork server (instrumented mode only). The idea is explained here:

   http://lcamtuf.blogspot.com/2014/10/fuzzing-binaries-without-execve.html

   In essence, the instrumentation allows us to skip execve(), and just keep
   cloning a stopped child. So, we just execute once, and then send commands
   through a pipe. The other part of this logic is in afl-as.h. */

void init_forkserver(char** argv) {
  static struct itimerval it;
  int st_pipe[2], ctl_pipe[2];
  int status;
  s32 rlen;

  ACTF("Spinning up the fork server...");

  if (pipe(st_pipe) || pipe(ctl_pipe)) PFATAL("pipe() failed");

  forksrv_pid = fork();

  if (forksrv_pid < 0) PFATAL("fork() failed");

  if (!forksrv_pid) {
    struct rlimit r;

    /* Umpf. On OpenBSD, the default fd limit for root users is set to
       soft 128. Let's try to fix that... */

    if (!getrlimit(RLIMIT_NOFILE, &r) && r.rlim_cur < FORKSRV_FD + 2) {
      r.rlim_cur = FORKSRV_FD + 2;
      setrlimit(RLIMIT_NOFILE, &r); /* Ignore errors */
    }

    if (mem_limit) {
      r.rlim_max = r.rlim_cur = ((rlim_t)mem_limit) << 20;

#ifdef RLIMIT_AS

      setrlimit(RLIMIT_AS, &r); /* Ignore errors */

#else

      /* This takes care of OpenBSD, which doesn't have RLIMIT_AS, but
         according to reliable sources, RLIMIT_DATA covers anonymous
         maps - so we should be getting good protection against OOM bugs. */

      setrlimit(RLIMIT_DATA, &r); /* Ignore errors */

#endif /* ^RLIMIT_AS */
    }

    /* Dumping cores is slow and can lead to anomalies if SIGKILL is delivered
       before the dump is complete. */

    r.rlim_max = r.rlim_cur = 0;

    setrlimit(RLIMIT_CORE, &r); /* Ignore errors */

    /* Isolate the process and configure standard descriptors. If out_file is
       specified, stdin is /dev/null; otherwise, out_fd is cloned instead. */

    setsid();

    dup2(dev_null_fd, 1);
    dup2(dev_null_fd, 2);

    if (out_file) {
      dup2(dev_null_fd, 0);

    } else {
      dup2(out_fd, 0);
      close(out_fd);
    }

    /* Set up control and status pipes, close the unneeded original fds. */

    if (dup2(ctl_pipe[0], FORKSRV_FD) < 0) PFATAL("dup2() failed");
    if (dup2(st_pipe[1], FORKSRV_FD + 1) < 0) PFATAL("dup2() failed");

    close(ctl_pipe[0]);
    close(ctl_pipe[1]);
    close(st_pipe[0]);
    close(st_pipe[1]);

    close(out_dir_fd);
    close(dev_null_fd);
    close(dev_urandom_fd);
    close(fileno(plot_file));

    /* This should improve performance a bit, since it stops the linker from
       doing extra work post-fork(). */

    if (!getenv("LD_BIND_LAZY")) setenv("LD_BIND_NOW", "1", 0);

    /* Set sane defaults for ASAN if nothing else specified. */

    setenv("ASAN_OPTIONS",
           "abort_on_error=1:"
           "detect_leaks=0:"
           "symbolize=0:"
           "allocator_may_return_null=1",
           0);

    /* MSAN is tricky, because it doesn't support abort_on_error=1 at this
       point. So, we do this in a very hacky way. */

    setenv("MSAN_OPTIONS", "exit_code=" STRINGIFY(MSAN_ERROR) ":"
                           "symbolize=0:"
                           "abort_on_error=1:"
                           "allocator_may_return_null=1:"
                           "msan_track_origins=0", 0);

    execv(target_path, argv);

    /* Use a distinctive bitmap signature to tell the parent about execv()
       falling through. */

    *(u32*)trace_bits = EXEC_FAIL_SIG;
    exit(0);
  }

  /* Close the unneeded endpoints. */

  close(ctl_pipe[0]);
  close(st_pipe[1]);

  fsrv_ctl_fd = ctl_pipe[1];
  fsrv_st_fd = st_pipe[0];

  /* Wait for the fork server to come up, but don't wait too long. */

  it.it_value.tv_sec = ((exec_tmout * FORK_WAIT_MULT) / 1000);
  it.it_value.tv_usec = ((exec_tmout * FORK_WAIT_MULT) % 1000) * 1000;

  setitimer(ITIMER_REAL, &it, NULL);

  rlen = read(fsrv_st_fd, &status, 4);

  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;

  setitimer(ITIMER_REAL, &it, NULL);

  /* If we have a four-byte "hello" message from the server, we're all set.
     Otherwise, try to figure out what went wrong. */

  if (rlen == 4) {
    OKF("All right - fork server is up.");
    return;
  }

  if (child_timed_out)
    FATAL("Timeout while initializing fork server (adjusting -t may help)");

  if (waitpid(forksrv_pid, &status, 0) <= 0) PFATAL("waitpid() failed");

  if (WIFSIGNALED(status)) {
    if (mem_limit && mem_limit < 500 && uses_asan) {
      SAYF("\n" cLRD "[-] " cRST
           "Whoops, the target binary crashed suddenly, before receiving any "
           "input\n"
           "    from the fuzzer! Since it seems to be built with ASAN and you "
           "have a\n"
           "    restrictive memory limit configured, this is expected; please "
           "read\n"
           "    %s/notes_for_asan.txt for help.\n",
           doc_path);

    } else if (!mem_limit) {
      SAYF(
          "\n" cLRD "[-] " cRST
          "Whoops, the target binary crashed suddenly, before receiving any "
          "input\n"
          "    from the fuzzer! There are several probable explanations:\n\n"

          "    - The binary is just buggy and explodes entirely on its own. If "
          "so, you\n"
          "      need to fix the underlying problem or find a better "
          "replacement.\n\n"

#ifdef __APPLE__

          "    - On MacOS X, the semantics of fork() syscalls are non-standard "
          "and may\n"
          "      break afl-fuzz performance optimizations when running "
          "platform-specific\n"
          "      targets. To fix this, set AFL_NO_FORKSRV=1 in the "
          "environment.\n\n"

#endif /* __APPLE__ */

          "    - Less likely, there is a horrible bug in the fuzzer. If other "
          "options\n"
          "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n");

    } else {
      SAYF("\n" cLRD "[-] " cRST
           "Whoops, the target binary crashed suddenly, before receiving any "
           "input\n"
           "    from the fuzzer! There are several probable explanations:\n\n"

           "    - The current memory limit (%s) is too restrictive, causing "
           "the\n"
           "      target to hit an OOM condition in the dynamic linker. Try "
           "bumping up\n"
           "      the limit with the -m setting in the command line. A simple "
           "way confirm\n"
           "      this diagnosis would be:\n\n"

#ifdef RLIMIT_AS
           "      ( ulimit -Sv $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#else
           "      ( ulimit -Sd $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#endif /* ^RLIMIT_AS */

           "      Tip: you can use http://jwilk.net/software/recidivm to "
           "quickly\n"
           "      estimate the required amount of virtual memory for the "
           "binary.\n\n"

           "    - The binary is just buggy and explodes entirely on its own. "
           "If so, you\n"
           "      need to fix the underlying problem or find a better "
           "replacement.\n\n"

#ifdef __APPLE__

           "    - On MacOS X, the semantics of fork() syscalls are "
           "non-standard and may\n"
           "      break afl-fuzz performance optimizations when running "
           "platform-specific\n"
           "      targets. To fix this, set AFL_NO_FORKSRV=1 in the "
           "environment.\n\n"

#endif /* __APPLE__ */

           "    - Less likely, there is a horrible bug in the fuzzer. If other "
           "options\n"
           "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n",
           DMS(mem_limit << 20), mem_limit - 1);
    }

    FATAL("Fork server crashed with signal %d", WTERMSIG(status));
  }

  if (*(u32*)trace_bits == EXEC_FAIL_SIG)
    FATAL("Unable to execute target application ('%s')", argv[0]);

  if (mem_limit && mem_limit < 500 && uses_asan) {
    SAYF("\n" cLRD "[-] " cRST
         "Hmm, looks like the target binary terminated before we could "
         "complete a\n"
         "    handshake with the injected code. Since it seems to be built "
         "with ASAN and\n"
         "    you have a restrictive memory limit configured, this is "
         "expected; please\n"
         "    read %s/notes_for_asan.txt for help.\n",
         doc_path);

  } else if (!mem_limit) {
    SAYF("\n" cLRD "[-] " cRST
         "Hmm, looks like the target binary terminated before we could "
         "complete a\n"
         "    handshake with the injected code. Perhaps there is a horrible "
         "bug in the\n"
         "    fuzzer. Poke <lcamtuf@coredump.cx> for troubleshooting tips.\n");

  } else {
    SAYF(
        "\n" cLRD "[-] " cRST
        "Hmm, looks like the target binary terminated before we could complete "
        "a\n"
        "    handshake with the injected code. There are %s probable "
        "explanations:\n\n"

        "%s"
        "    - The current memory limit (%s) is too restrictive, causing an "
        "OOM\n"
        "      fault in the dynamic linker. This can be fixed with the -m "
        "option. A\n"
        "      simple way to confirm the diagnosis may be:\n\n"

#ifdef RLIMIT_AS
        "      ( ulimit -Sv $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#else
        "      ( ulimit -Sd $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#endif /* ^RLIMIT_AS */

        "      Tip: you can use http://jwilk.net/software/recidivm to quickly\n"
        "      estimate the required amount of virtual memory for the "
        "binary.\n\n"

        "    - Less likely, there is a horrible bug in the fuzzer. If other "
        "options\n"
        "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n",
        getenv(DEFER_ENV_VAR) ? "three" : "two",
        getenv(DEFER_ENV_VAR)
            ? "    - You are using deferred forkserver, but __AFL_INIT() is "
              "never\n"
              "      reached before the program terminates.\n\n"
            : "",
        DMS(mem_limit << 20), mem_limit - 1);
  }

  FATAL("Fork server handshake failed");
}

/* Execute target application, monitoring for timeouts. Return status
   information. The called program will update trace_bits[]. */

u8 run_target(char** argv, u32 timeout) {
  static struct itimerval it;
  static u32 prev_timed_out = 0;
  static u64 exec_ms = 0;

  int status = 0;
  u32 tb4;

  child_timed_out = 0;

  /* After this memset, trace_bits[] are effectively volatile, so we
     must prevent any earlier operations from venturing into that
     territory. */

  memset(trace_bits, 0, MAP_SIZE);
  MEM_BARRIER();

  /* If we're running in "dumb" mode, we can't rely on the fork server
     logic compiled into the target program, so we will just keep calling
     execve(). There is a bit of code duplication between here and
     init_forkserver(), but c'est la vie. */

  if (dumb_mode == 1 || no_forkserver) {
    child_pid = fork();

    if (child_pid < 0) PFATAL("fork() failed");

    if (!child_pid) {
      struct rlimit r;

      if (mem_limit) {
        r.rlim_max = r.rlim_cur = ((rlim_t)mem_limit) << 20;

#ifdef RLIMIT_AS

        setrlimit(RLIMIT_AS, &r); /* Ignore errors */

#else

        setrlimit(RLIMIT_DATA, &r); /* Ignore errors */

#endif /* ^RLIMIT_AS */
      }

      r.rlim_max = r.rlim_cur = 0;

      setrlimit(RLIMIT_CORE, &r); /* Ignore errors */

      /* Isolate the process and configure standard descriptors. If out_file is
         specified, stdin is /dev/null; otherwise, out_fd is cloned instead. */

      setsid();

      dup2(dev_null_fd, 1);
      dup2(dev_null_fd, 2);

      if (out_file) {
        dup2(dev_null_fd, 0);

      } else {
        dup2(out_fd, 0);
        close(out_fd);
      }

      /* On Linux, would be faster to use O_CLOEXEC. Maybe TODO. */

      close(dev_null_fd);
      close(out_dir_fd);
      close(dev_urandom_fd);
      close(fileno(plot_file));

      /* Set sane defaults for ASAN if nothing else specified. */

      setenv("ASAN_OPTIONS",
             "abort_on_error=1:"
             "detect_leaks=0:"
             "symbolize=0:"
             "allocator_may_return_null=1",
             0);

      setenv("MSAN_OPTIONS", "exit_code=" STRINGIFY(MSAN_ERROR) ":"
                             "symbolize=0:"
                             "msan_track_origins=0", 0);

      execv(target_path, argv);

      /* Use a distinctive bitmap value to tell the parent about execv()
         falling through. */

      *(u32*)trace_bits = EXEC_FAIL_SIG;
      exit(0);
    }

  } else {
    s32 res;

    /* In non-dumb mode, we have the fork server up and running, so simply
       tell it to have at it, and then read back PID. */

    if ((res = write(fsrv_ctl_fd, &prev_timed_out, 4)) != 4) {
      if (stop_soon) return 0;
      RPFATAL(res, "Unable to request new process from fork server (OOM?)");
    }

    if ((res = read(fsrv_st_fd, &child_pid, 4)) != 4) {
      if (stop_soon) return 0;
      RPFATAL(res, "Unable to request new process from fork server (OOM?)");
    }

    if (child_pid <= 0) FATAL("Fork server is misbehaving (OOM?)");
  }

  /* Configure timeout, as requested by user, then wait for child to terminate.
   */

  it.it_value.tv_sec = (timeout / 1000);
  it.it_value.tv_usec = (timeout % 1000) * 1000;

  setitimer(ITIMER_REAL, &it, NULL);

  /* The SIGALRM handler simply kills the child_pid and sets child_timed_out. */

  if (dumb_mode == 1 || no_forkserver) {
    if (waitpid(child_pid, &status, 0) <= 0) PFATAL("waitpid() failed");

  } else {
    s32 res;

    if ((res = read(fsrv_st_fd, &status, 4)) != 4) {
      if (stop_soon) return 0;
      RPFATAL(res, "Unable to communicate with fork server (OOM?)");
    }
  }

  if (!WIFSTOPPED(status)) child_pid = 0;

  getitimer(ITIMER_REAL, &it);
  exec_ms =
      (u64)timeout - (it.it_value.tv_sec * 1000 + it.it_value.tv_usec / 1000);

  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;

  setitimer(ITIMER_REAL, &it, NULL);

  total_execs++;

  /* Any subsequent operations on trace_bits must not be moved by the
     compiler below this point. Past this location, trace_bits[] behave
     very normally and do not have to be treated as volatile. */

  MEM_BARRIER();

  tb4 = *(u32*)trace_bits;

#ifdef WORD_SIZE_64
  classify_counts((u64*)trace_bits);
#else
  classify_counts((u32*)trace_bits);
#endif /* ^WORD_SIZE_64 */

  prev_timed_out = child_timed_out;

  /* Report outcome to caller. */

  if (WIFSIGNALED(status) && !stop_soon) {
    kill_signal = WTERMSIG(status);

    if (child_timed_out && kill_signal == SIGKILL) return FAULT_TMOUT;

    return FAULT_CRASH;
  }

  /* A somewhat nasty hack for MSAN, which doesn't support abort_on_error and
     must use a special exit code. */

  if (uses_asan && WEXITSTATUS(status) == MSAN_ERROR) {
    kill_signal = 0;
    return FAULT_CRASH;
  }

  if ((dumb_mode == 1 || no_forkserver) && tb4 == EXEC_FAIL_SIG)
    return FAULT_ERROR;

  /* It makes sense to account for the slowest units only if the testcase was
  run under the user defined timeout. */
  if (!(timeout > exec_tmout) && (slowest_exec_ms < exec_ms)) {
    slowest_exec_ms = exec_ms;
  }

  return FAULT_NONE;
}

/* Write a modified test case, run program, process results. Handle
   error conditions, returning 1 if it's time to bail out. This is
   a helper function for fuzz_one(). */

u8 common_fuzz_stuff(char** argv, u8* out_buf, u32 len, Chunk* tree, Track *track) {
  u8 fault;

  total_mutation += 1;
  
  if (post_handler) {
    out_buf = post_handler(out_buf, &len);
    if (!out_buf || !len) return 0;
  }

  write_to_testcase(out_buf, len);

  fault = run_target(argv, exec_tmout);

  if (stop_soon) return 1;

  if (fault == FAULT_TMOUT) {
    if (subseq_tmouts++ > TMOUT_LIMIT) {
      cur_skipped_paths++;
      return 1;
    }

  } else
    subseq_tmouts = 0;

  /* Users can hit us with SIGUSR1 to request the current input
     to be abandoned. */

  if (skip_requested) {
    skip_requested = 0;
    cur_skipped_paths++;
    return 1;
  }

  /* This handles FAULT_ERROR for us: */
  queued_discovered += save_if_interesting(argv, out_buf, len, fault, tree, track);

  if (!(stage_cur % stats_update_freq) || stage_cur + 1 == stage_max) {
    show_stats();
  }

  return 0;
}