#include "afl-fuzz.h"

/* Mark deterministic checks as done for a particular queue entry. We use the
   .state file to avoid repeating deterministic fuzzing when resuming aborted
   scans. */

void mark_as_det_done(struct queue_entry* q) {
  u8* fn = strrchr(q->fname, '/');
  s32 fd;

  fn = alloc_printf("%s/queue/.state/deterministic_done/%s", out_dir, fn + 1);

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) PFATAL("Unable to create '%s'", fn);
  close(fd);

  ck_free(fn);

  q->passed_det = 1;
}

/* Mark as variable. Create symlinks if possible to make it easier to examine
   the files. */

void mark_as_variable(struct queue_entry* q) {
  u8 *fn = strrchr(q->fname, '/') + 1, *ldest;

  ldest = alloc_printf("../../%s", fn);
  fn = alloc_printf("%s/queue/.state/variable_behavior/%s", out_dir, fn);

  if (symlink(ldest, fn)) {
    s32 fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) PFATAL("Unable to create '%s'", fn);
    close(fd);
  }

  ck_free(ldest);
  ck_free(fn);

  q->var_behavior = 1;
}

/* Mark / unmark as redundant (edge-only). This is not used for restoring state,
   but may be useful for post-processing datasets. */

void mark_as_redundant(struct queue_entry* q, u8 state) {
  u8* fn;
  s32 fd;

  if (state == q->fs_redundant) return;

  q->fs_redundant = state;

  fn = strrchr(q->fname, '/');
  fn = alloc_printf("%s/queue/.state/redundant_edges/%s", out_dir, fn + 1);

  if (state) {
    fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) PFATAL("Unable to create '%s'", fn);
    close(fd);

  } else {
    if (unlink(fn)) PFATAL("Unable to remove '%s'", fn);
  }

  ck_free(fn);
}

/* The second part of the mechanism discussed above is a routine that
   goes over top_rated[] entries, and then sequentially grabs winners for
   previously-unseen bytes (temp_v) and marks them as favored, at least
   until the next run. The favored entries are given more air time during
   all fuzzing steps. */

void cull_queue(void) {
  struct queue_entry* q;
  static u8 temp_v[MAP_SIZE >> 3];
  u32 i;

  if (dumb_mode || !score_changed) return;

  score_changed = 0;

  memset(temp_v, 255, MAP_SIZE >> 3);

  queued_favored = 0;
  pending_favored = 0;

  q = queue;

  while (q) {
    q->favored = 0;
    q = q->next;
  }

  /* Let's see if anything in the bitmap isn't captured in temp_v.
     If yes, and if it has a top_rated[] contender, let's use it. */

  for (i = 0; i < MAP_SIZE; i++)
    if (top_rated[i] && (temp_v[i >> 3] & (1 << (i & 7)))) {
      u32 j = MAP_SIZE >> 3;

      /* Remove all bits belonging to the current entry from temp_v. */

      while (j--)
        if (top_rated[i]->trace_mini[j])
          temp_v[j] &= ~top_rated[i]->trace_mini[j];

      top_rated[i]->favored = 1;
      queued_favored++;

      if (!top_rated[i]->was_fuzzed) pending_favored++;
    }

  q = queue;

  while (q) {
    mark_as_redundant(q, !q->favored);
    q = q->next;
  }
}

/* Append new test case to the queue. */

void add_to_queue(u8* fname, u8* format_file, u8* track_file, u32 len, u8 passed_det) {
  struct queue_entry* q = ck_alloc(sizeof(struct queue_entry));

  /*Need to change*/
  q->fname = fname;
  q->len = len;
  q->format_file = format_file;
  q->track_file = track_file;
  q->depth = cur_depth + 1;
  q->passed_det = passed_det;
  q->par_mutators = NULL;
  q->my_mutators = NULL;
  q->was_inferred = 0;

  if (q->depth > max_depth) max_depth = q->depth;

  if (queue_top) {
    queue_top->next = q;
    queue_top = q;

  } else
    q_prev100 = queue = queue_top = q;

  queued_paths++;
  pending_not_fuzzed++;

  cycles_wo_finds = 0;

  if (!(queued_paths % 100)) {
    q_prev100->next_100 = q;
    q_prev100 = q;
  }
  last_path_time = get_cur_time();
}

/* Destroy the entire queue. */

void destroy_queue(void) {
  struct queue_entry *q = queue, *n;

  while (q) {
    n = q->next;
    ck_free(q->fname);
    ck_free(q->format_file);
    if(q->track_file) {
      ck_free(q->track_file);
    }
    if(q->par_mutators) {
      ck_free(q->par_mutators);
    }
    if(q->my_mutators) {
      ck_free(q->my_mutators);
    }
    ck_free(q->trace_mini);
    ck_free(q);
    q = n;
  }
}

/* Grab interesting test cases from other fuzzers. */

void sync_fuzzers(char** argv) {
  DIR* sd;
  struct dirent* sd_ent;
  u32 sync_cnt = 0;

  sd = opendir(sync_dir);
  if (!sd) PFATAL("Unable to open '%s'", sync_dir);

  stage_max = stage_cur = 0;
  cur_depth = 0;

  /* Look at the entries created for every other fuzzer in the sync directory.
   */

  while ((sd_ent = readdir(sd))) {
    static u8 stage_tmp[128];

    DIR* qd;
    struct dirent* qd_ent;
    u8 *qd_path, *qd_synced_path;
    u32 min_accept = 0, next_min_accept;

    s32 id_fd;

    u8* file_type;

    /* Skip dot files and our own output directory. */

    if (sd_ent->d_name[0] == '.' || !strcmp(sync_id, sd_ent->d_name)) continue;

    /* Skip anything that doesn't have a queue/ subdirectory. */

    qd_path = alloc_printf("%s/%s/queue", sync_dir, sd_ent->d_name);

    if (!(qd = opendir(qd_path))) {
      ck_free(qd_path);
      continue;
    }

    /* Retrieve the ID of the last seen test case. */

    qd_synced_path = alloc_printf("%s/.synced/%s", out_dir, sd_ent->d_name);

    id_fd = open(qd_synced_path, O_RDWR | O_CREAT, 0600);

    if (id_fd < 0) PFATAL("Unable to create '%s'", qd_synced_path);

    if (read(id_fd, &min_accept, sizeof(u32)) > 0) lseek(id_fd, 0, SEEK_SET);

    next_min_accept = min_accept;

    /* Show stats */

    sprintf(stage_tmp, "sync %u", ++sync_cnt);
    stage_name = stage_tmp;
    stage_cur = 0;
    stage_max = 0;

    /* For every file queued by this fuzzer, parse ID and see if we have looked
       at it before; exec a test case if not. */

    while ((qd_ent = readdir(qd))) {
      u8 *path, *format_path, *track_path;
      s32 fd;
      struct stat st;
      Chunk *tree;
      Track *track;

      if (qd_ent->d_name[0] == '.' ||
          sscanf(qd_ent->d_name, CASE_PREFIX "%06u", &syncing_case) != 1 ||
          syncing_case < min_accept)
        continue;

      /* Skip .json file */
      file_type = strrchr(qd_ent->d_name, '.');
      if (file_type != NULL && strcmp(file_type, ".json") == 0) {
        continue;
      }
      
      /* Skip .track file */
      if (file_type != NULL && strcmp(file_type, ".track") == 0) {
        continue;
      }

      /* Skip .log file */
      if (file_type != NULL && strcmp(file_type, ".log") == 0) {
        continue;
      }

      /* OK, sounds like a new one. Let's give it a try. */

      if (syncing_case >= next_min_accept) next_min_accept = syncing_case + 1;

      path = alloc_printf("%s/%s", qd_path, qd_ent->d_name);

      format_path = alloc_printf("%s/%s.json", qd_path, qd_ent->d_name);

      track_path = alloc_printf("%s/%s.track", qd_path, qd_ent->d_name);

      /* Allow this to fail in case the other fuzzer is resuming or so... */

      fd = open(path, O_RDONLY);

      if (fd < 0) {
        ck_free(path);
        ck_free(format_path);
        ck_free(track_path);
        continue;
      }

      // format_fd = open(format_path, O_RDONLY);
      // if (format_fd < 0) {
      //   ck_free(path);
      //   ck_free(format_path);
      //   continue;
      // }

      // track_fd = open(track_path, O_RDONLY);
      // if(track_fd < 0) {
      //   ck_free(track_path);
      // }

      if (fstat(fd, &st)) PFATAL("fstat() failed");

      /* Ignore zero-sized or oversized files. */

      if (st.st_size && st.st_size <= MAX_FILE) {
        u8 fault;
        u8* mem = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

        if (mem == MAP_FAILED) PFATAL("Unable to mmap '%s'", path);
        tree = parse_struture_file(format_path);

        track = parse_constraint_file(track_path);

        /* See what happens. We rely on save_if_interesting() to catch major
           errors and save the test case. */

        write_to_testcase(mem, st.st_size);

        fault = run_target(argv, exec_tmout);

        if (stop_soon) return;

        syncing_party = sd_ent->d_name;
        queued_imported +=
            save_if_interesting(argv, mem, st.st_size, fault, tree, track);
        syncing_party = 0;

        munmap(mem, st.st_size);
        free_tree(tree, True);

        if (!(stage_cur++ % stats_update_freq)) {
          show_stats();
        }
      }

      ck_free(path);
      ck_free(format_path);
      ck_free(track_path);
      close(fd);
      // close(format_fd);
      // close(track_fd);
    }

    ck_write(id_fd, &next_min_accept, sizeof(u32), qd_synced_path);

    close(id_fd);
    closedir(qd);
    ck_free(qd_path);
    ck_free(qd_synced_path);
  }

  closedir(sd);
}

