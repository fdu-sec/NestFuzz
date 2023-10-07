use super::*;
use crate::{loop_handlers::*, tag_set_wrap::*};
use angora_common::{cond_stmt_base::*, defs};
use lazy_static::lazy_static;
use libc::c_char;
use std::convert::TryInto;
use std::vec;
use std::{
    // ffi::CStr,
    env,
    ffi::CStr,
    ffi::OsStr,
    path::PathBuf,
    slice,
    sync::Mutex,
};

// Lazy static doesn't have reference count and won't call drop after the program finish.
// So, we should call drop manually.. see ***_fini.
lazy_static! {
    static ref OS: Mutex<Option<ObjectStack>> = Mutex::new(Some(ObjectStack::new()));
}

lazy_static! {
    static ref CLS: Mutex<Option<CmpLabelsStack>> = Mutex::new(Some(CmpLabelsStack::new()));
}

#[no_mangle]
pub extern "C" fn __chunk_get_load_label(_a: *const i8, _b: usize) {
    panic!("Forbid calling __chunk_get_load_label directly");
}

#[no_mangle]
pub extern "C" fn __dfsw___chunk_get_load_label(
    addr: *const i8,
    size: usize,
    _l0: DfsanLabel,
    _l1: DfsanLabel,
) -> u32 {
    let mut osl = OS.lock().unwrap();
    if let Some(ref mut os) = *osl {
        let arglen = if size == 0 {
            unsafe { libc::strlen(addr) as usize }
        } else {
            size
        };
        let lb = unsafe { dfsan_read_label(addr, arglen) };
        if lb <= 0 {
            if cfg!(debug_assertions) {
                eprintln!("[DEBUG] Load operation has no label");
            }
            return 0;
        }
        infer_shape(lb, arglen as u32);
        os.get_load_label(lb);
        return lb;
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn __chunk_push_new_obj(_a: u8, _b: u32, _c: u32) {
    panic!("Forbid calling __chunk_push_new_obj directly");
}

#[no_mangle]
pub extern "C" fn __dfsw___chunk_push_new_obj(
    is_loop: bool,
    loop_cnt: u32,
    loop_hash: u32,
    _l0: DfsanLabel,
    _l1: DfsanLabel,
    _l2: DfsanLabel,
) {
    //One object for one loop
    if is_loop && loop_cnt != 0 {
        return;
    }
    let mut osl = OS.lock().unwrap();
    if let Some(ref mut os) = *osl {
        os.new_obj(is_loop, loop_hash);
    }
}

#[no_mangle]
pub extern "C" fn __chunk_dump_each_iter(_a: u32) {
    panic!("Forbid calling __chunk_dump_each_iter directly");
}

#[no_mangle]
pub extern "C" fn __dfsw___chunk_dump_each_iter(loop_cnt: u32, _l0: DfsanLabel) {
    if loop_cnt == 0 {
        return;
    } else {
        let mut osl = OS.lock().unwrap();
        if let Some(ref mut os) = *osl {
            os.dump_cur_iter(loop_cnt);
        }
    }
}

#[no_mangle]
pub extern "C" fn __chunk_pop_obj(_a: u32) -> bool {
    panic!("Forbid calling __chunk_pop_obj directly");
}

#[no_mangle]
pub extern "C" fn __dfsw___chunk_pop_obj(loop_hash: u32, _l0: DfsanLabel) -> bool {
    let mut osl = OS.lock().unwrap();
    if let Some(ref mut os) = *osl {
        os.pop_obj(loop_hash);
        true
    } else {
        panic!("POP ERROR!");
    }
}

#[no_mangle]
pub extern "C" fn __chunk_object_stack_fini() {
    let mut osl = OS.lock().unwrap();
    *osl = None;
    let mut lcl = LC.lock().unwrap();
    *lcl = None;
}

#[no_mangle]
pub extern "C" fn __chunk_set_input_file_name(fsize: u32) {
    let input_file = match env::var("CHUNK_CURRENT_INPUT_FILE") {
        Ok(path) => PathBuf::from(path),
        Err(_) => panic!("set input_name error"),
    };
    let file_name = match input_file.file_name() {
        Some(tmp) => tmp.to_str().unwrap(),
        None => panic!("cannot get input file name"),
    };
    let mut osl = OS.lock().unwrap();
    if let Some(ref mut os) = *osl {
        // set json file path
        let mut json_file = input_file.clone();
        let json_name = &format!("{}{}", file_name, ".json");
        let json_name_os: &OsStr = OsStr::new(json_name);
        json_file.set_file_name(json_name_os);
        os.set_input_file_name(json_file);
        os.set_input_file_size(fsize);

        // set log file path
        let mut log_file = input_file.clone();
        let log_name = &format!("{}{}", file_name, ".log");
        let log_name_os = OsStr::new(log_name);
        log_file.set_file_name(log_name_os);
        os.set_log_file_name(log_file);
    }
    let mut lcl = LC.lock().expect("Could not lock LC.");
    if let Some(ref mut lc) = *lcl {
        let mut track_file = input_file.clone();
        let track_name = &format!("{}{}", file_name, ".track");
        let track_name_os: &OsStr = OsStr::new(track_name);
        track_file.set_file_name(track_name_os);
        lc.set_input_file_name(track_file);
    }
}

#[no_mangle]
pub extern "C" fn __chunk_trace_cmp_tt(
    _a: u32,
    _b: u32,
    _c: u64,
    _d: u64,
    _e: u32,
    _f: u8,
    _g: u8,
    _h: u8,
) {
    panic!("Forbid calling __chunk_trace_cmp_tt directly");
}

#[no_mangle]
pub extern "C" fn __dfsw___chunk_trace_cmp_tt(
    size: u32,
    op: u32,
    arg1: u64,
    arg2: u64,
    _condition: u32,
    in_loop_header: u8,
    is_cnst1: u8,
    is_cnst2: u8,
    _l0: DfsanLabel,
    _l1: DfsanLabel,
    l2: DfsanLabel,
    l3: DfsanLabel,
    _l4: DfsanLabel,
    _l5: DfsanLabel,
    _l6: DfsanLabel,
    _l7: DfsanLabel,
) {
    let lb1 = l2;
    let lb2 = l3;
    if lb1 == 0 && lb2 == 0 {
        return;
    }
    let mut size1 = 0;
    let mut size2 = 0;
    if cfg!(debug_assertions) {
        eprintln!("[DEBUG] __dfsw___chunk_trace_cmp_tt");
    }
    if in_loop_header == 1 {
        // 传入loop_handler,计数，收集在loop_header中的label的重复使用次数，在pop时过滤只使用一次的
        let mut osl = OS.lock().unwrap();
        if let Some(ref mut os) = *osl {
            // The tainted value used in loop header may be the length.
            if lb1 != 0 {
                os.maybe_length(lb1);
            }
            if lb2 != 0 {
                os.maybe_length(lb2);
            }
            os.count_cmp_num();
        }
    }
    infer_shape(lb1, size);
    infer_shape(lb2, size);
    let mut osl = OS.lock().unwrap();
    if let Some(ref mut os) = *osl {
        size1 = os.get_load_label(lb1);
        size2 = os.get_load_label(lb2);
    }
    // let op = infer_eq_sign(op, lb1, lb2);
    if cfg!(debug_assertions) {
        eprintln!("[DEBUG] op is {}, lb1 is {}, lb2 is {}, is_cnst2 is {}, arg2 is {}, size = {}, size1 = {}, size2 = {}", op, lb1, lb2, is_cnst2, arg2, size, size1, size2);
    }
    if op == 32 || op == 33 {
        if lb1 != 0 && lb2 == 0 && is_cnst2 == 1 {
            //log enum

            if arg2 == 0 {
                return;
            }
            let vec8 = arg2.to_le_bytes().to_vec();
            size2 = size1;
            let len = vec8.len();
            if size2 > len as u32 {
                size2 = len as u32
            }
            let slice_vec8 = &vec8[..size2 as usize];
            let vec8 = slice_vec8.to_vec();
            if cfg!(debug_assertions) {
                eprintln!("size2 is {}, size1 is {}, lb1 is {}, vec.len is {}", size2, size1, lb1, vec8.len());
            }
            log_enum(size2, lb1 as u64, vec8);
            return;
        } else if lb1 == 0 && lb2 != 0 && is_cnst1 == 1 {
            if arg1 == 0 {
                return;
            }
            size1 = size2;
            let vec8 = arg1.to_le_bytes().to_vec();
            let slice_vec8 = &vec8[..size1 as usize];
            let vec8 = slice_vec8.to_vec();

            log_enum(size1, lb2 as u64, vec8);
            return;
        } else if lb1 != 0 && lb2 != 0 {
            //maybe checksum
            //一个标签对应的数据长度等于size,另一个大于size
            //continous data
            if size1 != 0 && size2 != 0 {
                let list1 = tag_set_find(lb1.try_into().unwrap());
                let list2 = tag_set_find(lb2.try_into().unwrap());
                if size1 == size && size2 > size {
                    if list1.len() == 1 && list2.len() != 1 {
                        log_cond(0, size2, lb1 as u64, lb2 as u64, ChunkField::Checksum);
                        return;
                    }
                } else if size1 > size && size2 == size {
                    if list1.len() != 1 && list2.len() == 1 {
                        log_cond(0, size1, lb2 as u64, lb1 as u64, ChunkField::Checksum);
                        return;
                    }
                }
            }
        }
    }
    if lb1 != 0 && lb2 != 0 {
        log_cond(op, size, lb1 as u64, lb2 as u64, ChunkField::Constraint);
    }
}

#[no_mangle]
pub extern "C" fn __chunk_trace_switch_tt(_a: u32, _b: u64, _c: u32, _d: *mut u64, _e: u8) {
    panic!("Forbid calling __chunk_trace_switch_tt directly");
}

#[no_mangle]
pub extern "C" fn __dfsw___chunk_trace_switch_tt(
    size: u32,
    _condition: u64,
    num: u32,
    args: *mut u64,
    _l0: DfsanLabel,
    l1: DfsanLabel,
    _l2: DfsanLabel,
    _l3: DfsanLabel,
) {
    let lb = l1;
    if lb == 0 {
        return;
    }
    let mut real_size = 0;
    // let mut op = defs::COND_ICMP_EQ_OP;
    let sw_args = unsafe { slice::from_raw_parts(args, num as usize) }.to_vec();
    let mut osl = OS.lock().unwrap();
    if let Some(ref mut os) = *osl {
        real_size = os.get_load_label(lb);
        if real_size > size {
            real_size = size;
        }
        os.count_switch_num();
    }
    for arg in sw_args {
        let vec8 = arg.to_le_bytes().to_vec();
        let slice_vec8 = &vec8[..real_size as usize]; // wrong
        let vec8 = slice_vec8.to_vec();
        log_enum(real_size, lb as u64, vec8.clone());
    }
}

#[no_mangle]
pub extern "C" fn __chunk_trace_cmpfn_tt(_a: *mut i8, _b: *mut i8, _c: u32, _d: u8, _e: u8) {
    panic!("Forbid calling __chunk_trace_cmpfn_tt directly");
}

#[no_mangle]
pub extern "C" fn __dfsw___chunk_trace_cmpfn_tt(
    parg1: *const c_char,
    parg2: *const c_char,
    size: u32,
    _is_cnst1: u8,
    _is_cnst2: u8,
    _l0: DfsanLabel,
    _l1: DfsanLabel,
    _l2: DfsanLabel,
    _l3: DfsanLabel,
    _l4: DfsanLabel,
) {
    let (arglen1, arglen2) = if size == 0 {
        unsafe { (libc::strlen(parg1) as usize, libc::strlen(parg2) as usize) }
    } else {
        (size as usize, size as usize)
    };

    let lb1 = unsafe { dfsan_read_label(parg1, arglen1) };
    let lb2 = unsafe { dfsan_read_label(parg2, arglen2) };

    if lb1 == 0 && lb2 == 0 {
        return;
    }

    let arg1 = unsafe { slice::from_raw_parts(parg1 as *mut u8, arglen1) }.to_vec();
    let arg2 = unsafe { slice::from_raw_parts(parg2 as *mut u8, arglen2) }.to_vec();
    if lb1 > 0 && lb2 > 0 {
        log_cond(
            defs::COND_FN_OP,
            arglen1 as u32,
            lb1 as u64,
            lb2 as u64,
            ChunkField::Constraint,
        ); // op need check
        let mut osl = OS.lock().unwrap();
        if let Some(ref mut os) = *osl {
            infer_shape(lb1, arglen1 as u32);
            infer_shape(lb2, arglen2 as u32);
            os.get_load_label(lb1);
            os.get_load_label(lb2);
        }
    } else if lb1 > 0 {
        log_enum(arglen2 as u32, lb1 as u64, arg2);
        let mut osl = OS.lock().unwrap();
        if let Some(ref mut os) = *osl {
            infer_shape(lb1, arglen1 as u32);
            os.get_load_label(lb1);
        }
    } else if lb2 > 0 {
        log_enum(arglen1 as u32, lb2 as u64, arg1);
        let mut osl = OS.lock().unwrap();
        if let Some(ref mut os) = *osl {
            infer_shape(lb2, arglen2 as u32);
            os.get_load_label(lb2);
        }
    }
}

#[no_mangle]
pub extern "C" fn __chunk_trace_offsfn_tt(_a: u32, _b: u32, _c: u8) {
    panic!("Forbid calling __chunk_trace_offsfn_tt directly");
}

#[no_mangle]
pub extern "C" fn __dfsw___chunk_trace_offsfn_tt(
    offset: i32,
    whence: u32,
    l0: DfsanLabel,
    _l1: DfsanLabel,
) {
    // whence: SEEK_SET 0 ;SEEK_CUR 1; SEEK_END 2
    if l0 != 0 {
        log_cond(whence, offset as u32, l0 as u64, 0, ChunkField::Offset);
        let mut osl = OS.lock().unwrap();
        if let Some(ref mut os) = *osl {
            os.get_load_label(l0);
        }
    }
}

#[no_mangle]
pub extern "C" fn __chunk_trace_lenfn_tt(_a: *mut i8, _b: u64, _c: u32, _d: u64) {
    panic!("Forbid calling __chunk_trace_lenfn_tt directly");
}

#[no_mangle]
pub extern "C" fn __dfsw___chunk_trace_lenfn_tt(
    dst: *mut i8,
    _len1: u64,
    len2: u32,
    ret: u64,
    _l0: DfsanLabel,
    l1: DfsanLabel,
    l2: DfsanLabel,
    _l3: DfsanLabel,
) {
    if l1 == 0 && l2 == 0 {
        return;
    }

    let len = ret as usize;

    let lb = unsafe { dfsan_read_label(dst, len) };
    // lb先dst后len
    if lb != 0 && l1 != 0 {
        if cfg!(debug_assertions) {
            eprintln!("[DEBUG] length: {}, lb: {}, l1: {}", len, lb, l1);
        }
        log_cond(0, len as u32, l1 as u64, lb as u64, ChunkField::Length);
        let mut osl = OS.lock().unwrap();
        if let Some(ref mut os) = *osl {
            os.get_load_label(lb);
            os.get_load_label(l1);
        }
    }

    if len2 != 0 && lb != 0 && l2 != 0 {
        if cfg!(debug_assertions) {
            eprintln!("[DEBUG] length {}, lb: {}, l2: {}", len, lb, l2);
        }
        log_cond(0, len as u32, l2 as u64, lb as u64, ChunkField::Length);
        let mut osl = OS.lock().unwrap();
        if let Some(ref mut os) = *osl {
            os.get_load_label(lb);
            os.get_load_label(l2);
        }
    }
}

#[no_mangle]
pub extern "C" fn __chunk_trace_branch_tt(_a: u32, _b: u8) {
    panic!("Forbid calling __chunk_trace_branch_tt directly");
}

#[no_mangle]
pub extern "C" fn __dfsw___chunk_trace_branch_tt(
    hash: u32,
    itype: u8,
    _l1: DfsanLabel,
    _l2: DfsanLabel,
) {
    let mut clsl = CLS.lock().unwrap();
    if let Some(ref mut cls) = *clsl {
        match itype {
            0 => {
                cls.new_label(hash);
            }
            1 => {
                cls.pop_label(hash);
            }
            _ => {
                panic!("trace branch error!");
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn __debug_inst_loc_fn(_a: *const i8, _b: u32, _c: u32, _d: u32, _e: u32) {
    panic!("Forbid calling __debug_inst_loc_fn directly");
}

#[no_mangle]
pub extern "C" fn __dfsw___debug_inst_loc_fn(
    fname: *const i8,
    line: u32,
    col: u32,
    hash: u32,
    itype: u32,
    _l1: DfsanLabel,
    _l2: DfsanLabel,
    _l3: DfsanLabel,
    _l4: DfsanLabel,
    _l5: DfsanLabel,
) {

    if !cfg!(debug_assertions) {
        return;
    }
    // convert C string tp Rust string
    let chr = unsafe {
        assert!(!fname.is_null());
        CStr::from_ptr(fname)
    };
    let fname_slice = chr.to_str().unwrap();

    match itype {
        0 => {
            eprint!("[func call] ");
        }
        1 => {
            eprint!("[cmp func] ");
        }
        2 => {
            eprint!("[offset func] ");
        }
        3 => {
            eprint!("[fread] ");
        }
        4 => {
            eprint!("[memcpy] ");
        }
        5 => {
            eprint!("[read] ");
        }
        6 => {
            eprint!("[switch] ");
        }
        7 => {
            eprint!("\n[cmp inst] ");
        }
        8 => {
            eprint!("[load] ");
        }
        _ => {}
    }

    eprintln!(
        "trace : hash {:016X}, {}, {}, {}",
        hash, fname_slice, line, col
    );
}

/*
#[no_mangle]
pub extern "C" fn __chunk_trace_gep_tt(
    _a: *const i8,
    _b: usize,
    _c: u32,
) {
    panic!("Forbid calling __chunk_trace_gep_tt directly");
}

#[no_mangle]
pub extern "C" fn __dfsw___chunk_trace_gep_tt(
    addr: *const i8,
    size: usize,
    load_lb: u32,
    _l0: DfsanLabel,
    _l1: DfsanLabel,
    _l2: DfsanLabel,
) {
    if loop_handlers::ObjectStack::access_check(load_lb as u64, 0) == 0 {
        return;
    }
    let mut osl = OS.lock().unwrap();
    if let Some(ref mut os) = *osl {
        let arglen = if size == 0 {
            unsafe { libc::strlen(addr) as usize }
        } else {
            size
        };
        let lb = unsafe { dfsan_read_label(addr, arglen) };
        if lb <= 0 {
            return;
        }
        infer_shape(lb, arglen as u32);
        os.get_load_label(lb);
        println!("offset: offset-lb:{}, paylaod-lb:{}", lb, load_lb);
        log_cond(1, size as u32, lb as u64, load_lb as u64, ChunkField::Offset)
    }

}
*/

fn infer_eq_sign(op: u32, lb1: u32, lb2: u32) -> u32 {
    if op == defs::COND_ICMP_EQ_OP
        && ((lb1 > 0 && tag_set_wrap::tag_set_get_sign(lb1 as usize))
            || (lb2 > 0 && tag_set_wrap::tag_set_get_sign(lb2 as usize)))
    {
        return op | defs::COND_SIGN_MASK;
    }
    op
}

fn infer_shape(lb: u32, size: u32) {
    if lb > 0 {
        tag_set_wrap::__angora_tag_set_infer_shape_in_math_op(lb, size);
    }
}

fn log_cond(op: u32, size: u32, lb1: u64, lb2: u64, field: ChunkField) {
    let cond = CondStmtBase {
        op,
        size,
        lb1,
        lb2,
        field,
    };
    let mut lcl = LC.lock().expect("Could not lock LC.");
    if let Some(ref mut lc) = *lcl {
        lc.save(cond);
    }
}

fn log_enum(size: u32, lb: u64, enums: Vec<u8>) {
    if enums.len() != size as usize || size == 0 {
        return;
    }
    let mut lcl = LC.lock().expect("Could not lock LC.");
    if let Some(ref mut lc) = *lcl {
        lc.save_enums(lb, enums);
    }
}
