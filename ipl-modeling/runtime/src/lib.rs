pub mod ffds;
pub mod heapmap;
pub mod len_label;
pub mod logger;
mod tag_set;
pub mod tag_set_wrap;
// pub mod track;
pub mod loop_handlers;
pub mod loop_handlers_wrap;
pub mod stats;

use std::cell::RefCell;
use std::thread;
use is_main_thread::is_main_thread;

use crate::logger::Logger;
pub use crate::{tag_set::TagSet};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ThreadFlag {
    MainThread,
    SubThread,
    UnknownThread,
}

// Define the thread-local variable
thread_local! {
    pub static THREAD_LOCAL_FLAG: RefCell<ThreadFlag> = RefCell::new(ThreadFlag::UnknownThread);
}

pub fn set_thread_flag(flag: ThreadFlag) {
    THREAD_LOCAL_FLAG.with(|data| {
        *data.borrow_mut() = flag;
    });
}

pub fn get_thread_flag() -> ThreadFlag {
    THREAD_LOCAL_FLAG.with(|data| *data.borrow())
}

pub fn check_and_set_thread_flag() -> bool {
    match get_thread_flag() {
        ThreadFlag::MainThread => {
            if cfg!(debug_assertions) {
                println!("[DEBUG] This is the main thread.");
            }
            true
        },
        ThreadFlag::UnknownThread => {
            match is_main_thread() {
                Some(true) => {
                    set_thread_flag(ThreadFlag::MainThread);
                    true
                },
                _ => {
                    set_thread_flag(ThreadFlag::SubThread);
                    false
                }
            }
        },
        ThreadFlag::SubThread =>  {
            if cfg!(debug_assertions) {
                println!("[DEBUG] This is not the main thread. {:?}", thread::current().id());
            }
            false
        },
    }
}

pub type DfsanLabel = u32;
extern "C" {
    fn dfsan_read_label(addr: *const i8, size: usize) -> DfsanLabel;
}