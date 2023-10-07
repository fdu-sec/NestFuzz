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

use crate::logger::Logger;
pub use crate::{tag_set::TagSet};

pub type DfsanLabel = u32;
extern "C" {
    fn dfsan_read_label(addr: *const i8, size: usize) -> DfsanLabel;
}
