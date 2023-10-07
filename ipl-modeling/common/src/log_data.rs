use crate::{cond_stmt_base::CondStmtBase};
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Hash)]
pub struct Offset {
    pub begin: u32,
    pub end: u32,
    pub size: u32,
}

impl Offset {
    pub fn new(
        begin: u32,
        end: u32,
        size: u32,
    ) -> Self {
        Self {
            begin,
            end,
            size,
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct LogData {
    pub cond_list: Vec<CondStmtBase>,
    pub tags: HashMap<u64, Offset>, // key: lb, value: offset{begin, end, size}
    pub enums: HashMap<u64, Vec<Vec<u8>>>, //key: lb, value: candidates
    pub linear_constraint: Vec<u32>,
}

impl LogData {
    pub fn new() -> Self {
        Self {
            cond_list: vec![],
            tags: HashMap::new(),
            enums: HashMap::new(),
            linear_constraint: vec![],
        }
    }
}
