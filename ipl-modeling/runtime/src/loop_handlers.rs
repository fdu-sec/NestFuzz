use super::*;
use angora_common::{cond_stmt_base::*, log_data::*, tag::*};
// use itertools::Itertools;
use crate::{stats::Stats, tag_set_wrap};
use lazy_static::lazy_static;
use rand::Rng;
use std::collections::HashMap;
use std::{cmp::*, env, fs::File, io::prelude::*, path::PathBuf, sync::Mutex, time::*};

const STACK_MAX: usize = 100000;

lazy_static! {
    pub static ref LC: Mutex<Option<Logger>> = Mutex::new(Some(Logger::new()));
}

// lazy_static! {
//     pub static ref CT: Mutex<Option<Vec<Offset>>> = Mutex::new(Some(Vec::new()));
// }

// Loop & Function labels.
#[derive(Debug, Clone)]
pub struct ObjectLabels {
    is_loop: bool,
    hash: u32,
    cur_iter: Option<Vec<TaintSeg>>,
    cur_iter_num: u32,
    sum: Vec<TaintSeg>,
    length_candidates: HashMap<u32, u32>,
}

impl ObjectLabels {
    pub fn new(is_loop: bool, hash: u32) -> Self {
        let cur_iter = if is_loop { Some(vec![]) } else { None };
        Self {
            is_loop,
            hash,
            cur_iter,
            cur_iter_num: 0,
            sum: vec![],
            length_candidates: HashMap::new(),
        }
    }
}

#[derive(Debug)]
pub struct ObjectStack {
    objs: Vec<ObjectLabels>, // object label, representing tree node
    cur_id: usize,           // stack cur pointer
    fd: Option<File>,        // json file
    access_counter: u32,     // counter for load access operation
    fsize: u32,              // seed file size
    use_log: bool,           // flag indicating whether to use log
    stats: Stats,            // Statistical data for log
}

impl ObjectStack {
    pub fn new() -> Self {
        let mut objs = Vec::with_capacity(STACK_MAX);
        objs.push(ObjectLabels::new(false, 0)); //ROOT
        let use_log = match env::var("CHUNKFUZZER_LOG") {
            Ok(value) => {
                let mut ret = false;
                if value == "1" {
                    ret = true;
                }
                ret
            }
            Err(_) => false,
        };
        let stats = Stats::new();
        Self {
            objs,
            cur_id: 0,
            // file_name: String::new(),
            fd: None,
            fsize: 0,
            access_counter: 1,
            use_log,
            stats,
        }
    }

    #[inline(always)]
    pub fn new_obj(&mut self, is_loop: bool, hash: u32) {
        let len = self.objs.len();
        if len < STACK_MAX {
            self.objs.push(ObjectLabels::new(is_loop, hash));
            self.cur_id += 1;
            if is_loop {
                self.stats.num_loop += 1;
            } else {
                self.stats.num_func += 1;
            }
            return;
        } else {
            panic!("[ERR]: more than {} objs.. #[ERR]", STACK_MAX);
        }
    }

    pub fn get_num_objs(&self) -> usize {
        self.objs.len()
    }

    pub fn get_top_index(&self) -> usize {
        return self.get_num_objs() - 1;
    }

    // SegTag -> TaintTag ,minimize
    pub fn seg_tag_2_taint_tag(&mut self, lb: u64, list: &mut Vec<TagSeg>) -> Vec<TaintSeg> {
        list.sort_by(|a, b| match a.begin.cmp(&b.begin) {
            Ordering::Equal => b.end.cmp(&a.end),
            other => other,
        });
        let mut cur_begin = 0;
        let mut cur_end = 0;
        let mut new_list = vec![];
        for i in list {
            //new tag
            if cur_begin == cur_end {
                cur_begin = i.begin;
                cur_end = i.end;
            } else {
                // push current tag into new_list
                if i.begin > cur_end {
                    new_list.push(TaintSeg {
                        lb,
                        begin: cur_begin,
                        end: cur_end,
                        son: None,
                        cntr: self.access_counter,
                    });
                    cur_begin = i.begin;
                    cur_end = i.end;
                    self.access_counter += 1;
                } else {
                    cur_end = max(i.end, cur_end);
                }
            }
        }
        if cur_begin != cur_end {
            new_list.push(TaintSeg {
                lb,
                begin: cur_begin,
                end: cur_end,
                son: None,
                cntr: self.access_counter,
            });
            self.access_counter += 1;
        }
        new_list
    }

    pub fn insert_node(ancestor: &mut TaintSeg, node: TaintSeg) {
        if let Some(ref mut son) = ancestor.son {
            let son_len = son.len();
            for i in 0..son_len {
                match loop_handlers::ObjectStack::seg_relation(&son[i], &node) {
                    SegRelation::Father => {
                        loop_handlers::ObjectStack::insert_node(&mut son[i], node);
                        return;
                    }
                    SegRelation::Same => {
                        son[i].lb = min(son[i].lb, node.lb);
                        if let Some(node_son) = node.son {
                            for son_i in node_son {
                                loop_handlers::ObjectStack::insert_node(&mut son[i], son_i);
                            }
                        }
                        return;
                    }
                    _ => {}
                }
            }
            let mut overlap_start = usize::MAX;
            let mut overlap_end = 0;
            for i in 0..son_len {
                match loop_handlers::ObjectStack::seg_relation(&son[i], &node) {
                    SegRelation::Son | SegRelation::RightOverlap | SegRelation::LeftOverlap => {
                        overlap_start = min(overlap_start, i);
                        overlap_end = max(overlap_end, i);
                    }
                    _ => {}
                }
            }
            if overlap_start == usize::MAX && overlap_end == 0 {
                son.push(node);
                son.sort_by(|a, b| match a.begin.cmp(&b.begin) {
                    Ordering::Equal => b.end.cmp(&a.end),
                    other => other,
                });
            } else {
                let overlap_length = overlap_end - overlap_start + 1;
                let mut overlap_vec = vec![];
                for _i in 0..overlap_length {
                    overlap_vec.push(son.remove(overlap_start));
                }
                overlap_vec.push(node);
                loop_handlers::ObjectStack::construct_tree(&mut overlap_vec);
                son.append(&mut overlap_vec);
                son.sort_by(|a, b| match a.begin.cmp(&b.begin) {
                    Ordering::Equal => b.end.cmp(&a.end),
                    other => other,
                });
            }
            return;
        } else {
            ancestor.son = Some(vec![node]);
        }
    }

    // (TS)a is the subject, for example, return value "Father" means (TS)a is (TS)b's father
    pub fn seg_relation(a: &TaintSeg, b: &TaintSeg) -> SegRelation {
        if a.begin == b.begin && a.end == b.end {
            SegRelation::Same
        } else if a.begin <= b.begin && a.end >= b.end {
            SegRelation::Father
        } else if a.begin >= b.begin && a.end <= b.end {
            SegRelation::Son
        } else if a.begin == b.end {
            SegRelation::LeftConnect
        } else if a.end == b.begin {
            SegRelation::RightConnect
        } else if a.begin > b.begin && a.begin < b.end {
            SegRelation::LeftOverlap
        } else if a.end > b.begin && a.end < b.end {
            SegRelation::RightOverlap
        } else {
            SegRelation::Disjoint
        }
    }

    pub fn erase_lb_wrapper(list: &Vec<u64>) {
        let mut lcl = LC.lock().unwrap();
        if let Some(ref mut lc) = *lcl {
            for i in list {
                lc.erase_lb(*i);
            }
        }
    }

    pub fn handle_overlap(list: &mut Vec<TaintSeg>) {
        if list.len() <= 1 {
            return;
        }
        if cfg!(debug_assertions) {
            eprintln!("[DEBUG] Before handle overlap list:");
            for i in 0..list.len() {
                eprintln!(
                    "lb: {:016X}, begin: {}, end:{}, son_is_none: {}",
                    list[i].lb,
                    list[i].begin,
                    list[i].end,
                    list[i].son.is_none()
                );
            }
        }
        // extract all non-leaf node and fake node into retain list
        let mut retain_list = vec![];
        for i in 0..list.len() {
            if list[i].cntr == u32::MAX {
                retain_list.push(list[i].clone());
            } else if list[i].son.is_some() {
                retain_list.push(list[i].clone());
            };
        }

        // remove node in retain list from list
        for i in 0..retain_list.len() {
            if let Some(index) = list.iter().position(|x| *x == retain_list[i]) {
                list.remove(index);
            };
        }

        if list.len() <= 1 {
            list.append(&mut retain_list);
            return;
        }

        let mut overlap_start = usize::MAX;
        let mut overlap_end = usize::MAX;
        let mut erase_lbs = vec![];
        list.sort_by(|a, b| match a.begin.cmp(&b.begin) {
            Ordering::Equal => b.end.cmp(&a.end),
            other => other,
        });
        for i in 0..list.len() - 1 {
            match loop_handlers::ObjectStack::seg_relation(&list[i], &list[i + 1]) {
                SegRelation::RightOverlap => {
                    if overlap_start == usize::MAX {
                        overlap_start = i;
                    }
                    overlap_end = i + 1;
                }
                _ => {
                    retain_list.push(list[i].clone());
                    if overlap_start != usize::MAX && overlap_end != usize::MAX {
                        if list[overlap_start].cntr > list[overlap_end].cntr {
                            retain_list.push(list[overlap_start].clone());
                            for i in overlap_start + 1..overlap_end + 1 {
                                erase_lbs.push(list[i].lb);
                            }
                        } else {
                            retain_list.push(list[overlap_end].clone());
                            for i in overlap_start..overlap_end {
                                erase_lbs.push(list[i].lb);
                            }
                        }
                        overlap_start = usize::MAX;
                        overlap_end = usize::MAX;
                    }
                }
            };
        }

        if overlap_start == usize::MAX && overlap_end == usize::MAX {
            retain_list.push(list[list.len() - 1].clone());
        } else {
            if list[overlap_start].cntr > list[overlap_end].cntr {
                retain_list.push(list[overlap_start].clone());
                for i in overlap_start + 1..overlap_end + 1 {
                    erase_lbs.push(list[i].lb);
                }
            } else {
                retain_list.push(list[overlap_end].clone());
                for i in overlap_start..overlap_end {
                    erase_lbs.push(list[i].lb);
                }
            }
        }

        loop_handlers::ObjectStack::erase_lb_wrapper(&erase_lbs);
        list.clear();
        list.append(&mut retain_list);

        if cfg!(debug_assertions) {
            eprintln!("[DEBUG] After handle overlap list:");
            for i in 0..list.len() {
                eprintln!(
                    "lb: {:016X}, begin: {}, end:{}, son_is_none: {}",
                    list[i].lb,
                    list[i].begin,
                    list[i].end,
                    list[i].son.is_none()
                );
            }
        }
    }

    pub fn remove_son(list: &mut Vec<TaintSeg>, overlap_begin: u32, overlap_end: u32) {
        let mut remove_list = vec![];
        for i in 0..list.len() - 1 {
            if list[i].begin >= overlap_begin && list[i].end <= overlap_end {
                remove_list.push(list[i].clone());
            }
        }

        for i in 0..remove_list.len() {
            if let Some(index) = list.iter().position(|x| *x == remove_list[i]) {
                list.remove(index);
            }
        }
    }

    pub fn construct_tree(mut list: &mut Vec<TaintSeg>) {
        loop_handlers::ObjectStack::handle_overlap(&mut list);
        if list.len() <= 1 {
            return;
        }
        list.sort_by(|a, b| match a.begin.cmp(&b.begin) {
            Ordering::Equal => b.end.cmp(&a.end),
            other => other,
        });

        let mut new_list = vec![];
        let none_ts = TaintSeg {
            lb: 0,
            begin: 0,
            end: 0,
            son: Some(vec![]),
            cntr: u32::MAX,
        };
        let mut cur_ts = none_ts.clone();
        for i in 0..list.len() {
            if cur_ts == none_ts {
                cur_ts = list[i].clone();
            } else {
                match loop_handlers::ObjectStack::seg_relation(&cur_ts, &list[i]) {
                    SegRelation::Same => {
                        cur_ts.lb = min(cur_ts.lb, list[i].lb);
                        if !list[i].son.is_none() {
                            let tmp = list[i].clone().son.unwrap();
                            for son_i in tmp {
                                loop_handlers::ObjectStack::insert_node(&mut cur_ts, son_i);
                            }
                        }
                    }
                    SegRelation::Father => {
                        loop_handlers::ObjectStack::insert_node(&mut cur_ts, list[i].clone())
                    }
                    SegRelation::Son => {
                        let prev_ts = cur_ts;
                        cur_ts = list[i].clone();
                        loop_handlers::ObjectStack::insert_node(&mut cur_ts, prev_ts);
                    }
                    SegRelation::RightConnect
                    | SegRelation::RightOverlap
                    | SegRelation::Disjoint => {
                        let tmp_field = Offset {
                            begin: 0,
                            end: 0,
                            size: 0,
                        };
                        if loop_handlers::ObjectStack::access_check(cur_ts.lb as u64, tmp_field)
                            != 0
                        {
                            let prev_ts = cur_ts.clone();
                            cur_ts = none_ts.clone();
                            cur_ts.begin = prev_ts.begin;
                            cur_ts.end = list[i].end;
                            if let Some(ref mut son) = cur_ts.son {
                                son.push(prev_ts);
                                son.push(list[i].clone());
                            } else {
                                cur_ts.son = Some(vec![prev_ts, list[i].clone()]);
                            }
                            cur_ts.lb = hash_combine(cur_ts.son.as_ref().unwrap());
                        //cur_ts 和 list[i]为同一层，同为son
                        } else {
                            //合并得到的lb
                            cur_ts.end = list[i].end;
                            if let Some(ref mut son) = cur_ts.son {
                                son.push(list[i].clone());
                                cur_ts.lb = hash_combine(&son);
                            }
                        }
                    }
                    SegRelation::RightOverlap => {
                        new_list.push(cur_ts);
                        cur_ts = list[i].clone();

                        /*
                        if loop_handlers::ObjectStack::access_check(cur_ts.lb as u64, 0) == 0 {
                            // lb comes from hash_combine
                            cur_ts.end = list[i].end;
                            loop_handlers::ObjectStack::insert_node(&mut cur_ts, list[i].clone());
                            cur_ts.lb = hash_combine(cur_ts.son.as_ref().unwrap());
                        }
                        else if loop_handlers::ObjectStack::access_check(list[i].lb as u64, 0) == 0 {
                            let prev_ts = cur_ts.clone();
                            cur_ts = list[i].clone();
                            cur_ts.begin = prev_ts.begin;
                            loop_handlers::ObjectStack::insert_node(&mut cur_ts, prev_ts);
                            cur_ts.lb = hash_combine(cur_ts.son.as_ref().unwrap());
                        }
                        else if cur_ts.son.is_none() || list[i].son.is_none() {
                            eprintln!("RightOverlap son is none");
                            //the funtion handle_overlap has filterd out this situation
                            // println!("RightOverlap two none: cur_ts: {{lb: {:016X}, begin: {}, end:{}}}, list[i]: {{lb: {:016X}, begin: {}, end:{}}}", cur_ts.lb, cur_ts.begin, cur_ts.end, list[i].lb, list[i].begin, list[i].end);
                            // println!("please check function: handle_overlap");
                        }
                        else {
                            eprintln!("RightOverlap else");
                            let overlap_begin = list[i].begin;
                            let overlap_end = cur_ts.end;
                            eprintln!("overlap range begin: {}, end: {}", overlap_begin, overlap_end);

                            let mut left_son_counter = 0;
                            let mut queue: Vec<TaintSeg> = vec![];
                            // eprintln!("left queue:");
                            queue.push(cur_ts.clone());
                            while queue.len() != 0 {
                                if let Some(top) = queue.pop() {
                                    // eprintln!("top {:?}", top);
                                    if let Some(son) = top.son {
                                        for i in son {
                                            if i.begin >= overlap_begin && i.end <= overlap_end {
                                                if i.son.is_none() {
                                                    left_son_counter += 1;
                                                }
                                                queue.push(i.clone());
                                            } else if i.end > overlap_begin && i.end <= overlap_end {
                                                queue.push(i.clone());
                                            }
                                        }
                                    }
                                }
                            }

                            let mut right_son_counter = 0;
                            // eprintln!("right queue:");
                            queue.clear();
                            queue.push(list[i].clone());
                            while queue.len() != 0 {
                                if let Some(top) = queue.pop() {
                                    // eprintln!("top {:?}", top);
                                    if let Some(son) = top.son {
                                        for i in son {
                                            if i.begin <= overlap_begin && i.end >= overlap_end {
                                                if i.son.is_none() {
                                                    right_son_counter += 1;
                                                }
                                                queue.push(i.clone());
                                            } else if i.begin >= overlap_begin && i.begin < overlap_end {
                                                queue.push(i.clone());
                                            }
                                        }
                                    }
                                }
                            }

                            eprintln!("left: {}, right: {}", left_son_counter, right_son_counter);

                            let mut queue: Vec<&mut TaintSeg> = vec![];
                            let mut prev_ts = cur_ts.clone();
                            cur_ts = none_ts.clone();
                            cur_ts.begin = prev_ts.begin;
                            cur_ts.end = list[i].end;

                            // remove latter node left overlap node
                            if left_son_counter > right_son_counter {
                                list[i].begin = overlap_end;
                                queue.push(&mut list[i]);
                                while !queue.is_empty() {
                                    let top = queue.pop().unwrap();
                                    if let Some(ref mut son) = top.son {
                                        loop_handlers::ObjectStack::remove_son(son, overlap_begin, overlap_end);
                                        for i in son.iter_mut() {
                                            if i.begin < overlap_end && i.end > overlap_end {
                                                i.begin = overlap_end;
                                                queue.push(i);
                                            }
                                        }
                                    }
                                }

                            } else {
                                prev_ts.end = overlap_begin;
                                queue.push(&mut prev_ts);
                                while !queue.is_empty() {
                                    let top = queue.pop().unwrap();
                                    if let Some(ref mut son) = top.son {
                                        loop_handlers::ObjectStack::remove_son(son, overlap_begin, overlap_end);
                                        for i in son.iter_mut() {
                                            if i.begin < overlap_begin && i.end > overlap_begin {
                                                i.end = overlap_begin;
                                                queue.push(i);
                                            }
                                        }
                                    }
                                }

                            }

                            // eprintln!("{:?}", prev_ts);
                            // eprintln!("{:?}", list[i]);
                            cur_ts.son = Some(vec![prev_ts, list[i].clone()]);
                            cur_ts.lb = hash_combine(cur_ts.son.as_ref().unwrap());
                            // eprintln!("{:?}", cur_ts);

                            // println!("RightOverlap else: cur_ts: {{lb: {:016X}, begin: {}, end:{}}}, list[i]: {{lb: {:016X}, begin: {}, end:{}}}", cur_ts.lb, cur_ts.begin, cur_ts.end, list[i].lb, list[i].begin, list[i].end);
                            // println!("please check function: handle_overlap");
                        }
                        */
                    }
                    // SegRelation::Disjoint => {
                    //     eprintln!("Disjoint: cur_ts: {{lb: {:016X}, begin: {}, end: {}, son_is_none: {}}}, list[i]: {{lb: {:016X}, begin: {}, end: {}, son_is_none: {}}}", cur_ts.lb, cur_ts.begin, cur_ts.end, cur_ts.son.is_none(), list[i].lb, list[i].begin, list[i].end, list[i].son.is_none());
                    //     new_list.push(cur_ts);
                    //     cur_ts = list[i].clone();
                    // },
                    _ => {}
                }
            }
        }
        if cur_ts != none_ts {
            let lb_filed = Offset::new(cur_ts.begin, cur_ts.end, cur_ts.end - cur_ts.begin);
            loop_handlers::ObjectStack::access_check(cur_ts.lb, lb_filed);
            new_list.push(cur_ts);
        }
        list.clear();
        list.append(&mut new_list);
        // loop_handlers::ObjectStack::access_check(list[0].lb, list[0].end - list[0].begin);
    }

    // if size == 0 ,search lb in LC, return 0 if not found
    // if size != 0, save lb in LC, always return 0
    pub fn access_check(lb: u64, filed: Offset) -> u32 {
        let mut lcl = LC.lock().unwrap();
        if let Some(ref mut lc) = *lcl {
            lc.save_tag(lb, filed)
        } else {
            0
        }
    }

    pub fn maybe_length(&mut self, lb: u32) {
        *self.objs[self.cur_id]
            .length_candidates
            .entry(lb)
            .or_insert(0) += 1;
    }

    pub fn get_load_label(&mut self, lb: u32) -> u32 {
        let saved = loop_handlers::ObjectStack::access_check(lb as u64, Offset::new(0, 0, 0));
        if saved != 0 {
            if cfg!(debug_assertions) {
                eprintln!("[DEBUG] Meet saved load label");
            }
            return saved;
        }
        let mut set_list = tag_set_wrap::tag_set_find(lb as usize);
        let mut list = self.seg_tag_2_taint_tag(lb as u64, &mut set_list);

        if list.len() > 1 {
            // if the label number > 1, it means that there are multi byte of input with constraint
            let mut lcl = LC.lock().unwrap();
            if let Some(ref mut lc) = *lcl {
                lc.save_linear_constraint(lb)
            }
            return 0;
        }
        if list.len() != 0 {
            if cfg!(debug_assertions) {
                eprintln!("[DEBUG]Load: lb {}, {:?}", lb, list);
            }
            self.stats.num_load += 1;
            let size = list[0].end - list[0].begin;
            let lb_filed = Offset::new(list[0].begin, list[0].end, size);
            self.insert_labels(&mut list);
            loop_handlers::ObjectStack::access_check(lb as u64, lb_filed);
            return size;
        }
        return 0;
    }

    /**
     *  insert taint label in list into obj stack cur func or loop
     */
    pub fn insert_labels(&mut self, list: &mut Vec<TaintSeg>) {
        if self.objs[self.cur_id].is_loop {
            if self.objs[self.cur_id].cur_iter.is_none() {
                panic!("[ERR]: Loop object doesn't have cur_iter");
            } else {
                let tmp_iter = self.objs[self.cur_id].cur_iter.as_mut().unwrap();
                for i in list.clone() {
                    if tmp_iter.contains(&i) {
                        continue;
                    } else {
                        tmp_iter.push(i);
                    }
                }
            }
        } else {
            for i in list.clone() {
                if self.objs[self.cur_id].sum.contains(&i) {
                    continue;
                } else {
                    self.objs[self.cur_id].sum.push(i);
                }
            }
        }
    }

    pub fn insert_iter_into_sum(&mut self) {
        if self.objs[self.cur_id].cur_iter.is_none() {
            panic!("insert_iter_into_sum but cur_iter is none!");
        }
        let tmp_iter = self.objs[self.cur_id].cur_iter.as_ref().unwrap().clone();
        // let index = self.objs[self.cur_id].cur_iter_num - 1;
        // self.objs[self.cur_id].sum.insert(index, tmp_iter.to_vec());
        for i in tmp_iter.clone() {
            if self.objs[self.cur_id].sum.contains(&i) {
                continue;
            } else {
                self.objs[self.cur_id].sum.push(i);
            }
        }
    }

    // sum <= sum + cur_iter, cur_iter.clear()
    pub fn dump_cur_iter(&mut self, loop_cnt: u32) {
        if self.objs[self.cur_id].is_loop {
            if self.objs[self.cur_id].cur_iter.is_some() {
                let mut tmp_iter = self.objs[self.cur_id].cur_iter.as_mut().unwrap();
                loop_handlers::ObjectStack::construct_tree(&mut tmp_iter);
                self.insert_iter_into_sum();
                self.objs[self.cur_id].cur_iter.as_mut().unwrap().clear();
                self.objs[self.cur_id].cur_iter_num = loop_cnt;
            } else {
                panic!("[ERR]: Loop with wrong structure!! #[ERR]");
            }
        } else {
            panic!("[ERR]: Function doesn't have iteration!! #[ERR]");
        }
    }

    //退出循环、函数返回后，将当前栈顶pop，minimize, 插入上一层
    //若hash不匹配说明栈不平衡，出错了
    pub fn pop_obj(&mut self, hash: u32) {
        let top = self.objs.pop();
        if top.is_some() {
            let top_obj = top.unwrap();

            if hash != 0 && top_obj.hash != hash {
                let mut jmp_func = 0;
                let len = self.objs.len();
                for i in 0..len {
                    if self.objs[i].hash == hash {
                        jmp_func = i;
                        break;
                    }
                }

                if jmp_func != 0 {
                    let mut cur_list = top_obj.sum;
                    loop_handlers::ObjectStack::construct_tree(&mut cur_list);
                    self.cur_id -= 1;
                    self.insert_labels(&mut cur_list);

                    while self.cur_id >= jmp_func {
                        let obj = self.objs.pop();
                        if obj.is_some() {
                            let real_obj = obj.unwrap();
                            let mut list = real_obj.sum;
                            loop_handlers::ObjectStack::construct_tree(&mut list);
                            self.cur_id -= 1;
                            self.insert_labels(&mut list);
                        }
                    }
                } else {
                    panic!("[ERR] :pop error! incorrect Hash {} #[ERR]", top_obj.hash);
                }
            } else {
                let mut list = top_obj.sum;
                loop_handlers::ObjectStack::construct_tree(&mut list);
                if list.len() == 1 {
                    for (key, value) in &top_obj.length_candidates {
                        
                        let tmp_field = Offset {
                            begin: 0,
                            end: 0,
                            size: 0,
                        };
                        let size = loop_handlers::ObjectStack::access_check(*key as u64, tmp_field);
                        if cfg!(debug_assertions) {
                            eprintln!("[DEBUG] length candidate: lb {}, {}", key, value);
                            eprintln!("[DEBUG] list {:?}", list);
                        }

                        if size != 0 && *value == top_obj.cur_iter_num {
                            if cfg!(debug_assertions) {
                                eprintln!("[DEBUG] length: lb {}, {:?}", key, list);
                            }
                            let cond = CondStmtBase {
                                op: 0,
                                size,
                                lb1: *key as u64,
                                lb2: list[0].lb,
                                field: ChunkField::Length,
                            };
                            let mut lcl = LC.lock().expect("Could not lock LC.");
                            if let Some(ref mut lc) = *lcl {
                                lc.save(cond);
                            }
                        }
                    }
                }
                self.cur_id -= 1;
                self.insert_labels(&mut list);
            }
        } else {
            panic!("[ERR] :STACK EMPTY! #[ERR]");
        }
    }

    pub fn output_format(
        s: &mut String,
        ttsg: &TaintSeg,
        depth: usize,
        is_last: bool,
        _father_begin: u32,
    ) {
        // let father_begin = 0;
        let blank = "  ".repeat(depth);
        let blank2 = "  ".repeat(depth + 1);
        let start = "start";
        let end = "end";
        // let field = "type";
        let str_son = "child";
        s.push_str(&format!("{}\"{:016X}\":\n", blank, ttsg.lb));
        s.push_str(&format!("{}{{\n", blank));
        //need check lb
        s.push_str(&format!("{}\"{}\": {},\n", blank2, start, ttsg.begin)); //    "start": 0,
        if ttsg.son.is_none() {
            s.push_str(&format!("{}\"{}\": {}\n", blank2, end, ttsg.end));
            if is_last {
                s.push_str(&format!("{}}}\n", blank));
            } else {
                s.push_str(&format!("{}}},\n", blank));
            }
            return;
        }
        s.push_str(&format!("{}\"{}\": {},\n", blank2, end, ttsg.end)); //    "end": 8,
        let ttsg_sons = ttsg.son.as_ref().unwrap();
        s.push_str(&format!("{}\"{}\": {{\n", blank2, str_son));
        let mut fake_seg = TaintSeg {
            lb: 0,
            begin: 0,
            end: 0,
            son: None,
            cntr: u32::MAX,
        };
        let mut rng = rand::thread_rng();
        for i in 0..ttsg_sons.len() {
            // /*
            if i == 0 {
                if ttsg_sons[0].begin != ttsg.begin {
                    fake_seg.lb = rng.gen_range(0..0x10000000) + 0x100000000;
                    fake_seg.begin = ttsg.begin;
                    fake_seg.end = ttsg_sons[0].begin;
                    loop_handlers::ObjectStack::output_format(
                        s,
                        &fake_seg.clone(),
                        depth + 1,
                        false,
                        ttsg.begin,
                    );
                }
            } else if ttsg_sons[i - 1].end < ttsg_sons[i].begin
                && ttsg_sons[i - 1].end != ttsg_sons[i].begin
            {
                fake_seg.lb = rng.gen_range(0..0x10000000) + 0x200000000;
                fake_seg.begin = ttsg_sons[i - 1].end;
                fake_seg.end = ttsg_sons[i].begin;
                loop_handlers::ObjectStack::output_format(
                    s,
                    &fake_seg.clone(),
                    depth + 1,
                    false,
                    ttsg.begin,
                );
            }
            // */
            if i == ttsg_sons.len() - 1 {
                // /*
                if ttsg.end != ttsg_sons[i].end {
                    fake_seg.lb = rng.gen_range(0..0x10000000) + 0x30000000;
                    fake_seg.begin = ttsg_sons[ttsg_sons.len() - 1].end;
                    fake_seg.end = ttsg.end;
                    loop_handlers::ObjectStack::output_format(
                        s,
                        &ttsg_sons[i],
                        depth + 1,
                        false,
                        ttsg.begin,
                    );
                    loop_handlers::ObjectStack::output_format(
                        s,
                        &fake_seg.clone(),
                        depth + 1,
                        true,
                        ttsg.begin,
                    );
                } else {
                    // */
                    loop_handlers::ObjectStack::output_format(
                        s,
                        &ttsg_sons[i],
                        depth + 1,
                        true,
                        ttsg.begin,
                    );
                }
            } else {
                loop_handlers::ObjectStack::output_format(
                    s,
                    &ttsg_sons[i],
                    depth + 1,
                    false,
                    ttsg.begin,
                );
            }

            // s.push_str(&format!("{}}},\n",blank));
        }
        s.push_str(&format!("{}}}\n", blank2));
        if is_last {
            s.push_str(&format!("{}}}\n", blank));
        } else {
            s.push_str(&format!("{}}},\n", blank));
        }
    }

    pub fn set_input_file_name(&mut self, json_name: PathBuf) {
        if self.fd.is_some() {
            return;
        }
        let json_file = match File::create(json_name) {
            Ok(a) => a,
            Err(e) => {
                panic!("FATAL: Could not create json file: {:?}", e);
            }
        };
        self.fd = Some(json_file);
    }

    pub fn set_input_file_size(&mut self, fsize: u32) {
        self.fsize = fsize;
    }

    pub fn set_log_file_name(&mut self, log_path: PathBuf) {
        self.stats.create_log_file(log_path);
    }

    pub fn count_cmp_num(&mut self) {
        self.stats.num_cmp += 1;
    }

    pub fn count_switch_num(&mut self) {
        self.stats.num_switch += 1;
    }

    pub fn fini(&mut self) {
        while self.cur_id != 0 {
            if self.objs[self.cur_id].is_loop {
                self.dump_cur_iter(0);
            }
            self.pop_obj(0);
        }
        let mut s = String::new();
        loop_handlers::ObjectStack::construct_tree(&mut self.objs[self.cur_id].sum);

        if self.objs[self.cur_id].sum.len() == 1 {
            let sum_clone = self.objs[self.cur_id].sum.clone();
            let end = sum_clone[0].end;
            if end < self.fsize {
                self.stats.is_complete = false;
                let remain_sum = TaintSeg {
                    lb: rand::thread_rng().gen_range(0..0x10000000) + 0x300000000,
                    begin: end,
                    end: self.fsize,
                    son: None,
                    cntr: self.access_counter,
                };
                self.objs[self.cur_id].sum.push(remain_sum);
            }
        } else if self.objs[self.cur_id].sum.len() > 1 {
            let sum_clone = self.objs[self.cur_id].sum.clone();
            let end = sum_clone[sum_clone.len() - 1].end;
            if end < self.fsize {
                self.stats.is_complete = false;
                let remain_sum = TaintSeg {
                    lb: rand::thread_rng().gen_range(0..0x10000000) + 0x300000000,
                    begin: end,
                    end: self.fsize,
                    son: None,
                    cntr: self.access_counter,
                };
                self.objs[self.cur_id].sum.push(remain_sum);
            }
        }

        if self.objs[self.cur_id].sum.len() > 1 {
            let sum_clone = self.objs[self.cur_id].sum.clone();
            let sum_len = sum_clone.len();
            let new_sum = TaintSeg {
                lb: rand::thread_rng().gen_range(0..0x10000000) + 0x400000000,
                begin: sum_clone[0].begin,
                end: sum_clone[sum_len - 1].end,
                son: Some(sum_clone),
                cntr: self.access_counter,
            };
            self.objs[self.cur_id].sum = vec![new_sum];
        }

        s.push_str(&format!("{{\n"));
        for i in &self.objs[self.cur_id].sum {
            if &i == &self.objs[self.cur_id].sum.last().unwrap() {
                loop_handlers::ObjectStack::output_format(&mut s, &i, 0, true, 0);
            } else {
                loop_handlers::ObjectStack::output_format(&mut s, &i, 0, true, 0);
            }
        }
        s.push_str(&format!("}}\n"));

        if self.fd.is_some() {
            self.fd
                .as_ref()
                .unwrap()
                .write_all(s.as_bytes())
                .expect("Unable to write file");
        } else {
            let timestamp = {
                let start = SystemTime::now();
                let since_the_epoch = start
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards");
                let ms = since_the_epoch.as_secs() as i64 * 1000i64
                    + (since_the_epoch.subsec_nanos() as f64 / 1_000_000.0) as i64;
                ms
            };
            let mut json_name = "logfile_".to_string();
            json_name += &timestamp.to_string();
            json_name += &".json".to_string();
            json_name = ".isi.json".to_string();
            let mut json_file = File::create(json_name).expect("Unable to create log file");
            json_file
                .write_all(s.as_bytes())
                .expect("Unable to write file");
        }

        if self.use_log {
            self.stats.output_logs();
        }
    }
}

impl Drop for ObjectStack {
    fn drop(&mut self) {
        self.fini();
    }
}

// print_type_of(&xxx);
// fn print_type_of<T>(_: &T) {
//     println!("{}", std::any::type_name::<T>())
// }

// Compare label
#[derive(Debug, Clone)]
pub struct CompareLabel {
    hash: u32,
}

impl CompareLabel {
    pub fn new(hash: u32) -> Self {
        Self { hash }
    }
}

#[derive(Debug)]
pub struct CmpLabelsStack {
    labels: Vec<CompareLabel>,
    cur_id: usize,
}

impl CmpLabelsStack {
    pub fn new() -> Self {
        let mut labels = Vec::with_capacity(STACK_MAX);
        labels.push(CompareLabel::new(0));
        Self { labels, cur_id: 0 }
    }

    // function: push new label for stack
    #[inline(always)]
    pub fn new_label(&mut self, hash: u32) {
        let len = self.labels.len();
        if len < STACK_MAX {
            self.labels.push(CompareLabel::new(hash));
            self.cur_id += 1;
            return;
        } else {
            panic!("[ERR]: more than {} objs.. #[ERR]", STACK_MAX);
        }
    }

    pub fn pop_label(&mut self, hash: u32) {
        let top = self.labels.pop();
        if top.is_some() {
            let top_label = top.unwrap();
            if hash != 0 && top_label.hash != hash {
                panic!(
                    "[ERR] :pop incorrect Hash {}, stack current hash {} #[ERR]",
                    hash, top_label.hash
                );
            }

            self.cur_id -= 1;
        } else {
            panic!("[ERR] :STACK EMPTY! #[ERR]");
        }
    }
}

pub fn hash_combine(ts: &Vec<TaintSeg>) -> u64 {
    let mut seed = 0;
    if ts.len() == 1 {
        seed = ts[0].lb
    } else {
        for b in ts {
            seed ^= b.lb ^ 0x9E3779B97F4A7C15u64 ^ (seed << 6) ^ (seed >> 2);
        }
    }
    seed
}
