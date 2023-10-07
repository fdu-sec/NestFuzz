// use bincode::{deserialize_from, serialize_into};
// use std::{collections::HashMap, env, fs::File, io::prelude::*, path::Path};
use std::{
    fs::File, 
    io::prelude::*,
    path::PathBuf,
    time::*,
};

// use crate::{len_label, tag_set_wrap};
// use angora_common::{cond_stmt_base::*, config, defs, log_data::LogData};
use angora_common::{cond_stmt_base::*, log_data::*};

#[derive(Debug)]
pub struct Logger {
    data: LogData,
    fd: Option<File>,
    // order_map: HashMap<(u32, u32), u32>,
}

impl Logger {
    pub fn new() -> Self {
        Self {
            data: LogData::new(),
            fd: None,
            // order_map: HashMap::new(),
        }
    }

    pub fn find_tag_lb(&self, lb: u64) -> bool {
        self.data.tags.contains_key(&lb)
    }

    pub fn save_tag(&mut self, lb: u64, filed: Offset) -> u32 {
        if lb > 0 {
            if self.data.tags.contains_key(&lb) {
                if let Some(ret) = self.data.tags.get(&lb) {
                    ret.size
                } 
                else {
                    0
                }
            }
            else {
                if filed.size != 0 {
                    //save lb
                    self.data.tags.insert(lb, filed);
                }
                0
            }
        }
        else {
            0
        }
    }

    pub fn save_linear_constraint(&mut self, lb: u32) {
        if !self.data.linear_constraint.contains(&lb) {
            self.data.linear_constraint.push(lb)
        }
    }

    pub fn save_enums(&mut self, lb: u64, bytes: Vec<u8>) {
        if lb > 0 {
            // let tag = tag_set_wrap::tag_set_find(lb as usize);
            if self.data.enums.contains_key(&lb) {
                let v = self.data.enums.get_mut(&lb).unwrap();
                if !v.contains(&bytes) {
                    v.push(bytes);
                }
            }
            else {
                self.data.enums.insert(lb, vec![bytes]);
            }
            
        }
    }

    pub fn erase_lb(&mut self, lb: u64) {
        let _ = &self.data.enums.remove(&lb);
        let _ = &self.data.tags.remove(&lb);
        if let Some(index) = self.data.cond_list.iter().position(|x| x.lb1 == lb || x.lb2 == lb) {
            self.data.cond_list.remove(index);
        };
    }
    /*
    // like the fn in fparser.rs
    pub fn get_order(&mut self, cond: &mut CondStmtBase) -> u32 {
        let order_key = (cond.cmpid, cond.context);
        let order = self.order_map.entry(order_key).or_insert(0);
        if cond.order == 0 {
            // first case in switch
            let order_inc = *order + 1;
            *order = order_inc;
        }
        cond.order += *order;
        *order
    }
    */

    pub fn save(&mut self, cond: CondStmtBase) {
        if cond.lb1 == 0 && cond.lb2 == 0 {
            return;
        }

        // self.save_tag(cond.lb1, cond.size);
        // self.save_tag(cond.lb2, cond.size);

        if !self.data.cond_list.contains(&cond) {
            self.data.cond_list.push(cond);
        }
    }

    pub fn enums_clean(&mut self){
        let mut del = vec![];

        for (key, value) in &self.data.enums {
            if value.len() == 1 {
                // check valid byte
                let v_len = value[0].len();
                let mut invalid_byte = 0;
                for i in 0 .. v_len {
                    if value[0][i] == 0 {
                        invalid_byte += 1;
                    }
                    else {
                        invalid_byte = 0;
                    }
                }
                if v_len - invalid_byte == 1 {
                    let target = key.clone();
                    del.push(target);
                }
            }
        }
        
        for key in del {
            let _ = &self.data.enums.remove(&key);
        }
        let enum_clone = self.data.enums.clone();
        self.data.cond_list.retain(|&item| enum_clone.contains_key(&item.lb1) == false);
    }
    pub fn set_input_file_name(
        &mut self,
        track_name: PathBuf,
    ){
        if self.fd.is_some() {
            return;
        }
        // println!("track_name: {:?}", track_name);
        let track_file = match File::create(track_name) {
            Ok(a) => a,
            Err(e) => {
                panic!("FATAL: Could not create track file: {:?}", e);
            }
        };
        self.fd = Some(track_file);
    }

    pub fn output_logs(&self, s: &mut String) {
        // for (k, v) in &self.data.tags {
        //     eprintln!("lb: {}, begin: {}, end: {}, size: {}", k, v.begin, v.end, v.size);
        // }
        // for cond in &self.data.cond_list {
        //     eprintln!("{:?}", cond);
        // }

        // output：(lb1，lb2, field, remarks)
        // remarks: Enum's candidate; Constraints's op; offset's absolute/relatively
        let mut count = 0;
        let start = "start";
        let end = "end";
        let ty = "type";
        let blank = "  ".repeat(1);
        let blank2 = "  ".repeat(2);
        let blank3 = "  ".repeat(3);
        s.push_str(&format!("{{\n"));
        for (key, value) in &self.data.enums {
            if let Some(field) = self.data.tags.get(key) {
                count += 1;
                s.push_str(&format!("{}\"{:016X}\": {{\n", blank, key));
                s.push_str(&format!("{}\"{}\": {},\n", blank2, start, field.begin));
                s.push_str(&format!("{}\"{}\": {},\n", blank2, end, field.end));
                s.push_str(&format!("{}\"{}\": \"enum\",\n", blank2, ty));
                s.push_str(&format!("{}\"num\": {},\n", blank2, value.len()));

                s.push_str(&format!("{}\"candidates\": {{\n", blank2));
                for i in 0..value.len() {
                    s.push_str(&format!("{}\"{}\": \"", blank3, i));
                    for cand in value[i].clone() {
                        s.push_str(&format!("{:02X}, ", cand));
                    }
                    s.pop();
                    s.pop();
                    s.push_str(&format!("\",\n"));
                }
                s.pop();
                s.pop();
                s.push('\n');
                s.push_str(&format!("{}}}\n", blank2));
                s.push_str(&format!("{}}},\n", blank));
    
            }
            // else {
            //     panic!("can not find lb {:016X} offset!", key);
            // }
        }

        for i in &self.data.cond_list {
            if i.field == ChunkField::Length {
                if let Some(field1) = self.data.tags.get(&i.lb1) {
                    if let Some(field2) = self.data.tags.get(&i.lb2) {
                        count += 1;
                        s.push_str(&format!("{}\"{:016X}\": {{\n", blank, i.lb1));
                        s.push_str(&format!("{}\"{}\": {},\n", blank2, start, field1.begin));
                        s.push_str(&format!("{}\"{}\": {},\n", blank2, end, field1.end));
                        s.push_str(&format!("{}\"{}\": \"length\",\n", blank2, ty));  
                        
                        s.push_str(&format!("{}\"{:016X}\": {{\n", blank2, i.lb2));
                        s.push_str(&format!("{}\"{}\": {},\n", blank3, start, field2.begin));
                        s.push_str(&format!("{}\"{}\": {}\n", blank3, end, field2.end));
                        s.push_str(&format!("{}}}\n", blank2));
                        s.push_str(&format!("{}}},\n", blank));
    
                    }
                }
            }

            if i.field == ChunkField::Offset {
                if let Some(field1) = self.data.tags.get(&i.lb1) {
                    if let Some(field2) = self.data.tags.get(&i.lb2) {
                        count += 1;
                        s.push_str(&format!("{}\"{:016X}\": {{\n", blank, i.lb1));
                        s.push_str(&format!("{}\"{}\": {},\n", blank2, start, field1.begin));
                        s.push_str(&format!("{}\"{}\": {},\n", blank2, end, field1.end));
                        s.push_str(&format!("{}\"{}\": \"offset\",\n", blank2, ty));  
                        
                        s.push_str(&format!("{}\"{:016X}\": {{\n", blank2, i.lb2));
                        s.push_str(&format!("{}\"{}\": {},\n", blank3, start, field2.begin));
                        s.push_str(&format!("{}\"{}\": {}\n", blank3, end, field2.end));
                        s.push_str(&format!("{}}}\n", blank2));
                        s.push_str(&format!("{}}},\n", blank));
    
                    }
                }
            }

        }
        s.pop();
        s.pop();
        s.push('\n');
        s.push_str(&format!("}}"));
    }

    fn fini(&mut self) {

        self.enums_clean();
        let mut s = String::new();
            self.output_logs(&mut s); 
        if self.fd.is_some() {
            self.fd.as_ref().unwrap().write_all(s.as_bytes()).expect("Unable to write file");
        }
        else {
            let timestamp = {
                let start = SystemTime::now();
                let since_the_epoch = start
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards");
                let ms = since_the_epoch.as_secs() as i64 * 1000i64 + (since_the_epoch.subsec_nanos() as f64 / 1_000_000.0) as i64;
                ms
            };
            let mut track_name = "logfile_".to_string();
            track_name += &timestamp.to_string();
            track_name += &".track".to_string();
            track_name = ".isi.track".to_string();
            let mut track_file = File::create(track_name).expect("Unable to create log file");
            track_file.write_all(s.as_bytes()).expect("Unable to write file");
        }
    }
}

impl Drop for Logger {
    fn drop(&mut self) {
        self.fini();
    }
}
/*
pub fn get_log_data(path: &Path) -> io::Result<LogData> {
    let f = fs::File::open(path)?;
    if f.metadata().unwrap().len() == 0 {
        return Err(io::Error::new(io::ErrorKind::Other, "Could not find any interesting constraint!, Please make sure taint tracking works or running program correctly."));
    }
    let mut reader = io::BufReader::new(f);
    match deserialize_from::<&mut io::BufReader<fs::File>, LogData>(&mut reader) {
        Ok(v) => Ok(v),
        Err(_) => Err(io::Error::new(io::ErrorKind::Other, "bincode parse error!")),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
*/