use std::{
    time::Instant,
    path::PathBuf,
    fs::File,
    io::Write,
};

#[derive(Debug)]
pub struct Stats {
    fd: Option<File>,

    start_time: Instant,

    pub num_load: u64,
    pub num_func: u64,
    pub num_loop: u64,
    pub num_cmp: u64,
    pub num_switch: u64,
    
    pub is_complete: bool,

}

impl Stats {
    
    pub fn new() -> Self {
        let start_time = Instant::now();
        Self {
            fd: None,
            start_time, 
            num_load: 0,
            num_func: 0, 
            num_loop: 0,
            num_cmp: 0,
            num_switch: 0,
            is_complete: true 
        }
    }

    pub fn output_logs(&mut self) {
        let mut msg = String::new();
        msg.push_str(&format!("duration {:?}\n",
            self.start_time.elapsed()));
        msg.push_str(
            &format!(
                "load: {}\nfunc: {}\nloop: {}\ncmp: {}\nswitch: {}\nis complete: {}\n",
                 self.num_load,
                 self.num_func,
                 self.num_loop,
                 self.num_cmp,
                 self.num_switch,
                 self.is_complete,
            ));
        
        if self.fd.is_some() {
            self.fd.as_ref().unwrap()
                .write_all(msg.as_bytes())
                .expect("Unable to write log file");
        }
    }

    pub fn create_log_file(&mut self, log_path: PathBuf) {
        //println!("log file name: {:?}", log_path);
        if self.fd.is_some() {
            return;
        }
        
        let log_file = match File::create(log_path) {
            Ok(a) => a,
            Err(e) => {
                panic!("FATAL: Could not create log file: {:?}", e);
            }
        };

        self.fd = Some(log_file);
    }


}