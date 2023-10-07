use serde_derive::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Eq, Ord, PartialOrd, Debug, Clone, Copy, Hash)]
#[repr(C)] 
pub struct TagSeg {
    pub sign: bool,
    pub begin: u32,
    pub end: u32,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Ord, PartialOrd, Debug, Clone, Hash)]
#[repr(C)] 
pub struct TaintSeg {
    pub lb: u64,
    pub begin: u32,
    pub end: u32,
    pub son: Option<Vec<TaintSeg>>,
    pub cntr: u32,
    //pub is_loop: bool,
}

#[derive(PartialEq, Eq, Ord, PartialOrd, Debug, Clone, Copy, Hash)]
pub enum SegRelation {
    Same,
    Son,
    Father,
    LeftConnect,
    RightConnect,
    LeftOverlap,
    RightOverlap,
    Disjoint,
}

/*
impl TaintSeg {
    pub fn new(

    ) {

    }

}
*/

// impl TagSeg {
//     pub fn slice_from<'a>(&self, v: &'a [u8]) -> &'a [u8] {
//         &v[(self.begin as usize)..(self.end as usize)]
//     }

//     pub fn slice_from_mut<'a>(&self, v: &'a mut [u8]) -> &'a mut [u8] {
//         &mut v[(self.begin as usize)..(self.end as usize)]
//     }
// }
