// SPDX-License-Identifier: MIT OR Apache-2.0
//! Experimental unified cursor and bounded authenticated deferred queue.
use glaux_messenger::nostr::{Event,cursor::{Cursor,CursorStore}};
use glaux_messenger::error::Error;
use std::path::PathBuf;

pub(crate) struct DeferredItem {pub event_id:String,pub event_json:String,pub received_at:u64}
pub(crate) struct Deferred {store:CursorStore}
impl Deferred {
    pub fn from_store(store:CursorStore)->Self {Self{store}}
    #[cfg(test)] pub fn open(root:PathBuf,lock:PathBuf,key:[u8;32])->Result<Self,String> {
        std::fs::create_dir_all(&root).map_err(|e|e.to_string())?;
        let path=root.join("state.enc");let store=CursorStore::new(path.clone(),key,"test","test").map_err(|e|e.to_string())?.with_lock(lock);
        if !path.exists(){store.initialize(&Cursor::default()).map_err(|e|e.to_string())?;}
        Ok(Self{store})
    }
    pub fn save(&self,id:&str,json:&str,now:u64)->Result<(),String> {
        let event:Event=serde_json::from_str(json).map_err(|_|"invalid deferred event".to_string())?;
        if event.id!=id{return Err("invalid deferred event id".into());}
        self.store.update(|s|s.preserve(&event,now)).map_err(|e|e.to_string())
    }
    pub fn list(&self)->Result<Vec<DeferredItem>,String> {
        Ok(self.store.load().map_err(|e|e.to_string())?.deferred.into_iter().map(|i|DeferredItem{event_id:i.id,event_json:i.json,received_at:i.received_at}).collect())
    }
    pub fn process(&self,id:&str,handle:impl FnOnce(&DeferredItem)->Result<bool,String>)->Result<(),String> {
        self.store.update(|s| {
            let i=s.deferred.iter().position(|v|v.id==id).ok_or_else(||Error::Store("deferred record missing".into()))?;
            let item=&s.deferred[i];let item=DeferredItem{event_id:item.id.clone(),event_json:item.json.clone(),received_at:item.received_at};
            if handle(&item).map_err(Error::Store)? {s.deferred.remove(i);}Ok(())
        }).map_err(|e|e.to_string())
    }
    /// Replay one bounded snapshot under the same lock; persist at most once.
    pub fn process_all(&self,mut handle:impl FnMut(&DeferredItem)->Result<bool,String>)->Result<Vec<String>,String> {
        self.store.update(|s| {
            let mut errors=Vec::new();let mut i=0;
            while i<s.deferred.len() {
                let item=&s.deferred[i];let item=DeferredItem{event_id:item.id.clone(),event_json:item.json.clone(),received_at:item.received_at};
                match handle(&item) {Ok(true)=>{s.deferred.remove(i);},Ok(false)=>i+=1,Err(e)=>{errors.push(e);i+=1;}}
            } Ok(errors)
        }).map_err(|e|e.to_string())
    }
    pub fn delete(&self,id:&str)->Result<(),String> {self.process(id,|_|Ok(true))}
}
impl glaux_messenger::nostr::transport::DeferredNostrEvent for Deferred {
    fn preserve(&self,event:&Event,now:u64)->glaux_messenger::error::Result<()> {
        let json=serde_json::to_string(event).map_err(|_|Error::Store("deferred encoding".into()))?;
        self.save(&event.id,&json,now).map_err(Error::Store)
    }
}
