// SPDX-License-Identifier: MIT OR Apache-2.0
//! Experimental I2P transport. The endpoint stores only encrypted envelopes;
//! callers must verify/decrypt and persist them before acknowledging locally.
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::{Address, Envelope, FileMailbox, Transport};
use crate::envelope::{unix_now, POW_MIN_BITS};
use crate::error::{Error, Result};
use crate::i2p_binding::Binding;
use crate::i2p_sam::Session;

const MAGIC: &[u8; 4] = b"GS01";
const MAX_FRAME: usize = 128 * 1024;

fn err(message: &str) -> Error { Error::Store(message.into()) }

/// Stores a bounded, encrypted envelope for this profile and acknowledges only
/// after the local mailbox accepts it. This is not a proof of on-chain payment.
fn receive_one(mut socket: TcpStream, own: &Address, mailbox: &FileMailbox) -> Result<()> {
    socket.set_read_timeout(Some(Duration::from_secs(10))).map_err(|_| err("I2P receive timeout setup"))?;
    socket.set_write_timeout(Some(Duration::from_secs(10))).map_err(|_| err("I2P reply timeout setup"))?;
    let mut header=[0u8;8]; socket.read_exact(&mut header).map_err(|_| err("I2P invalid message header"))?;
    if &header[..4] != MAGIC {return Err(err("I2P unsupported message"))}
    let size=u32::from_be_bytes(header[4..].try_into().unwrap()) as usize;
    if size==0 || size>MAX_FRAME {return Err(err("I2P message size exceeded"))}
    let mut body=vec![0u8;size]; socket.read_exact(&mut body).map_err(|_| err("I2P truncated message"))?;
    let envelope:Envelope=serde_json::from_slice(&body).map_err(|_| err("I2P invalid envelope"))?;
    if envelope.recipient != own.to_string() {return Err(Error::WrongRecipient)}
    let now=unix_now();
    if envelope.ttl==0 || envelope.ttl>13*60*60 || envelope.created_at>now.saturating_add(300) || envelope.created_at.saturating_add(envelope.ttl)<=now {return Err(Error::Expired)}
    envelope.verify_pow(POW_MIN_BITS)?;
    mailbox.deliver(&envelope)?;
    socket.write_all(&[1]).map_err(|_| err("I2P reply failed"))?;
    Ok(())
}

/// Listener and storage exist only while the wallet's service is running.
pub struct I2pEndpoint {
    session: Arc<Session>, own: Address, mailbox: Arc<FileMailbox>,
    stop: Arc<AtomicBool>, worker: Option<JoinHandle<()>>,
}

impl I2pEndpoint {
    pub fn start(session: Session, own: Address, mailbox: FileMailbox) -> Result<Self> {
        Self::start_guarded(session, own, mailbox, None)
    }
    pub fn start_guarded(session: Session, own: Address, mailbox: FileMailbox, gate: Option<crate::channel_drain::ChannelDrain>) -> Result<Self> {
        let session=Arc::new(session); let mailbox=Arc::new(mailbox); let stop=Arc::new(AtomicBool::new(false));
        let s=session.clone(); let m=mailbox.clone(); let flag=stop.clone(); let address=own.clone();
        let worker=thread::Builder::new().name("glaux-i2p-listener".into()).spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                match s.accept_timeout(Duration::from_secs(20)) {
                    Ok((socket,_peer)) => {
                        let _permit = match &gate { Some(g) => match g.enter() { Some(p) => Some(p), None => { drop(socket); continue; } }, None => None };
                        let result=receive_one(socket,&address,&m);
                        #[cfg(test)] if let Err(e)=result { eprintln!("test I2P receiver: {e}"); }
                        #[cfg(not(test))] let _=result;
                    }
                    Err(e) => {
                        #[cfg(test)] if e.kind() != std::io::ErrorKind::TimedOut && e.kind() != std::io::ErrorKind::WouldBlock { eprintln!("test I2P accept: {:?}", e.kind()); }
                        #[cfg(not(test))] let _=e;
                        thread::sleep(Duration::from_millis(200));
                    },
                }
            }
        }).map_err(|_|err("I2P listener start failed"))?;
        Ok(Self { session, own, mailbox, stop, worker:Some(worker) })
    }
    /// Copies the already verified contacts; signatures and expiry are checked
    /// again on each send. The caller persists rollback protection separately.
    pub fn transport(&self, bindings: HashMap<String,Binding>) -> I2pTransport {
        I2pTransport { session:self.session.clone(), own:self.own.clone(), mailbox:self.mailbox.clone(), bindings }
    }
    pub fn stop(&mut self) { self.stop.store(true,Ordering::Relaxed); if let Some(w)=self.worker.take() {let _=w.join();} }
}
impl Drop for I2pEndpoint { fn drop(&mut self) { self.stop(); } }

#[derive(Clone)]
pub struct I2pTransport { session: Arc<Session>, own: Address, mailbox: Arc<FileMailbox>, bindings: HashMap<String,Binding> }
impl I2pTransport {
    pub fn with_bindings(&self, bindings: HashMap<String, Binding>) -> Self {
        Self { session:self.session.clone(), own:self.own.clone(), mailbox:self.mailbox.clone(), bindings }
    }
}
impl Transport for I2pTransport {
    fn fetch_signed_tagged(&self, recipient:&crate::Identity, now:u64, limit:usize)->Result<Vec<(Envelope, Option<String>)>> {
        self.fetch(recipient.address(),now,limit)?.into_iter().map(|e| {
            let digest=crate::ack::envelope_digest(&e)?;let token=format!("{}:{digest}",e.id);Ok((e,Some(token)))
        }).collect()
    }
    fn ack_signed(&self, recipient:&crate::Identity, tokens:&[String])->Result<usize> {
        if recipient.address()!=&self.own { return Err(Error::WrongRecipient); }
        self.mailbox.ack_exact(recipient.address(),tokens)
    }
    fn deliver(&self, envelope: &Envelope) -> Result<()> {
        let recipient=Address::parse(&envelope.recipient)?;
        let binding=self.bindings.get(&recipient.to_string()).ok_or_else(||err("I2P contact has no signed address"))?;
        binding.verify(&recipient,unix_now(),0).map_err(|_|err("I2P contact address invalid or expired"))?;
        let bytes=serde_json::to_vec(envelope).map_err(|_|err("I2P invalid envelope"))?;
        if bytes.is_empty() || bytes.len()>MAX_FRAME {return Err(err("I2P message size exceeded"))}
        let mut uncertain = false;
        // Retry the exact same envelope, never create a second message id.
        // The receiving mailbox rejects a different payload with the same id.
        for attempt in 0..2 {
            if let Ok(mut socket)=self.session.connect(&binding.destination) {
                let _=socket.set_read_timeout(Some(Duration::from_secs(15)));
                let _=socket.set_write_timeout(Some(Duration::from_secs(10)));
                uncertain = true; // The peer may receive bytes even on write error.
                if socket.write_all(MAGIC).and_then(|_|socket.write_all(&(bytes.len() as u32).to_be_bytes())).and_then(|_|socket.write_all(&bytes)).is_ok() {
                    let mut reply=[0u8;1];
                    if socket.read_exact(&mut reply).is_ok() && reply == [1] { return Ok(()); }
                }
            }
            if attempt == 0 { thread::sleep(Duration::from_secs(1)); }
        }
        if uncertain { Err(err("I2P delivery outcome unknown")) } else { Err(err("I2P connection unavailable")) }
    }
    fn fetch(&self, recipient:&Address, now:u64, limit:usize)->Result<Vec<Envelope>> {
        if recipient != &self.own {return Err(Error::WrongRecipient)}
        self.mailbox.fetch(recipient,now,limit)
    }
    fn ack(&self,recipient:&Address,ids:&[String])->Result<usize> {
        if recipient != &self.own {return Err(Error::WrongRecipient)}
        self.mailbox.ack(recipient,ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Identity,MessageKind};
    use std::net::TcpListener;
    #[test]
    fn incoming_frame_is_bounded_and_only_ciphertext_is_stored() {
        let root=std::env::temp_dir().join(format!("gs-i2p-transport-{}",uuid::Uuid::new_v4()));
        let own=Identity::from_seed([3;32],"tgrin").unwrap();
        let sender=Identity::from_seed([4;32],"tgrin").unwrap();
        let env=Envelope::seal_now(&sender,own.address(),MessageKind::Text{text:"private sample".into()},600).unwrap();
        let bytes=serde_json::to_vec(&env).unwrap(); assert!(!String::from_utf8_lossy(&bytes).contains("private sample"));
        let mailbox=FileMailbox::open(&root).unwrap();
        let listener=TcpListener::bind("127.0.0.1:0").unwrap(); let addr=listener.local_addr().unwrap();
        let client=thread::spawn(move || {let mut s=TcpStream::connect(addr).unwrap();s.write_all(MAGIC).unwrap();s.write_all(&(bytes.len() as u32).to_be_bytes()).unwrap();s.write_all(&bytes).unwrap();let mut reply=[0];s.read_exact(&mut reply).unwrap();assert_eq!(reply,[1]);});
        receive_one(listener.accept().unwrap().0,own.address(),&mailbox).unwrap(); client.join().unwrap();
        let received=mailbox.fetch(own.address(),unix_now(),10).unwrap();assert_eq!(received.len(),1);
        assert_eq!(received[0].open(&own,unix_now()).unwrap().sender,sender.address().clone());
        // A resend after a lost reply uses the same envelope and stays one record.
        let retry=serde_json::to_vec(&env).unwrap();
        let listener=TcpListener::bind("127.0.0.1:0").unwrap();let addr=listener.local_addr().unwrap();
        let client=thread::spawn(move||{let mut s=TcpStream::connect(addr).unwrap();s.write_all(MAGIC).unwrap();s.write_all(&(retry.len() as u32).to_be_bytes()).unwrap();s.write_all(&retry).unwrap();let mut reply=[0];s.read_exact(&mut reply).unwrap();assert_eq!(reply,[1]);});
        receive_one(listener.accept().unwrap().0,own.address(),&mailbox).unwrap();client.join().unwrap();
        assert_eq!(mailbox.fetch(own.address(),unix_now(),10).unwrap().len(),1);
        let listener=TcpListener::bind("127.0.0.1:0").unwrap();let addr=listener.local_addr().unwrap();
        let client=thread::spawn(move||{let mut s=TcpStream::connect(addr).unwrap();s.write_all(MAGIC).unwrap();s.write_all(&((MAX_FRAME as u32)+1).to_be_bytes()).unwrap();});
        assert!(receive_one(listener.accept().unwrap().0,own.address(),&mailbox).is_err());client.join().unwrap();
    }

    #[test]
    #[ignore = "requires two explicitly started isolated I2P routers"]
    fn live_two_router_transport_saves_and_verifies_text() {
        use crate::i2p_sam::Destination;
        use crate::Messenger;
        let a:std::net::SocketAddr="127.0.0.1:17657".parse().unwrap();
        let b:std::net::SocketAddr="127.0.0.1:17658".parse().unwrap();
        let da=Destination::generate(a).unwrap(); let db=Destination::generate(b).unwrap();
        let sa=da.open_session(a,"glaux-transport-a").unwrap();
        let sb=db.open_session(b,"glaux-transport-b").unwrap();
        let alice=Identity::from_seed([14;32],"tgrin").unwrap();
        let bob=Identity::from_seed([15;32],"tgrin").unwrap();
        let root=std::env::temp_dir().join(format!("gs-i2p-live-{}",uuid::Uuid::new_v4()));
        let ep_a=I2pEndpoint::start(sa,alice.address().clone(),FileMailbox::open(root.join("a")).unwrap()).unwrap();
        let ep_b=I2pEndpoint::start(sb,bob.address().clone(),FileMailbox::open(root.join("b")).unwrap()).unwrap();
        let now=unix_now();
        let binding=Binding::create(&bob,db.public(),1,now,now+3600).unwrap();
        let mut destinations=HashMap::new(); destinations.insert(bob.address().to_string(),binding);
        let sender=ep_a.transport(destinations);
        let receiver=Messenger::new(ep_b.transport(HashMap::new()));
        let envelope=Envelope::seal_now(&alice,bob.address(),MessageKind::Text{text:"synthetic I2P message".into()},600).unwrap();
        let mut sent=false;
        for attempt in 1..=10 {
            match sender.deliver(&envelope) {
                Ok(())=>{sent=true;break},
                Err(error)=>{println!("waiting for I2P route {attempt}/10: {error}");thread::sleep(Duration::from_secs(15));}
            }
        }
        assert!(sent,"I2P send unavailable");
        let batch=receiver.fetch_open(&bob,10).unwrap(); assert_eq!(batch.opened.len(),1);
        assert_eq!(batch.opened[0].sender,alice.address().clone());
        assert_eq!(batch.opened[0].kind,MessageKind::Text{text:"synthetic I2P message".into()});
        receiver.ack_signed(&bob,&[batch.opened[0].transport_token.clone().unwrap()]).unwrap();
        drop(receiver); drop(sender); drop(ep_b); drop(ep_a);
    }
}
