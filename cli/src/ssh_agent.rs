use std::convert::TryFrom;
use std::convert::TryInto;
use thiserror::Error;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;

// https://tools.ietf.org/html/draft-miller-ssh-agent-04#section-5.1
// Requests from client to agent
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;

// Replies from agent to client
const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENT_SUCCESS: u8 = 6;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;

#[derive(Error, Debug)]
pub enum SignError {
    // #[error("IO error: {0}")]
    // IO(#[from] std::io::Error),
    #[error("Read: {0}")]
    Read(#[from] ReadError),
    #[error("Send: {0}")]
    Send(#[from] SendError),
    #[error("List keys: {0}")]
    ListKeys(#[from] ListKeysError),
}

#[derive(Error, Debug)]
pub enum SendError {
    #[error("IO error: {0}")]
    IO(#[from] std::io::Error),
    #[error("Length mismatch")]
    LengthMismatch,
    #[error("Length conversion: {0}")]
    TryFromInt(#[from] core::num::TryFromIntError),
}

#[derive(Error, Debug)]
pub enum ReadError {
    #[error("IO: {0}")]
    IO(#[from] std::io::Error),
    #[error("Length conversion: {0}")]
    TryFromInt(#[from] core::num::TryFromIntError),
}

#[derive(Error, Debug)]
pub enum ListKeysError {
    #[error("Send: {0}")]
    Send(#[from] SendError),
    #[error("Read: {0}")]
    Read(#[from] ReadError),
    #[error("IO error: {0}")]
    IO(#[from] std::io::Error),
    #[error("Length conversion: {0}")]
    TryFromInt(#[from] core::num::TryFromIntError),
    #[error("Unexpected reply to key list request: {0}")]
    UnexpectedAnswer(u8),
    #[error("Missing number of keys in response. Length: {0}")]
    MissingNKeys(usize),
    #[error("Try from slice: {0}")]
    TryFromSlice(#[from] core::array::TryFromSliceError),
}

#[derive(Debug)]
struct Message {
    pub type_: u8,
    pub contents: Vec<u8>,
}

/*
impl Message {
    fn new(type_: u8, contents: Vec<u8>) -> Self {
        Self {
            len: contents.len().into(),
            type_,
            contents,
        }
    }
}
*/

async fn read_msg(ssh_agent_sock: &mut tokio::net::UnixStream) -> Result<Message, ReadError> {
    use bytes::BytesMut;
    let len = ssh_agent_sock.read_u32().await?;
    eprintln!("len {}", len);
    let msg_type = ssh_agent_sock.read_u8().await?;
    eprintln!("type {}", msg_type);
    let len = usize::try_from(len)? - 1;
    let mut contents = BytesMut::with_capacity(len);
    let mut remaining = len;
    while remaining > 0 {
        let read = ssh_agent_sock.read_buf(&mut contents).await?;
        remaining -= read;
    }
    // eprintln!("contents {}", &contents);
    Ok(Message {
        type_: msg_type,
        contents: contents.to_vec(),
    })
}

async fn send_msg(
    ssh_agent_sock: &mut tokio::net::UnixStream,
    msg: Message,
) -> Result<(), SendError> {
    let len = u32::try_from(msg.contents.len())? + 1;
    ssh_agent_sock.write_u32(len).await?;
    ssh_agent_sock.write_u8(msg.type_).await?;
    ssh_agent_sock.write_all(&msg.contents).await?;
    Ok(())
}

async fn list_keys(ssh_agent_sock: &mut tokio::net::UnixStream) -> Result<Vec<u8>, ListKeysError> {
    send_msg(
        ssh_agent_sock,
        Message {
            type_: SSH_AGENTC_REQUEST_IDENTITIES,
            contents: Vec::new(),
        },
    )
    .await?;
    let reply = read_msg(ssh_agent_sock).await?;
    eprintln!("reply {:?}", reply);
    if reply.type_ != SSH_AGENT_IDENTITIES_ANSWER {
        return Err(ListKeysError::UnexpectedAnswer(reply.type_));
    }
    if reply.contents.len() < 4 {
        return Err(ListKeysError::MissingNKeys(reply.contents.len()));
    }
    let bytes = reply.contents[0..4].try_into()?;
    let nkeys_u32 = u32::from_be_bytes(bytes);
    let nkeys = usize::try_from(nkeys_u32)?;
    eprintln!("nkeys {}", nkeys);

    Ok(Vec::new())
}

pub async fn sign(
    prep: &ssi::ldp::ProofPreparation,
    ssh_agent_sock: &mut tokio::net::UnixStream,
) -> Result<String, SignError> {
    eprintln!("prep {}", serde_json::to_string_pretty(&prep).unwrap());
    let keys = list_keys(ssh_agent_sock).await?;
    eprintln!("keys {:?}", keys);
    // send_msg(&mut ssh_agent_sock).await?;
    // read_msg(ssh_agent_sock).await?;
    Ok("TODO".to_string())
}
