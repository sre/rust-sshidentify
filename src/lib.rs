// © 2018 Sebastian Reichel
// SPDX-License-Identifier: ISC

#![crate_type = "lib"]
#![crate_name = "sshidentify"]

//! The Rust `sshidentify` can be used to gain information about the
//! SSH key, that has been used for the current connection. The
//! public `get_ssh_info()` will traverse through the process tree
//! to find the parent sshd PID. Once found the PID is being used
//! to check the systemd journal for the key fingerprint having been
//! used for the connection. Last but not least the `~/.ssh/authorized_keys`
//! is being examined to find the public key for the fingerprint.
//! 
//! NOTE: The resulting binary must be called with permissions to
//! access the system's systemd journal to be functional.
//! 
//! # Example
//! ```
//! extern crate sshidentify;
//! 
//! /// Print information about first gpiochip
//! fn main() {
//! 	let info = sshidentify::get_ssh_info().unwrap()
//!     println!("SSH Info: {:?}", info);
//! }
//! ```

extern crate nix;
extern crate libc;
extern crate systemd;
extern crate regex;
extern crate base64;
extern crate sha2;
extern crate md5;

use std::io;
use std::io::BufRead;
use sha2::Digest;

#[derive(Debug)]
struct ProcessInfo {
    pid: nix::unistd::Pid,
    ppid: nix::unistd::Pid,
    name: String,
}

#[derive(Debug)]
struct SSHLogInfo {
    username: String,
    ip: String,
    keytype: String,
    fingerprint: String,
    fptype: SSHFingerprintType,
}

#[derive(Debug)]
struct SSHPubKey {
    keytype: String,
    keydata: String,
    comment: String,
}

#[derive(Debug)]
pub enum SSHFingerprintType {
    MD5,
    SHA256,
}

#[derive(Debug)]
pub struct SSHInfo {
    /// type of the fingerprint found in the systemd journal
    pub fingerprint_type: SSHFingerprintType,
    /// fingerprint found in the systemd journal
    pub fingerprint: String,
    /// local username of the ssh connection
    pub username: String,
    /// remote ip of the ssh connection
    pub ip: String,
    /// type of the public key
    pub keytype: String,
    /// the public key
    pub keydata: String,
    /// comment behind the public key (i.e. "user@localhost")
    pub comment: String,
}

/// read process info for a PID from procfs (Linux only)
fn get_pid_info(pid: nix::unistd::Pid) -> std::io::Result<(ProcessInfo)> {
    let pid_info_file = format!("/proc/{}/status", pid);
    let f = try!(std::fs::File::open(pid_info_file));
    let file = std::io::BufReader::new(&f);

    let mut name = String::new();
    let mut ppid = nix::unistd::Pid::from_raw(1);

    for line in file.lines() {
        let l = line.unwrap();
        let mut linesplit = l.split(":\t");
        let key = linesplit.next();
        let val = linesplit.next();
        if key.is_none() || val.is_none() {
            continue;
        }
        match key.unwrap() {
            "PPid" => ppid = nix::unistd::Pid::from_raw(val.unwrap().parse::<libc::pid_t>().unwrap()),
            "Name" => name = val.unwrap().to_string(),
            _ => {},
        };
    }
    Ok(ProcessInfo { pid, ppid, name } )
}

/// walk through parent processes until sshd process is found
fn get_sshd_pid() -> std::io::Result<(nix::unistd::Pid)> {
    let mut info = try!(get_pid_info(nix::unistd::getppid()));

    while !info.name.contains("sshd") && info.pid != nix::unistd::Pid::from_raw(1) {
        info = try!(get_pid_info(info.ppid));
    }

    if info.pid == nix::unistd::Pid::from_raw(1) {
        return Err(io::Error::new(io::ErrorKind::NotFound, "sshd parent process not found"))
    }

    if nix::unistd::Uid::current().is_root() {
        Ok(info.pid)
    } else {
        Ok(info.ppid)
    }
}

/// find "Accepted publickey" message for provided pid in systemd journal
fn get_sshd_journal_entry(pid: nix::unistd::Pid) -> std::io::Result<(String)> {
    let mut journal = try!(systemd::journal::Journal::open(systemd::journal::JournalFiles::System, false, false));
    try!(journal.seek(systemd::journal::JournalSeek::Current));
    let pidstr = format!("{}", pid);

    try!(journal.match_add("SYSLOG_IDENTIFIER", "sshd"));
    try!(journal.match_and());
    try!(journal.match_add("SYSLOG_PID", pidstr));

    let mut record = try!(journal.next_record());
    while record.is_some() {
        let recordmap = record.unwrap();
        let msg = recordmap.get("MESSAGE");

        if msg.is_some() {
            let rawmsg = msg.unwrap();
            if rawmsg.contains("Accepted publickey") {
                return Ok(rawmsg.to_string());
            }
        }

        record = try!(journal.next_record());
    }

    Err(io::Error::new(io::ErrorKind::NotFound, "sshd log entry not found"))
}

/// decode Accepted publickey log message from ssh
fn decode_ssh_log(message: &str) -> std::io::Result<SSHLogInfo> {
    // ... (username) ... (ip) ... (keytype) ... (keyhash)
    let re_md5 = regex::Regex::new(r"^Accepted publickey for ([-_\\.a-zA-Z0-9]+) from ([0-9\\.:]+) port [0-9]+ ssh2: ([A-Z0-9]+) ([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})$").unwrap();
    let re_sha256 = regex::Regex::new(r"^Accepted publickey for ([-_\\.a-zA-Z0-9]+) from ([0-9\\.:]+) port [0-9]+ ssh2: ([A-Z0-9]+) SHA256:([A-Za-z0-9+/]+)$").unwrap();

    let mut fptype = SSHFingerprintType::SHA256;
    let mut caps = re_sha256.captures(message);
    if caps.is_none() {
        fptype = SSHFingerprintType::MD5;
        caps = re_md5.captures(message);
    }

    if caps.is_none() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "No regex match"))
    }

    let cap = caps.unwrap();
    let username = cap.get(1).unwrap().as_str().to_string();
    let ip = cap.get(2).unwrap().as_str().to_string();
    let keytype = cap.get(3).unwrap().as_str().to_string();
    let fingerprint = cap.get(4).unwrap().as_str().to_string();

    Ok(SSHLogInfo{username: username, ip: ip, keytype: keytype, fptype: fptype, fingerprint: fingerprint})
}

/// generate fingerprint hash
fn key2fp(loginfo: &SSHLogInfo, pubkey64: &str) -> io::Result<String> {
    let pubkeydata = match base64::decode(pubkey64) {
        Ok(data) => data,
        Err(_err) => return Err(io::Error::new(io::ErrorKind::InvalidData, "Failed to Decode mime64 pubkey")),
    };

    match loginfo.fptype {
        SSHFingerprintType::SHA256 => {
            let mut hasher = sha2::Sha256::default();
            hasher.input(&pubkeydata);
            let hashed = hasher.result();
            let fp64 = base64::encode(&hashed);
            return Ok(fp64.trim_right_matches('=').to_string());
        },
        SSHFingerprintType::MD5 => {
            let digest = md5::compute(&pubkeydata);
            let fp = format!("{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                             digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
                             digest[8], digest[9], digest[10], digest[11], digest[12], digest[13], digest[14], digest[15]);
            return Ok(fp.to_string());
        },
    }
}

/// get authorized_key information for publickey fingerprint
fn ssh_get_authorized_key(loginfo: &SSHLogInfo) -> std::io::Result<SSHPubKey> {
    let mut authfile = std::env::home_dir().unwrap();
    authfile.push(".ssh");
    authfile.push("authorized_keys");
    let f = try!(std::fs::File::open(authfile));
    let file = std::io::BufReader::new(&f);

    for line in file.lines() {
        let l = line.unwrap();
        let parts : Vec<&str> = l.splitn(3, ' ').collect();

        if parts.len() != 3 {
            continue;
        }

        let keytype = parts[0];
        let pubkey64 = parts[1];
        let comment = parts[2];

        let pubkeyfp = try!(key2fp(&loginfo, pubkey64));

        if pubkeyfp == loginfo.fingerprint {
            return Ok(SSHPubKey{keytype: keytype.to_string(), keydata: pubkey64.to_string(), comment: comment.to_string()});
        }
    }

    Err(io::Error::new(io::ErrorKind::NotFound, "Fingerprint not found in authorized_key file"))
}

/// get ssh key information for UID
pub fn get_ssh_info() -> std::io::Result<SSHInfo> {
    let pid = try!(get_sshd_pid());
    let msg = try!(get_sshd_journal_entry(pid));
    let info = try!(decode_ssh_log(&msg));
    let auth = try!(ssh_get_authorized_key(&info));

    Ok(SSHInfo{fingerprint_type: info.fptype, fingerprint: info.fingerprint, username: info.username, ip: info.ip, keytype: auth.keytype, keydata: auth.keydata, comment: auth.comment})
}
