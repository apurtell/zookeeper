// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! TLS test material that the tests make at test time.
//!
//! The repository holds no keys or certificates. It holds only the
//! scripts that make them. [`tls_dir`] gives the TLS fixtures of
//! `gen.sh` and `trust/gen.sh`. [`tls_corpus_dir`] gives the
//! trust-decision corpus of `gencorpus.sh`.
//!
//! Each set goes into a cache entry whose name holds a key. The key is a
//! hash of the build inputs: the scripts, the tool paths and the OpenSSL
//! version. Thus a script edit or a new OpenSSL gives a new entry. The
//! helper never uses an old entry by mistake.
//!
//! The helper makes an entry in a temporary directory and then renames
//! it to its final name. Thus a directory with a final name is always
//! complete. A lock directory prevents two parallel builds of one entry.
//! Correctness does not depend on the lock.
//!
//! These variables change the behavior:
//!
//! - `ZK_TEST_OPENSSL`: the only `openssl` candidate.
//! - `ZK_TEST_FIXTURE_DIR`: the cache root.
//! - `ZK_TEST_TLS_FIXTURES`, `ZK_TEST_TLS_CORPUS`: a ready directory for
//!   one set. The helper uses it as it is and starts no process.
//!
//! The directory variables must hold absolute paths.

use std::env;
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::process::{self, Command, Stdio};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant};

/// The version of the cache key rule. Change it when the rule changes.
const KEY_RULE: &str = "zk-fixtures/1";
/// The longest wait for another process that makes the same entry.
const WAIT: Duration = Duration::from_secs(15 * 60);
/// The interval between two checks of a lock that another process holds.
const POLL: Duration = Duration::from_millis(250);
/// A lock directory without a pid file is stale after this time.
const NO_PID_GRACE: Duration = Duration::from_secs(30);
/// The number of log lines in a failure message.
const TAIL_LINES: usize = 30;
/// A full corpus has more case directories than this.
const MIN_CASES: usize = 100;

/// The generators in the workspace. The TLS scripts have the same
/// relative paths in the entry.
const TLS_SRC: &str = "crates/zk-driver/tests/fixtures/tls";
const TLS_SCRIPTS: [&str; 2] = ["gen.sh", "trust/gen.sh"];
const CORPUS_SCRIPT: &str = "c/tests/conformance/tls/gencorpus.sh";

const OPENSSL_NEED: &str = "the TLS test fixtures need the command line tool of \
     OpenSSL 3.4 or later (3.x, the OpenSSL that the legacy C client links; not 4.x and \
     not LibreSSL). Set ZK_TEST_OPENSSL=/path/to/openssl.";
const CORPUS_HELD_BACK: &str = "the trust-decision corpus needs \
     c/tests/conformance/tls/gencorpus.sh from the held-back subtree c/tests";

/// Gives the directory of the TLS fixtures.
///
/// The directory has the layout of `tests/fixtures/tls` of zk-driver,
/// with `keys/` and `trust/`. It also holds copies of
/// `gen.sh` and `trust/gen.sh`. The first call in a process makes the
/// fixtures when the cache has no entry for them. The other calls wait
/// for the first call and then use its result.
///
/// # Panics
///
/// The function panics when no usable OpenSSL is found or when the
/// generator fails. The message tells what to do.
pub fn tls_dir() -> &'static Path {
    TLS.dir()
}

/// Gives the directory of the trust-decision corpus.
///
/// The directory holds one directory for each case and the keys in
/// `_keys`. The first call in a process makes the corpus when the cache
/// has no entry for it. The first build takes about one or two minutes.
///
/// # Panics
///
/// The function panics when `gencorpus.sh` is not in the tree, when no
/// usable OpenSSL is found, or when the generator fails.
pub fn tls_corpus_dir() -> &'static Path {
    CORPUS.dir()
}

/// One set of test material, and the cell that keeps its result.
struct Set {
    name: &'static str,
    what: &'static str,
    ready_var: &'static str,
    /// The corpus needs extra tools and has its cases in `corpus/`.
    is_corpus: bool,
    cell: OnceLock<Result<PathBuf, String>>,
}

static TLS: Set = Set {
    name: "tls",
    what: "TLS fixtures",
    ready_var: "ZK_TEST_TLS_FIXTURES",
    is_corpus: false,
    cell: OnceLock::new(),
};

static CORPUS: Set = Set {
    name: "corpus",
    what: "trust-decision corpus",
    ready_var: "ZK_TEST_TLS_CORPUS",
    is_corpus: true,
    cell: OnceLock::new(),
};

impl Set {
    #[allow(
        clippy::panic,
        reason = "a test fixture that cannot be made stops the test"
    )]
    fn dir(&'static self) -> &'static Path {
        // The cell keeps a failure too, so the other tests of the process
        // report it at once and do not run the generator again.
        match self.cell.get_or_init(|| locate(self)) {
            Ok(dir) => dir,
            Err(msg) => panic!("{msg}"),
        }
    }

    /// The directory that the caller gets for a cache entry.
    fn entry(&self, dir: &Path) -> PathBuf {
        if self.is_corpus {
            dir.join("corpus")
        } else {
            dir.to_path_buf()
        }
    }
}

/// The inputs of one build, and the key that they give.
struct Plan {
    set: &'static Set,
    /// The root of the Rust workspace.
    rs: PathBuf,
    openssl: PathBuf,
    /// Only the corpus plan has extra tools.
    corpus: Option<CorpusTools>,
    key: String,
    inputs: String,
}

struct CorpusTools {
    bash: PathBuf,
    c_dir: PathBuf,
}

fn locate(set: &'static Set) -> Result<PathBuf, String> {
    if let Some(dir) = env_dir(set.ready_var)? {
        return ready(set, dir);
    }
    let plan = plan(set)?;
    obtain(&cache_root()?, &plan)
}

/// Checks a ready directory from the environment. It starts no process,
/// because the free-scan run sets it under an allocator preload.
fn ready(set: &Set, dir: PathBuf) -> Result<PathBuf, String> {
    check_path_text(&dir)?;
    let var = set.ready_var;
    let why = if set.is_corpus {
        let cases = count_cases(&dir);
        (cases <= MIN_CASES).then(|| {
            format!("has {cases} case directories, and a full corpus has more than {MIN_CASES}")
        })
    } else {
        (!dir.join("ca.pem").is_file()).then(|| "has no ca.pem".to_owned())
    };
    match why {
        Some(why) => Err(format!("{var}={} {why}", dir.display())),
        None => Ok(dir),
    }
}

/// Reads a directory variable. Cargo runs the tests of each crate in the
/// crate directory, so a relative value names a different directory for
/// each crate. The helper thus accepts only an absolute value.
fn env_dir(var: &str) -> Result<Option<PathBuf>, String> {
    match env::var_os(var).map(PathBuf::from) {
        Some(path) if !path.is_absolute() => Err(format!(
            "{var}={} is a relative path. Set it to an absolute path",
            path.display()
        )),
        dir => Ok(dir),
    }
}

/// Formats an I/O error with the path that it concerns.
fn at(path: &Path) -> impl FnOnce(io::Error) -> String + '_ {
    move |e| format!("{}: {e}", path.display())
}

fn canonical(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// The root of the Rust workspace, from the manifest of this crate.
fn workspace_dir() -> Result<PathBuf, String> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| "zk-testkit is not in crates/ of the Rust workspace".to_owned())
}

/// Finds the tools of a set and computes its cache key. The checks run
/// before the lock and the build, so a missing tool fails at once.
fn plan(set: &'static Set) -> Result<Plan, String> {
    let rs = workspace_dir()?;
    let script = rs.join(CORPUS_SCRIPT);
    if set.is_corpus && !script.is_file() {
        return Err(format!(
            "{CORPUS_HELD_BACK} ({} is missing)",
            script.display()
        ));
    }
    let (openssl, version) = find_openssl()?;
    let (scripts, corpus, corpus_fields): (Vec<PathBuf>, _, Vec<Field>) = if set.is_corpus {
        let (tools, fields) = corpus_tools(&rs)?;
        (vec![script], Some(tools), fields.into())
    } else {
        (
            TLS_SCRIPTS.map(|s| rs.join(TLS_SRC).join(s)).into(),
            None,
            Vec::new(),
        )
    };
    let real = canonical(&openssl);
    let mut fields: Vec<Field> = vec![
        ("rule", KEY_RULE.to_owned(), KEY_RULE.into()),
        ("set", set.name.to_owned(), set.name.into()),
        (
            "openssl",
            format!("{} (given as {})", real.display(), openssl.display()),
            real.into_os_string().into_encoded_bytes(),
        ),
        ("version", version.clone(), version.into_bytes()),
    ];
    for script in &scripts {
        fields.push(file_field("script", script).map_err(at(script))?);
    }
    fields.extend(corpus_fields);
    let (key, inputs) = cache_key(&fields);
    Ok(Plan {
        set,
        rs,
        openssl,
        corpus,
        key,
        inputs,
    })
}

/// Finds the extra tools of the corpus and gives their key fields. The
/// real gencerts.sh of the legacy C client is an input of the corpus, so
/// its bytes and the keytool path go into the key.
fn corpus_tools(rs: &Path) -> Result<(CorpusTools, [Field; 2]), String> {
    if on_path("xxd").is_none() {
        return Err("the trust-decision corpus needs xxd on PATH: \
             install xxd (vim-common)"
            .to_owned());
    }
    let bash = on_path("bash").ok_or("the trust-decision corpus needs bash on PATH")?;
    // gencorpus.sh makes the real gencerts.sh cases only when keytool
    // exists. Thus a missing keytool is an error, so that no case
    // disappears without a message.
    let keytool = on_path("keytool").ok_or(
        "the trust-decision corpus needs keytool (a JDK) on PATH, because \
         gencorpus.sh runs the real ssl/gencerts.sh of the legacy C client",
    )?;
    let c_dir = env_dir("ZK_C_DIR")?.unwrap_or_else(|| rs.join("../zookeeper-client-c"));
    let gencerts = canonical(&c_dir.join("ssl/gencerts.sh"));
    let gencerts = file_field("gencerts", &gencerts).map_err(|e| {
        format!(
            "the trust-decision corpus needs {} of the legacy C client \
             (ZK_C_DIR selects its directory): {e}",
            gencerts.display()
        )
    })?;
    let keytool = canonical(&keytool);
    let keytool = (
        "keytool",
        keytool.display().to_string(),
        keytool.into_os_string().into_encoded_bytes(),
    );
    Ok((CorpusTools { bash, c_dir }, [gencerts, keytool]))
}

/// One input of the cache key: a label, a text for the log, and the
/// bytes that the key hashes.
type Field = (&'static str, String, Vec<u8>);

/// Gives a field with the bytes of a file. The log shows its path and size.
fn file_field(label: &'static str, path: &Path) -> io::Result<Field> {
    let bytes = fs::read(path)?;
    let shown = format!("{} ({} bytes)", path.display(), bytes.len());
    Ok((label, shown, bytes))
}

/// Gives the cache key and the list of its inputs for the log. The key is
/// a 64-bit FNV-1a hash. Each field has a length prefix, so two field
/// lists never give the same byte stream.
fn cache_key(fields: &[Field]) -> (String, String) {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut inputs = String::new();
    for (label, shown, bytes) in fields {
        let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        for &b in len.to_le_bytes().iter().chain(bytes) {
            hash = (hash ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
        }
        let _ = writeln!(inputs, "  {label}: {shown}");
    }
    (format!("{hash:016x}"), inputs)
}

/// Finds the first `openssl` candidate with an accepted version.
fn find_openssl() -> Result<(PathBuf, String), String> {
    let candidates: Vec<PathBuf> = match env::var_os("ZK_TEST_OPENSSL") {
        Some(path) => vec![PathBuf::from(path)],
        None => [
            "/opt/homebrew/opt/openssl@3/bin/openssl",
            "/usr/local/opt/openssl@3/bin/openssl",
        ]
        .iter()
        .map(PathBuf::from)
        .chain(all_on_path("openssl"))
        .collect(),
    };
    let mut tried = String::new();
    for candidate in candidates {
        match probe_openssl(&candidate) {
            // The generators run in the work directory, so they get an
            // absolute path.
            Ok(version) => {
                let path = std::path::absolute(&candidate).map_err(at(&candidate))?;
                return Ok((path, version));
            }
            Err(why) => {
                let _ = writeln!(tried, "  {}: {why}", candidate.display());
            }
        }
    }
    Err(format!("{OPENSSL_NEED} Tried:\n{tried}"))
}

fn probe_openssl(candidate: &Path) -> Result<String, String> {
    if !candidate.is_file() {
        return Err("not found".to_owned());
    }
    let out = Command::new(candidate)
        .arg("version")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("does not run ({e})"))?;
    if !out.status.success() {
        return Err(format!("`version` fails ({})", out.status));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().next().unwrap_or("").trim().to_owned();
    if accepts_version(&line) {
        Ok(line)
    } else {
        Err(format!("\"{line}\" is not OpenSSL 3.4 to 3.x"))
    }
}

/// Accepts an `openssl version` line of OpenSSL 3.N with N >= 4. Older
/// 3.x has no `-not_before` and no `-x509v1`. OpenSSL 4.x changes some
/// corpus verdicts, and LibreSSL is a different oracle.
fn accepts_version(line: &str) -> bool {
    let Some(rest) = line.strip_prefix("OpenSSL ") else {
        return false;
    };
    let mut parts = rest.split_whitespace().next().unwrap_or("").split('.');
    let major = parts.next();
    let minor = parts.next().and_then(|m| m.parse::<u32>().ok());
    major == Some("3") && minor.is_some_and(|m| m >= 4)
}

fn all_on_path(name: &str) -> Vec<PathBuf> {
    env::var_os("PATH")
        .map(|path| {
            env::split_paths(&path)
                .map(|dir| dir.join(name))
                .filter(|file| file.is_file())
                .collect()
        })
        .unwrap_or_default()
}

fn on_path(name: &str) -> Option<PathBuf> {
    all_on_path(name).into_iter().next()
}

/// Finds the cache root. The default is next to the build output, so
/// `cargo clean` removes the cache too.
fn cache_root() -> Result<PathBuf, String> {
    let root = env_dir("ZK_TEST_FIXTURE_DIR")?.unwrap_or_else(|| {
        env::current_exe()
            .ok()
            .and_then(|exe| {
                exe.ancestors()
                    .skip(1)
                    .find(|dir| dir.join("CACHEDIR.TAG").is_file())
                    .map(Path::to_path_buf)
            })
            .or_else(|| env::var_os("CARGO_TARGET_DIR").map(PathBuf::from))
            .unwrap_or_else(env::temp_dir)
            .join("zk-fixtures")
    });
    let root = std::path::absolute(&root).map_err(at(&root))?;
    check_path_text(&root)?;
    fs::create_dir_all(&root).map_err(at(&root))?;
    Ok(root)
}

/// The characters that a fixture path must not hold. The tests put the
/// paths into SSL_CERT_DIR lists (':'), into the comma lists of the
/// ZooKeeper certificate strings (',') and into C string literals ('"'
/// and '\\').
const PATH_BAD: [char; 4] = [':', ',', '"', '\\'];

/// Checks that a fixture path is ASCII and holds no character of
/// [`PATH_BAD`].
fn check_path_text(path: &Path) -> Result<(), String> {
    match path.to_str() {
        Some(text) if text.is_ascii() && !text.contains(PATH_BAD) => Ok(()),
        _ => Err(format!(
            "the fixture path {} must be ASCII and must not hold ':', ',', '\"' or '\\'. \
             Set ZK_TEST_FIXTURE_DIR to another directory",
            path.display()
        )),
    }
}

/// Gives the cache entry of the plan. It makes the entry when it does
/// not exist.
fn obtain(root: &Path, plan: &Plan) -> Result<PathBuf, String> {
    let name = format!("{}-{}", plan.set.name, plan.key);
    let done = root.join(&name);
    let lock = wait_for_lock(root, &name, &done);
    // Another process can publish between the last look and the lock.
    if done.is_dir() {
        return Ok(plan.set.entry(&done));
    }
    let made = build(root, plan, &name, &done);
    drop(lock);
    made
}

/// The lock directory of one build. Its pid file names the owner. The
/// owner removes the lock when the build ends, also on a panic.
struct Busy(PathBuf);

impl Drop for Busy {
    fn drop(&mut self) {
        // A waiter can remove this lock as stale. A third process can then
        // take the name. Thus the owner removes the lock only when the pid
        // file names it.
        if read_pid(&self.0) == Some(process::id()) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

/// Waits for the lock of an entry. It gives `None` when the entry
/// exists, when the wait ends, or when the lock cannot be made. The lock
/// is only advisory, so the caller can then build without it.
fn wait_for_lock(root: &Path, name: &str, done: &Path) -> Option<Busy> {
    let busy = root.join(format!("{name}.busy"));
    let start = Instant::now();
    loop {
        if done.is_dir() {
            return None;
        }
        match take_lock(root, name, &busy) {
            Ok(Some(lock)) => return Some(lock),
            Ok(None) if start.elapsed() <= WAIT => {}
            _ => return None,
        }
        if !stale(&busy).is_some_and(|seen| reclaim(root, name, &busy, seen)) {
            thread::sleep(POLL);
        }
    }
}

/// Tries to take the lock. It gives `None` when another process holds
/// it. The pid file exists before the lock directory gets its name, so
/// each lock names its owner from the start.
fn take_lock(root: &Path, name: &str, busy: &Path) -> io::Result<Option<Busy>> {
    let tmp = root.join(format!(".{name}.busy-{}", process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir(&tmp)?;
    let made =
        fs::write(tmp.join("pid"), process::id().to_string()).and_then(|()| fs::rename(&tmp, busy));
    match made {
        Ok(()) => Ok(Some(Busy(busy.to_path_buf()))),
        Err(e) => {
            let _ = fs::remove_dir_all(&tmp);
            if busy.exists() { Ok(None) } else { Err(e) }
        }
    }
}

/// Reads the owner pid of a lock directory.
fn read_pid(busy: &Path) -> Option<u32> {
    fs::read_to_string(busy.join("pid"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Tells if a lock directory has no live owner. When it has none, the
/// function gives the pid that it read. Thus the caller removes only the
/// lock that it examined.
fn stale(busy: &Path) -> Option<Option<u32>> {
    let age = fs::metadata(busy)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok());
    let pid = read_pid(busy);
    let dead = match pid {
        Some(pid) => owner_gone(pid),
        // A lock of this helper always has a pid file. A lock without one
        // comes from an interrupted removal or from another tool, so a
        // short wait is enough.
        None => age.is_some_and(|age| age > NO_PID_GRACE),
    };
    (dead || age.is_some_and(|age| age > WAIT)).then_some(pid)
}

/// Removes a stale lock. A rename first moves the lock to a private
/// name, so two waiters cannot remove the same lock. When the moved lock
/// is not the examined one, the waiter tries to put it back. The lock is
/// only advisory, so a rare second build is safe.
fn reclaim(root: &Path, name: &str, busy: &Path, seen: Option<u32>) -> bool {
    let grave = root.join(format!(".{name}.stale-{}", process::id()));
    let _ = fs::remove_dir_all(&grave);
    if fs::rename(busy, &grave).is_err() {
        return false;
    }
    if read_pid(&grave) != seen && fs::rename(&grave, busy).is_ok() {
        return true;
    }
    let _ = fs::remove_dir_all(&grave);
    true
}

/// Tells if the owner of a lock is no longer running. An interrupted
/// test run can leave its lock, and the next run must not wait for it.
#[cfg(unix)]
fn owner_gone(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| !s.success())
}

#[cfg(not(unix))]
fn owner_gone(_pid: u32) -> bool {
    false
}

/// Makes the entry in a private work directory and then publishes it.
#[allow(
    clippy::print_stderr,
    reason = "one line tells where the new material is"
)]
fn build(root: &Path, plan: &Plan, name: &str, done: &Path) -> Result<PathBuf, String> {
    let job = Job::start(root, name, &plan.inputs)?;
    match &plan.corpus {
        None => make_tls(plan, &job)?,
        Some(tools) => make_corpus(plan, tools, &job)?,
    }
    match fs::rename(&job.work, done) {
        Ok(()) => {
            let log_path = root.join(format!("{name}.log"));
            let _ = fs::rename(&job.log_path, &log_path);
            eprintln!(
                "zk-testkit: made the {} in {} (log {})",
                plan.set.what,
                done.display(),
                log_path.display()
            );
        }
        // A directory with the final name is always complete. Thus the
        // entry of the race winner serves this process too.
        Err(_) if done.is_dir() => {
            let _ = fs::remove_dir_all(&job.work);
            let _ = fs::remove_file(&job.log_path);
        }
        Err(e) => {
            return Err(format!(
                "cannot rename {} to {}: {e}",
                job.work.display(),
                done.display()
            ));
        }
    }
    Ok(plan.set.entry(done))
}

/// The context of one build: the work directory and the log.
struct Job {
    log: File,
    log_path: PathBuf,
    work: PathBuf,
}

impl Job {
    /// Makes an empty work directory and a log with the key inputs. Each
    /// builder has its own log. The log gets its final name together with
    /// the entry, so two builders never write to one file.
    fn start(root: &Path, name: &str, inputs: &str) -> Result<Self, String> {
        let work = root.join(format!(".tmp-{name}-{}", process::id()));
        if work.exists() {
            fs::remove_dir_all(&work).map_err(at(&work))?;
        }
        fs::create_dir_all(&work).map_err(at(&work))?;
        let log_path = root.join(format!(".tmp-{name}-{}.log", process::id()));
        let mut log = File::create(&log_path).map_err(at(&log_path))?;
        let header = format!("{KEY_RULE} inputs of {name}:\n{inputs}\n");
        log.write_all(header.as_bytes()).map_err(at(&log_path))?;
        Ok(Self {
            log,
            log_path,
            work,
        })
    }

    /// Runs one generator step. Its output goes to the log.
    fn run(&self, cmd: &mut Command, what: &str) -> Result<(), String> {
        let log = || self.log.try_clone().map_err(at(&self.log_path));
        let status = cmd
            .current_dir(&self.work)
            .stdin(Stdio::null())
            .stdout(log()?)
            .stderr(log()?)
            .status()
            .map_err(|e| self.failure(&format!("{what} does not start ({e})")))?;
        if status.success() {
            Ok(())
        } else {
            Err(self.failure(&format!("{what} fails ({status})")))
        }
    }

    /// A failure message with the end of the log. The work directory
    /// stays, so that a person can examine it.
    fn failure(&self, what: &str) -> String {
        let text = fs::read(&self.log_path)
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        let tail: String = lines
            .iter()
            .skip(lines.len().saturating_sub(TAIL_LINES))
            .map(|line| format!("  {line}\n"))
            .collect();
        format!(
            "{what}. The work directory {} stays. Log {}, last lines:\n{tail}",
            self.work.display(),
            self.log_path.display()
        )
    }
}

fn make_tls(plan: &Plan, job: &Job) -> Result<(), String> {
    // gen.sh and trust/gen.sh write next to themselves, so copies run in
    // the work directory. The copies also stay in the entry, because the
    // C conformance case tls_init reads gen.sh as an input file.
    let trust = job.work.join("trust");
    fs::create_dir_all(&trust).map_err(at(&trust))?;
    let src = plan.rs.join(TLS_SRC);
    for script in TLS_SCRIPTS {
        let (from, to) = (src.join(script), job.work.join(script));
        fs::copy(&from, &to).map_err(|e| format!("{} to {}: {e}", from.display(), to.display()))?;
    }
    // gen.sh takes a list of sections, and `all` selects every section.
    for (script, sections) in [("gen.sh", Some("all")), ("trust/gen.sh", None)] {
        let mut cmd = Command::new("sh");
        job.run(cmd.arg(script).arg(&plan.openssl).args(sections), script)?;
    }

    for file in [
        "ca.pem",
        "server.pem",
        "client.key",
        "keys/rsa-pkcs1.pem",
        "keys/p8-scrypt.pem",
    ] {
        if !job.work.join(file).is_file() {
            return Err(job.failure(&format!("gen.sh made no {file}")));
        }
    }
    let expect = fs::read_to_string(trust.join("expect.txt")).unwrap_or_default();
    for line in ["load ca-root.pem ok", "load ca-bundle.pem ok"] {
        if !expect.lines().any(|l| l.trim() == line) {
            return Err(job.failure(&format!(
                "trust/expect.txt has no \"{line}\" line: a process listens on \
                 127.0.0.1:23419, so the load verdicts are wrong"
            )));
        }
    }
    Ok(())
}

fn make_corpus(plan: &Plan, tools: &CorpusTools, job: &Job) -> Result<(), String> {
    let out = job.work.join("corpus");
    let mut cmd = Command::new(&tools.bash);
    cmd.arg(plan.rs.join(CORPUS_SCRIPT))
        .env("OPENSSL", &plan.openssl)
        .env("ZK_CORPUS_OUT", &out)
        .env("ZK_C_DIR", &tools.c_dir);
    job.run(&mut cmd, "gencorpus.sh")?;
    let cases = count_cases(&out);
    if cases <= MIN_CASES {
        return Err(job.failure(&format!(
            "gencorpus.sh made {cases} cases, and a full corpus has more than {MIN_CASES}"
        )));
    }
    if !out.join("_keys/leaf.pem").is_file() {
        return Err(job.failure("gencorpus.sh made no _keys/leaf.pem"));
    }
    for case in ["tc01b-gencerts", "tc02-gencerts"] {
        if !out.join(case).join("verdict.txt").is_file() {
            return Err(job.failure(&format!(
                "gencorpus.sh made no {case} case from the real gencerts.sh"
            )));
        }
    }
    Ok(())
}

/// Counts the case directories, which are the ones with a verdict.txt.
fn count_cases(dir: &Path) -> usize {
    fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter(|e| e.path().join("verdict.txt").is_file())
                .count()
        })
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::accepts_version;

    #[test]
    fn version_rule_accepts_only_openssl_3_4_to_3_x() {
        assert!(accepts_version("OpenSSL 3.4.0 22 Oct 2024"));
        assert!(accepts_version(
            "OpenSSL 3.6.3 9 Jun 2026 (Library: OpenSSL 3.6.3 9 Jun 2026)"
        ));
        assert!(!accepts_version("OpenSSL 3.0.13 30 Jan 2024"));
        assert!(!accepts_version("OpenSSL 3.3.2 3 Sep 2024"));
        assert!(!accepts_version("OpenSSL 4.1.0 23 Oct 2026"));
        assert!(!accepts_version("LibreSSL 3.3.6"));
        assert!(!accepts_version(""));
    }
}
