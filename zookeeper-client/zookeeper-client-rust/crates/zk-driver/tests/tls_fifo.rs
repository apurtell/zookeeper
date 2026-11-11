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

//! Tests that a FIFO at a certificate, key or CA path never blocks the credential loader.
//!
//! The loader runs on the I/O thread. An open of a FIFO with no writer waits for a writer. Each
//! test runs the loader on a helper thread, and a timeout turns a blocked open into a failure.

#![cfg(all(unix, feature = "tls"))]
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
#![allow(clippy::disallowed_macros)]

use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use zk_driver::net::tls::identity::Identity;
use zk_driver::net::tls::trust::{TrustLoadError, TrustSet};
use zk_driver::net::tls::{LegacyPath, TlsConfigStep, TlsSetupError, default_provider};
use zk_proto::SecretBytes;

/// Time limit for one guarded call. A blocked open never returns, so any limit works.
const LIMIT: Duration = Duration::from_secs(20);

/// Run time of the swap stress test.
const SWAP_RUN: Duration = Duration::from_secs(2);

fn fixture(name: &str) -> PathBuf {
    zk_testkit::fixtures::tls_dir().join(name)
}

fn legacy(path: &Path) -> LegacyPath {
    LegacyPath::new(path.as_os_str().as_bytes().to_vec())
}

/// Makes a fresh scratch directory for one test.
fn scratch_dir(tag: &str) -> PathBuf {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("tls_fifo-{}-{tag}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Makes a FIFO, or gives `None` when `mkfifo` is not available.
fn make_fifo(path: &Path) -> Option<()> {
    std::process::Command::new("mkfifo")
        .arg(path)
        .status()
        .is_ok_and(|s| s.success())
        .then_some(())
}

/// Runs `f` on a helper thread and fails the test if `f` does not return within [`LIMIT`].
///
/// A blocked helper stays parked in its open. The test process ends it at exit.
fn guarded<R: Send + 'static>(what: &str, f: impl FnOnce() -> R + Send + 'static) -> R {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    match rx.recv_timeout(LIMIT) {
        Ok(r) => r,
        Err(e) => panic!("{what} did not return in {LIMIT:?}: {e}"),
    }
}

/// Loads a certificate chain and key, and gives the failed step.
fn load_identity(cert: &Path, key: &Path) -> Result<(), TlsConfigStep> {
    Identity::load(
        &legacy(cert),
        &legacy(key),
        &SecretBytes::from_slice(b""),
        &default_provider(),
    )
    .map(drop)
    .map_err(|e| match e {
        TlsSetupError::Config { step } => step,
        other => panic!("not a config error: {other:?}"),
    })
}

fn load_ca(ca: &Path) -> Result<(), TrustLoadError> {
    TrustSet::default().load_ca_file(Some(&legacy(ca)))
}

/// Asserts that a FIFO at the CA, certificate or key path fails its step at once.
///
/// The metadata check before the open rejects this fixed FIFO. The swap test covers the
/// non-blocking open. Without `mkfifo`, the test returns early and passes.
#[test]
fn a_fifo_credential_path_fails_and_does_not_block() {
    let dir = scratch_dir("fixed");
    let fifo = dir.join("fifo.pem");
    if make_fifo(&fifo).is_none() {
        return;
    }
    let (cert, key) = (fixture("client.pem"), fixture("client.key"));
    assert_eq!(load_identity(&cert, &key), Ok(()));
    assert_eq!(load_ca(&fixture("ca.pem")), Ok(()));

    let at = fifo.clone();
    let r = guarded("the CA load", move || load_ca(&at));
    assert_eq!(r, Err(TrustLoadError::Io));
    let (at, k) = (fifo.clone(), key.clone());
    let r = guarded("the certificate load", move || load_identity(&at, &k));
    assert_eq!(r, Err(TlsConfigStep::ClientCertChain));
    let at = fifo.clone();
    let r = guarded("the key load", move || load_identity(&cert, &at));
    assert_eq!(r, Err(TlsConfigStep::ClientKey));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Points `link` at `target` in one atomic rename.
fn swap_link(target: &Path, tmp: &Path, link: &Path) {
    let _ = std::fs::remove_file(tmp);
    std::os::unix::fs::symlink(target, tmp).unwrap();
    std::fs::rename(tmp, link).unwrap();
}

/// Asserts that a CA path that flips between a regular file and a FIFO never blocks the load.
///
/// A swapper thread flips the path while the loader runs in a loop. Some loads see the swap
/// between the metadata check and the open. Each load must succeed or fail at once. The race
/// window is small. Thus this test is a stress guard, and a run can miss the race.
#[test]
fn a_ca_path_swapped_to_a_fifo_does_not_block() {
    let dir = scratch_dir("swap");
    let fifo = dir.join("fifo.pem");
    if make_fifo(&fifo).is_none() {
        return;
    }
    let regular = fixture("ca.pem");
    let link = dir.join("ca.pem");
    swap_link(&regular, &dir.join("tmp"), &link);

    let stop = Arc::new(AtomicBool::new(false));
    let swapper = {
        let (stop, dir, fifo, link) = (Arc::clone(&stop), dir.clone(), fifo.clone(), link.clone());
        std::thread::spawn(move || {
            let tmp = dir.join("tmp");
            while !stop.load(Ordering::Relaxed) {
                swap_link(&fifo, &tmp, &link);
                swap_link(&regular, &tmp, &link);
            }
        })
    };
    let at = link.clone();
    let (ok, failed) = guarded("a CA load during the swaps", move || {
        let (mut ok, mut failed) = (0u32, 0u32);
        let started = Instant::now();
        while started.elapsed() < SWAP_RUN {
            match load_ca(&at) {
                Ok(()) => ok += 1,
                Err(TrustLoadError::Io) => failed += 1,
                Err(e) => panic!("unexpected CA load error: {e:?}"),
            }
        }
        (ok, failed)
    });
    stop.store(true, Ordering::Relaxed);
    swapper.join().unwrap();
    assert!(ok > 0 && failed > 0, "ok {ok} failed {failed}");
    std::fs::remove_dir_all(&dir).unwrap();
}
