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

//! The private C ABI types of `zkrs.h`.
//!
//! cbindgen reads this file and writes `zookeeper-client-rust/c/shim/zkrs.h`.
//! The names are the C names, so the Rust code and the shim use the same
//! words. Every type is `repr(C)` and holds only integers and raw
//! pointers. The file depends on `core` and `std` only. A standalone harness,
//! such as a fuzz target or a layout probe, can thus include it by
//! `#[path]`. The `zk-ffi-layout` crate does so. It compares each type,
//! variant and constant with its form in `zkrs.h`.
//!
//! The values of the constants are normative. A change here
//! changes the generated header, and `cbindgen --verify` then fails until
//! the header is regenerated and the shim agrees.

#![allow(non_camel_case_types, non_snake_case)]

use std::ffi::{c_char, c_double, c_int, c_long, c_void};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::ptr;

/// The opaque Rust handle. C holds `Arc::into_raw(Arc<Inner>)` as a
/// `const zkrs_handle *`. C never reads through it.
pub struct zkrs_handle {
    _opaque: [u8; 0],
}

/// A bounded byte view.
///
/// `is_null == 1` is a jute null token. Then `p` is NULL and `len` is 0.
/// `len > 0` needs a non-NULL `p`. `len` is at most `0x7fffffff`, so
/// each length fits in a C `int`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct zkrs_bytes {
    /// The first byte.
    pub p: *const u8,
    /// The number of bytes.
    pub len: u32,
    /// 1 for a jute null token.
    pub is_null: u8,
}

impl zkrs_bytes {
    /// The null view: `{NULL, 0, 1}`.
    #[must_use]
    pub const fn null() -> Self {
        Self {
            p: ptr::null(),
            len: 0,
            is_null: 1,
        }
    }
}

/// The kind of a SASL call.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum zkrs_sasl_kind {
    /// Start a new Cyrus connection. `local` and `peer` are set.
    ZKRS_SASL_START = 1,
    /// Give a server token to Cyrus. `token` is set.
    ZKRS_SASL_STEP = 2,
    /// Dispose the Cyrus connection. No result follows.
    ZKRS_SASL_DISPOSE = 3,
}

/// The status of a SASL result.
///
/// `ZKRS_SASL_STALE` goes only from the glue to the drain. Rust treats
/// each status other than CONTINUE or DONE as FAIL.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum zkrs_sasl_status {
    /// Cyrus gave `SASL_CONTINUE`.
    ZKRS_SASL_CONTINUE = 0,
    /// Cyrus gave `SASL_OK`.
    ZKRS_SASL_DONE = 1,
    /// The glue or Cyrus failed.
    #[allow(dead_code, reason = "only the C glue writes it")]
    ZKRS_SASL_FAIL = -1,
    /// The generation is stale. The glue made no Cyrus call.
    #[allow(dead_code, reason = "only the C glue writes it")]
    ZKRS_SASL_STALE = -2,
}

/// The SASL call view of a `ZKRS_ITEM_SASL` item.
///
/// The views point into outbox storage. They stay valid until the
/// matching `zkrs_sasl_result` returns or the outbox moves on.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct zkrs_sasl_call {
    /// `zkrs_sasl_kind`.
    pub kind: u32,
    /// The session generation. It is never 0.
    pub r#gen: u32,
    /// START only: the platform `sockaddr_in` or `sockaddr_in6` image of
    /// the local address. Otherwise the null view.
    pub local: zkrs_bytes,
    /// START only: the image of the peer address. Otherwise the null view.
    pub peer: zkrs_bytes,
    /// STEP only: the server token. A -1 token is the null view.
    pub token: zkrs_bytes,
}

/// The Cyrus output of one START or STEP.
///
/// C keeps the views valid until `zkrs_sasl_result` returns. Rust copies
/// them before it returns.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct zkrs_sasl_out {
    /// `zkrs_sasl_status`.
    pub status: i32,
    /// START: the mechanism that Cyrus chose. Otherwise the null view.
    pub mech: zkrs_bytes,
    /// The Cyrus `clientout`. The null view when Cyrus gave none.
    pub token: zkrs_bytes,
}

/// The result of a driving call.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum zkrs_step {
    /// The call finished. `*rc` is valid.
    ZKRS_DONE = 0,
    /// The call stopped at a barrier. C drains, then calls `zkrs_resume`.
    ZKRS_MORE = 1,
    /// The final close finished. `*rc` is the close rc. C drains, then
    /// frees `zh` and drops its reference.
    ZKRS_RELEASE = 2,
    /// Library-thread loops only: leave the loop.
    ZKRS_EXIT = 3,
}

/// The type of an outbox item.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum zkrs_item_type {
    /// A log line.
    ZKRS_ITEM_LOG = 1,
    /// A completion: async, sync or auth.
    ZKRS_ITEM_RESULT = 2,
    /// A node or session event.
    ZKRS_ITEM_WATCH = 3,
    /// A legacy `zoo_lock_auth` site.
    ZKRS_ITEM_AUTH_LOCKPOINT = 4,
    /// A SASL call: start, step or dispose of one Cyrus negotiation.
    ZKRS_ITEM_SASL = 5,
    /// A thread join or detach (mt only).
    ZKRS_ITEM_THREAD = 6,
}

/// The operation of a `ZKRS_ITEM_THREAD` item.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum zkrs_thread_op {
    /// Join the thread of the role.
    ZKRS_THREAD_JOIN = 1,
    /// Detach the calling thread.
    ZKRS_THREAD_DETACH = 2,
}

/// The status of a submission. C maps it to the legacy rc
/// with `zks_funnel`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum zkrs_status {
    /// The token is retained and is delivered exactly once.
    ZKRS_OK = 0,
    /// A local remove-watches call finished. The token is not retained.
    ZKRS_OK_LOCAL = 1,
    /// The TTL or path stage failed.
    ZKRS_EARLY_BADARGS = 2,
    /// `state < 0`, or `state == 0` for `zoo_add_auth`.
    ZKRS_EARLY_STATE = 3,
    /// The serialization stage failed: encode, input defect or close.
    ZKRS_LATE = 4,
    /// A multi sub-op type is not supported.
    ZKRS_UNIMPLEMENTED = 5,
    /// No watcher matches the remove-watches call.
    ZKRS_NOWATCHER = 6,
    /// `zoo_add_auth`: a negative `certLen` with a non-NULL `cert`, or a
    /// shim allocation failure.
    ZKRS_SYSTEM = 7,
}

/// A thread whose role was never set.
#[allow(dead_code, reason = "the C shim reads it through zkrs.h")]
pub const ZKRS_ROLE_FOREIGN: u32 = 0;
/// The thread that runs `zookeeper_init`.
pub const ZKRS_ROLE_INIT: u32 = 1;
/// The mt IO thread.
pub const ZKRS_ROLE_IO: u32 = 2;
/// The mt dispatch (completion) thread.
pub const ZKRS_ROLE_DISPATCH: u32 = 3;

/// `zkrs_init_args.flavor` of `libzookeeper_mt`.
pub const ZKRS_FLAVOR_MT: u32 = 1;
/// `zkrs_init_args.flavor` of `libzookeeper_st`.
#[allow(dead_code, reason = "the C shim reads it through zkrs.h")]
pub const ZKRS_FLAVOR_ST: u32 = 2;

/// Async delivery through the per-handle FIFO.
#[allow(dead_code, reason = "the C shim reads it through zkrs.h")]
pub const ZKRS_DELIVER_QUEUED: u32 = 0;
/// Sync and auth delivery on the producing thread.
pub const ZKRS_DELIVER_DIRECT: u32 = 1;

/// The result comes from a server reply.
pub const ZKRS_ORIGIN_REPLY: u32 = 0;
/// The result comes from a teardown.
pub const ZKRS_ORIGIN_TEARDOWN: u32 = 1;

/// Completion kind `COMPLETION_VOID`.
pub const ZKRS_K_VOID: u32 = 0;
/// Completion kind `COMPLETION_STAT`.
pub const ZKRS_K_STAT: u32 = 1;
/// Completion kind `COMPLETION_DATA`.
pub const ZKRS_K_DATA: u32 = 2;
/// Completion kind `COMPLETION_STRINGLIST`.
pub const ZKRS_K_STRINGLIST: u32 = 3;
/// Completion kind `COMPLETION_STRINGLIST_STAT`.
pub const ZKRS_K_STRINGLIST_STAT: u32 = 4;
/// Completion kind `COMPLETION_ACLLIST`.
pub const ZKRS_K_ACLLIST: u32 = 5;
/// Completion kind `COMPLETION_STRING`.
pub const ZKRS_K_STRING: u32 = 6;
/// Completion kind `COMPLETION_MULTI`.
pub const ZKRS_K_MULTI: u32 = 7;
/// Completion kind `COMPLETION_STRING_STAT`.
pub const ZKRS_K_STRING_STAT: u32 = 8;

/// `zoo_acreate*`.
pub const ZKRS_OP_CREATE: u32 = 1;
/// `zoo_adelete`.
pub const ZKRS_OP_DELETE: u32 = 2;
/// `zoo_awexists`.
pub const ZKRS_OP_EXISTS: u32 = 3;
/// `zoo_awget`.
pub const ZKRS_OP_GETDATA: u32 = 4;
/// `zoo_aset`.
pub const ZKRS_OP_SETDATA: u32 = 5;
/// `zoo_aget_acl`.
pub const ZKRS_OP_GETACL: u32 = 6;
/// `zoo_aset_acl`.
pub const ZKRS_OP_SETACL: u32 = 7;
/// `zoo_awget_children`.
pub const ZKRS_OP_GETCHILDREN: u32 = 8;
/// `zoo_awget_children2`.
pub const ZKRS_OP_GETCHILDREN2: u32 = 9;
/// `zoo_async`.
pub const ZKRS_OP_SYNC: u32 = 10;
/// `zoo_awgetconfig`.
pub const ZKRS_OP_GETCONFIG: u32 = 11;
/// `zoo_areconfig`.
pub const ZKRS_OP_RECONFIG: u32 = 12;
/// `zoo_amulti`.
pub const ZKRS_OP_MULTI: u32 = 13;
/// `zoo_aremove_watches`, `zoo_aremove_all_watches`.
pub const ZKRS_OP_REMOVE_WATCHES: u32 = 14;

/// `zkrs_request.flags`: create2 (reply with a stat).
pub const ZKRS_F_CREATE2: u32 = 0x01;
/// `zkrs_request.flags`: the path gets no chroot prefix (getconfig).
#[allow(dead_code, reason = "the C shim reads it through zkrs.h")]
pub const ZKRS_F_RAW_PATH: u32 = 0x02;
/// `zkrs_request.flags`: remove all watches.
pub const ZKRS_F_REMOVE_ALL: u32 = 0x04;
/// `zkrs_request.flags`: local remove-watches.
pub const ZKRS_F_LOCAL: u32 = 0x08;
/// `zkrs_add_auth` flags: the shim could not allocate the request.
pub const ZKRS_AUTH_F_ALLOC_FAILED: u32 = 0x01;
/// `*rc` at the SASL point of init. It is never an errno.
pub const ZKRS_INIT_SASL_POINT: i32 = -1;

/// `zkrs_sockaddr_view.family` of an IPv4 address.
pub const ZKRS_AF_INET: u32 = 4;
/// `zkrs_sockaddr_view.family` of an IPv6 address.
pub const ZKRS_AF_INET6: u32 = 6;

/// Log argument: `int64_t i`.
pub const ZKRS_ARG_I64: u32 = 0;
/// Log argument: `uint64_t u`.
pub const ZKRS_ARG_U64: u32 = 1;
/// Log argument: `uintptr_t p`.
pub const ZKRS_ARG_PTR: u32 = 2;
/// Log argument: `zkrs_str s`.
pub const ZKRS_ARG_STR: u32 = 3;
/// Log argument: `zkrs_sockaddr_view ep`.
pub const ZKRS_ARG_ENDPOINT: u32 = 4;
/// Log argument: `strerror(err)`.
pub const ZKRS_ARG_ERRNO_STR: u32 = 5;
/// Log argument: the resolver text of `gai_rc` and `err`.
pub const ZKRS_ARG_GAI_STR: u32 = 6;

/// The outbox of one driving call, on the C stack.
///
/// `impl` is NULL until Rust stores the first item. Only Rust reads it.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct zkrs_outbox {
    /// The Rust outbox, or NULL.
    pub r#impl: *mut c_void,
}

/// A NUL-terminated string view. `ptr` is NULL for a jute null string.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct zkrs_str {
    /// The bytes, with `ptr[len] == 0`, or NULL.
    pub ptr: *const c_char,
    /// The length without the NUL.
    pub len: i32,
}

/// A byte buffer view. `len` is -1 for null znode data.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct zkrs_buf {
    /// The bytes, or NULL.
    pub ptr: *const c_char,
    /// The length, or -1.
    pub len: i32,
}

/// The fields of `struct Stat`, in a fixed layout. The writers
/// copy it field by field into the public record.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct zkrs_stat {
    /// `czxid`.
    pub czxid: i64,
    /// `mzxid`.
    pub mzxid: i64,
    /// `ctime`.
    pub ctime: i64,
    /// `mtime`.
    pub mtime: i64,
    /// `version`.
    pub version: i32,
    /// `cversion`.
    pub cversion: i32,
    /// `aversion`.
    pub aversion: i32,
    /// `ephemeralOwner`.
    pub ephemeralOwner: i64,
    /// `dataLength`.
    pub dataLength: i32,
    /// `numChildren`.
    pub numChildren: i32,
    /// `pzxid`.
    pub pzxid: i64,
}

/// One ACL entry of a result view.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct zkrs_acl_view {
    /// The permission bits.
    pub perms: i32,
    /// The scheme.
    pub scheme: zkrs_str,
    /// The id.
    pub id: zkrs_str,
}

/// One sub-result of a multi view.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct zkrs_multi_op {
    /// The sub-op error.
    pub err: i32,
    /// 1 for an error result.
    pub failed: i32,
    /// The stripped path of a create, or NULL.
    pub path: zkrs_str,
    /// The stat of a set, or NULL.
    pub stat: *const zkrs_stat,
}

/// A log argument. `kind` tells which field holds the value.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct zkrs_log_arg {
    /// `ZKRS_ARG_*`.
    pub kind: u32,
    /// `ZKRS_ARG_I64`.
    pub i: i64,
    /// `ZKRS_ARG_U64`.
    pub u: u64,
    /// `ZKRS_ARG_PTR`.
    pub p: usize,
    /// `ZKRS_ARG_STR`.
    pub s: zkrs_str,
    /// `ZKRS_ARG_ENDPOINT`.
    pub ep: zkrs_sockaddr_view,
    /// `ZKRS_ARG_GAI_STR`.
    pub gai_rc: i32,
    /// `ZKRS_ARG_GAI_STR` and `ZKRS_ARG_ERRNO_STR`.
    pub err: i32,
}

/// A log line of the core. C renders the pinned format of
/// `site` with `args`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct zkrs_log_view {
    /// `ZOO_LOG_LEVEL_*`.
    pub level: u32,
    /// The site id: the index in `zk_proto::LogSite::ALL`.
    pub site: u32,
    /// The wall-clock seconds that zk-ffi stamped.
    pub tv_sec: i64,
    /// The microseconds of the stamp.
    pub tv_usec: i32,
    /// The arguments, in format order.
    pub args: *const zkrs_log_arg,
    /// The number of arguments.
    pub nargs: u32,
}

/// The view of a completion.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct zkrs_result_view {
    /// `ZKRS_K_*` of the request.
    pub kind: u32,
    /// `ZKRS_ORIGIN_*`.
    pub origin: u32,
    /// The legacy rc.
    pub rc: i32,
    /// 1 when no body was decoded.
    pub failed: i32,
    /// DATA: the node data.
    pub data: zkrs_buf,
    /// The stat, or NULL.
    pub stat: *const zkrs_stat,
    /// STRING: the stripped path.
    pub path: zkrs_str,
    /// STRINGLIST: the children.
    pub children: *const zkrs_str,
    /// The number of children, or -1 for a jute null vector.
    pub nchildren: i32,
    /// ACLLIST: the entries.
    pub acl: *const zkrs_acl_view,
    /// The number of ACL entries, or -1.
    pub nacl: i32,
    /// MULTI: the sub-results.
    pub ops: *const zkrs_multi_op,
    /// The number of sub-results.
    pub nops: i32,
    /// The delivery lines, emitted before the callback.
    pub delivery_logs: *const zkrs_log_view,
    /// The number of delivery lines.
    pub n_delivery_logs: u32,
}

/// One watcher: the application `(watcher_fn, void *)` pair.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct zkrs_watcher {
    /// The `watcher_fn` value.
    pub r#fn: usize,
    /// The context value.
    pub ctx: usize,
}

/// The view of a node or session event.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct zkrs_watch_event_view {
    /// The event type. `ZOO_SESSION_EVENT` is -1.
    pub r#type: i32,
    /// The state.
    pub state: i32,
    /// The stripped path. `""` for a session event.
    pub path: zkrs_str,
    /// The watchers, in delivery order.
    pub list: *const zkrs_watcher,
    /// The number of watchers.
    pub n: u32,
    /// The delivery lines, emitted before the callbacks.
    pub delivery_logs: *const zkrs_log_view,
    /// The number of delivery lines.
    pub n_delivery_logs: u32,
}

/// One outbox item. Only the members of `type` are valid.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct zkrs_item {
    /// `zkrs_item_type`.
    pub r#type: u32,
    /// LOG.
    pub log: *const zkrs_log_view,
    /// RESULT: the token. Ownership passes to C.
    pub token: usize,
    /// RESULT.
    pub result: *const zkrs_result_view,
    /// WATCH.
    pub watch: *const zkrs_watch_event_view,
    /// SASL.
    pub sasl: *const zkrs_sasl_call,
    /// THREAD: `zkrs_thread_op`.
    pub thread_op: u32,
    /// THREAD: `ZKRS_ROLE_IO` or `ZKRS_ROLE_DISPATCH`.
    pub thread_role: u32,
}

/// One request from a `zoo_a*` entry point.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct zkrs_request {
    /// `ZKRS_OP_*`.
    pub op: u32,
    /// `ZKRS_F_*`.
    pub flags: u32,
    /// The application path, or NULL.
    pub path: *const c_char,
    /// The value buffer.
    pub data: *const c_char,
    /// The value length.
    pub datalen: i32,
    /// Create and set ACL: `const struct ACL_vector *`, or NULL.
    pub acl: *const c_void,
    /// The create mode.
    pub mode: i32,
    /// The create TTL.
    pub ttl: i64,
    /// The version.
    pub version: i32,
    /// The reconfig version.
    pub reconfig_version: i64,
    /// Reconfig: joining servers, or NULL.
    pub joining: *const c_char,
    /// Reconfig: leaving servers, or NULL.
    pub leaving: *const c_char,
    /// Reconfig: new members, or NULL.
    pub members: *const c_char,
    /// The watcher function, or 0.
    pub watch_fn: usize,
    /// The watcher context.
    pub watch_ctx: usize,
    /// Remove-watches: the watcher type.
    pub wtype: i32,
    /// Multi: `const zoo_op_t *`, the array of the caller.
    pub ops: *const c_void,
    /// Multi: the length of the prefix.
    pub ops_len: i32,
    /// Multi: the original count.
    pub count: i32,
}

/// The outputs of `zkrs_interest`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct zkrs_interest_out {
    /// The socket, or -1.
    pub fd: isize,
    /// `ZOOKEEPER_READ | ZOOKEEPER_WRITE`.
    pub interest: i32,
    /// The timeout in milliseconds.
    pub timeout_ms: i64,
}

/// A socket address in a fixed layout.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct zkrs_sockaddr_view {
    /// 0 (none), `ZKRS_AF_INET` or `ZKRS_AF_INET6`.
    pub family: u32,
    /// The port in host byte order.
    pub port: u16,
    /// The address in network byte order. IPv4 uses the first 4 bytes.
    pub addr: [u8; 16],
    /// IPv6 only.
    pub flowinfo: u32,
    /// IPv6 only.
    pub scope_id: u32,
}

/// The arguments of `zkrs_handle_new`. The strings are
/// borrowed for the call.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct zkrs_init_args {
    /// `ZKRS_FLAVOR_*`.
    pub flavor: u32,
    /// The host string.
    pub hosts: *const c_char,
    /// The session timeout.
    pub recv_timeout: i32,
    /// 1 when the caller gave a client id.
    pub have_client_id: u32,
    /// The session id.
    pub client_id: i64,
    /// The session password.
    pub client_passwd: [u8; 16],
    /// The raw init flags.
    pub flags: i32,
    /// 1 only from `zookeeper_init_ssl`.
    pub tls: u32,
    /// TLS CA path.
    pub tls_ca: *const c_char,
    /// TLS certificate path.
    pub tls_cert: *const c_char,
    /// TLS key path.
    pub tls_key: *const c_char,
    /// TLS key passphrase.
    pub tls_passwd: *const c_char,
    /// 1 when Rust may read `SSL_CERT_FILE` and `SSL_CERT_DIR`.
    pub tls_env_allowed: u32,
    /// 1 when `zookeeper_init_sasl` got parameters.
    pub sasl: u32,
    /// The xid seed, `(int32_t)time(0)`.
    pub xid_seed: i32,
    /// The `SOCK_CLOEXEC_ENABLED` build option.
    pub sock_cloexec: u32,
    /// 1 when `char` is signed in the shim compiler.
    pub c_char_signed: u32,
}

/// The services that C gives to Rust. Pure entries never block.
/// Blocking entries run with no Rust lock held. No entry reaches
/// application code.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct zkrs_host_vtable {
    /// Pure. Frees a `zks_req` without a callback.
    pub discard_token: Option<unsafe extern "C" fn(token: usize)>,
    /// Pure. Reads the default watcher pair.
    pub snapshot_default_watcher: Option<unsafe extern "C" fn(host: usize, out: *mut zkrs_watcher)>,
    /// Pure. Stores the session id and password in `zh->client_id`.
    pub store_client_id: Option<unsafe extern "C" fn(host: usize, id: i64, passwd: *const u8)>,
    /// Pure. The `logLevel` rule of the legacy macros.
    pub log_enabled: Option<unsafe extern "C" fn(level: u32) -> c_int>,
    /// Pure. `zoo_deterministic_conn_order`.
    pub conn_permute_disabled: Option<unsafe extern "C" fn() -> c_int>,
    /// Pure. libc `random()`.
    pub rng_random: Option<unsafe extern "C" fn() -> c_long>,
    /// Pure. libc `drand48()`.
    pub rng_drand48: Option<unsafe extern "C" fn() -> c_double>,
    /// Blocking. The legacy reseed.
    pub rng_reseed: Option<unsafe extern "C" fn()>,
    /// Blocking. `getaddrinfo` for one host entry. Returns the errno.
    #[allow(clippy::type_complexity, reason = "the C prototype names no typedef")]
    pub resolve: Option<
        unsafe extern "C" fn(
            name: *const c_char,
            port: *const c_char,
            gai_rc: *mut i32,
            push: Option<unsafe extern "C" fn(sink: *mut c_void, addr: *const zkrs_sockaddr_view)>,
            skip: Option<unsafe extern "C" fn(sink: *mut c_void, family: i32)>,
            sink: *mut c_void,
        ) -> c_int,
    >,
}

/// Writer destinations. NULL means "not wanted".
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct zkrs_result_dst {
    /// `struct Stat *`.
    pub stat: *mut c_void,
    /// DATA: the `malloc` copy.
    pub value: *mut *mut c_char,
    /// DATA: the length, or -1.
    pub value_len: *mut i32,
    /// `struct String_vector *`.
    pub strings: *mut c_void,
    /// `struct ACL_vector *`.
    pub acl: *mut c_void,
    /// STRING: the `malloc` copy of the stripped path.
    pub str: *mut *mut c_char,
    /// STRING: the length.
    pub str_len: *mut i32,
    /// MULTI into a sync record: the per-op copies.
    pub ops: *mut *mut zkrs_multi_copy,
    /// MULTI into a sync record: the number of copies.
    pub nops: *mut i32,
}

/// One sub-result copy in a sync record.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct zkrs_multi_copy {
    /// The sub-op error.
    pub err: i32,
    /// 1 for an error result.
    pub failed: i32,
    /// A `malloc` copy of the path, or NULL.
    pub path: *mut c_char,
    /// The path length.
    pub path_len: i32,
    /// 1 when `stat` is valid.
    pub has_stat: u32,
    /// The stat of a set.
    pub stat: zkrs_stat,
}

/// The reply image of a sync record.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct zkrs_sync_src {
    /// `ZKRS_K_*` of the wrapper.
    pub kind: u32,
    /// The rc.
    pub rc: i32,
    /// 1 when no body was decoded.
    pub failed: i32,
    /// `ZKRS_ORIGIN_*`.
    pub origin: i32,
    /// DATA: the record copy.
    pub data: *const c_char,
    /// DATA: the length, or -1.
    pub data_len: i32,
    /// STRING: the record copy.
    pub path: *const c_char,
    /// STRING: the length.
    pub path_len: i32,
    /// `const struct Stat *` of the record.
    pub stat: *const c_void,
    /// MULTI: the per-op copies.
    pub ops: *const zkrs_multi_copy,
    /// MULTI: the number of copies.
    pub nops: i32,
    /// MULTI: the per-op writer kinds.
    pub op_kind: *const u8,
}

/// The caller outputs of a sync wrapper. NULL where the wrapper
/// has none.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct zkrs_sync_dst {
    /// DATA: the caller buffer.
    pub buffer: *mut c_char,
    /// DATA: the capacity in, the length out.
    pub buffer_len: *mut i32,
    /// STRING: the caller path buffer.
    pub path_buffer: *mut c_char,
    /// STRING: the capacity.
    pub path_buffer_len: i32,
    /// `struct Stat *`.
    pub stat: *mut c_void,
    /// MULTI: `zoo_op_result_t[]`.
    pub results: *mut c_void,
    /// MULTI: the count.
    pub count: i32,
}

impl zkrs_str {
    /// The jute null string.
    #[must_use]
    pub const fn null() -> Self {
        Self {
            ptr: ptr::null(),
            len: 0,
        }
    }
}

impl zkrs_buf {
    /// Null znode data.
    #[must_use]
    pub const fn null() -> Self {
        Self {
            ptr: ptr::null(),
            len: -1,
        }
    }
}

impl zkrs_item {
    /// An item with every member zero. The outbox fills `type` and the
    /// members of that type.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            r#type: 0,
            log: ptr::null(),
            token: 0,
            result: ptr::null(),
            watch: ptr::null(),
            sasl: ptr::null(),
            thread_op: 0,
            thread_role: 0,
        }
    }
}

impl zkrs_sockaddr_view {
    /// No address (`family == 0`).
    #[must_use]
    pub const fn none() -> Self {
        Self {
            family: 0,
            port: 0,
            addr: [0; 16],
            flowinfo: 0,
            scope_id: 0,
        }
    }

    /// Makes the view of an address. `None` gives [`Self::none`].
    #[must_use]
    pub fn from_addr(a: Option<SocketAddr>) -> Self {
        match a {
            None => Self::none(),
            Some(SocketAddr::V4(v4)) => {
                let mut addr = [0u8; 16];
                let (head, _) = addr.split_at_mut(4);
                head.copy_from_slice(&v4.ip().octets());
                Self {
                    family: ZKRS_AF_INET,
                    port: v4.port(),
                    addr,
                    flowinfo: 0,
                    scope_id: 0,
                }
            }
            Some(SocketAddr::V6(v6)) => Self {
                family: ZKRS_AF_INET6,
                port: v6.port(),
                addr: v6.ip().octets(),
                flowinfo: v6.flowinfo(),
                scope_id: v6.scope_id(),
            },
        }
    }

    /// Reads the view back. An unknown family gives `None`.
    #[must_use]
    pub fn to_addr(self) -> Option<SocketAddr> {
        match self.family {
            ZKRS_AF_INET => {
                let [a, b, c, d, ..] = self.addr;
                Some(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::new(a, b, c, d),
                    self.port,
                )))
            }
            ZKRS_AF_INET6 => Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(self.addr),
                self.port,
                self.flowinfo,
                self.scope_id,
            ))),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sockaddr_view_round_trips_both_families() {
        let v4: SocketAddr = "10.1.2.3:2181".parse().unwrap_or_else(|_| unreachable!());
        let v = zkrs_sockaddr_view::from_addr(Some(v4));
        assert_eq!(v.family, ZKRS_AF_INET);
        assert_eq!(v.addr[..4], [10, 1, 2, 3]);
        assert_eq!(v.to_addr(), Some(v4));
        let v6 = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 2182, 7, 9));
        let w = zkrs_sockaddr_view::from_addr(Some(v6));
        assert_eq!(w.family, ZKRS_AF_INET6);
        assert_eq!(w.to_addr(), Some(v6));
        assert_eq!(zkrs_sockaddr_view::from_addr(None).to_addr(), None);
    }

    #[test]
    fn enum_values_match_the_header_table() {
        assert_eq!(zkrs_step::ZKRS_EXIT as u32, 3);
        assert_eq!(zkrs_item_type::ZKRS_ITEM_THREAD as u32, 6);
        assert_eq!(zkrs_thread_op::ZKRS_THREAD_DETACH as u32, 2);
        assert_eq!(zkrs_status::ZKRS_SYSTEM as u32, 7);
    }
}
