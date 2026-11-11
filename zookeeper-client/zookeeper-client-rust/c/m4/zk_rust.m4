# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This file holds the autotools logic of the Rust client core. The
# common configure.ac includes this file and calls
# ZK_RUST_CLIENT once. rust.am uses the results.

# ZK_RUST_C_DIR
# -------------
# The Rust C tree, as a path relative to configure.ac.
# autoconf reads this file through m4_include, so the file name gives the
# directory. Thus only the configure.ac hook names the location.
m4_define([ZK_RUST_C_DIR], m4_bpatsubst(__file__, [/m4/zk_rust\.m4$]))

# ZK_RUST_CLIENT
# --------------
# Defines --with-rust-client and the Rust-only options, selects the
# client core and configures the Rust core. configure.ac calls it after
# the legacy OpenSSL and SASL probes. The macro defines every conditional
# of rust.am in each mode, because automake needs them on every configure
# run. In legacy mode, the macro only defines the conditionals and checks
# the Rust-only options.
AC_DEFUN([ZK_RUST_CLIENT], [
dnl zk_rust_c_dir is the Rust C tree, as a path from the build directory.
dnl The ABI and public-API tests are a separate subtree. Without it, rust.am
dnl defines no test targets.
AS_CASE([ZK_RUST_C_DIR], [/*], [zk_rust_c_dir='ZK_RUST_C_DIR'],
  [zk_rust_c_dir="$srcdir/ZK_RUST_C_DIR"])
AM_CONDITIONAL([ZKRS_TESTS], [test -d "$zk_rust_c_dir/tests"])
dnl The legacy OpenSSL probe changes with_openssl, CPPFLAGS and LDFLAGS.
dnl This text runs before the probe and keeps the values that the user
dnl gave. Nothing in configure.ac changes CPPFLAGS or LDFLAGS before the
dnl probe, so these are also the values before the probe.
m4_divert_text([INIT_PREPARE], [zk_user_with_openssl=${with_openssl-yes}
zk_rust_init_CPPFLAGS=$CPPFLAGS
zk_rust_init_LDFLAGS=$LDFLAGS])
dnl This option selects the client core. Without it, the build uses the
dnl legacy core. zk_rust_client_default records that the user gave no value.
AC_ARG_WITH([rust-client],
 [AS_HELP_STRING([--with-rust-client=no|yes|auto],[client core implementation [default=no]])],
 [AS_CASE([$withval], [true], [with_rust_client=yes])],
 [with_rust_client=no; zk_rust_client_default=yes])
dnl Each Rust-only option that is given records zk_rust_requested_by.
AC_ARG_WITH([rust-workspace],
 [AS_HELP_STRING([--with-rust-workspace=DIR],[Rust workspace, with the same shim as the drop-in sources (default: the parent of ]ZK_RUST_C_DIR[)])],
 [AS_IF([test "x$withval" != xauto], [zk_rust_requested_by=${zk_rust_requested_by:-"--with-rust-workspace=$withval"}])],
 [with_rust_workspace=auto])
AC_ARG_WITH([rust-staticlib],
 [AS_HELP_STRING([--with-rust-staticlib=PATH],[link this prebuilt libzk_ffi.a; make does not run cargo])],
 [zk_rust_requested_by=${zk_rust_requested_by:-"--with-rust-staticlib=$withval"}])
AC_ARG_WITH([rust-target],
 [AS_HELP_STRING([--with-rust-target=TRIPLE],[pass --target TRIPLE to cargo (required for cross builds)])],
 [zk_rust_requested_by=${zk_rust_requested_by:-"--with-rust-target=$withval"}])
dnl The TLS options of the Rust core. ZK_RUST_TLS_CONFIG
dnl applies them. Only --with-rust-tls=yes is a request. A provider that is
dnl given, ring included, is a request.
AC_ARG_WITH([rust-tls],
 [AS_HELP_STRING([--with-rust-tls=yes|no],[build TLS into the Rust client also without OpenSSL headers [default=no]])],
 [AS_IF([test "x$withval" = xyes], [zk_rust_requested_by=${zk_rust_requested_by:-"--with-rust-tls=yes"}])],
 [with_rust_tls=no])
AC_ARG_WITH([rust-tls-provider],
 [AS_HELP_STRING([--with-rust-tls-provider=ring|aws-lc-rs|aws-lc-rs-fips],[the rustls crypto provider of the Rust client [default=ring]])],
 [zk_rust_provider_given=yes
  zk_rust_requested_by=${zk_rust_requested_by:-"--with-rust-tls-provider=$withval"}],
 [with_rust_tls_provider=ring])
AC_ARG_WITH([rust-tls-default-paths],
 [AS_HELP_STRING([--with-rust-tls-default-paths=FILE:DIR],[the default trust file and directory of the Rust client (default: the OPENSSLDIR of the probed OpenSSL, else the platform list)])],
 [zk_rust_requested_by=${zk_rust_requested_by:-"--with-rust-tls-default-paths=$withval"}],
 [with_rust_tls_default_paths=auto])
dnl The crate sources of cargo. ZK_RUST_CRATE_SOURCES applies them. An
dnl empty value is not a request, because Maven always gives the options.
AC_ARG_WITH([cargo-vendor],
 [AS_HELP_STRING([--with-cargo-vendor=DIR],[build the Rust client offline with the crates of a cargo vendor directory])],
 [AS_CASE([$withval], [no], [with_cargo_vendor=],
   [?*], [zk_rust_requested_by=${zk_rust_requested_by:-"--with-cargo-vendor=$withval"}])],
 [with_cargo_vendor=])
AC_ARG_WITH([system-rust-crates],
 [AS_HELP_STRING([--with-system-rust-crates@<:@=DIR@:>@],[build the Rust client offline with the system crates of DIR (default DIR: /usr/share/cargo/registry)])],
 [AS_CASE([$withval], [no], [with_system_rust_crates=],
   [yes], [with_system_rust_crates=/usr/share/cargo/registry])
  AS_IF([test -n "$with_system_rust_crates"],
   [zk_rust_requested_by=${zk_rust_requested_by:-"--with-system-rust-crates=$with_system_rust_crates"}])],
 [with_system_rust_crates=])
AC_ARG_ENABLE([werror],
 [AS_HELP_STRING([--disable-werror],[do not add -Werror to the Rust client shim flags])],
 [], [enable_werror=yes])
AC_ARG_VAR([CARGO],[the cargo command of the Rust client build])
AC_ARG_VAR([RUSTC],[the rustc command of the Rust client build])
dnl The option and the host check select the core. Each build has exactly
dnl one core, so configure rejects all other values.
AS_CASE([$with_rust_client], [no|yes|auto], [],
  [AC_MSG_ERROR([--with-rust-client must be no, yes or auto, not $with_rust_client])])
AS_IF([test "x$with_rust_client" != xno && test -n "$with_cargo_vendor" && test -n "$with_system_rust_crates"],
  [AC_MSG_ERROR([give only one of --with-cargo-vendor and --with-system-rust-crates])])
AS_IF([test "x$with_rust_client" != xno && test "x$with_cargo_vendor" = xyes],
  [AC_MSG_ERROR([--with-cargo-vendor needs a directory: give --with-cargo-vendor=DIR])])
ZKRS_CARGO_SOURCE_ARGS=
ZKRS_CARGO_SOURCE_CONFIG=
AS_IF([test "x$with_rust_client" != xno], [ZK_RUST_CHECK])
AS_CASE([$with_rust_client],
  [no], [AS_IF([test "x$zk_rust_client_default" = xyes && test -n "$zk_rust_requested_by"],
    [AC_MSG_ERROR([$zk_rust_requested_by needs --with-rust-client=yes])])],
  [yes], [AS_IF([test "x$zk_rust_ok" != xyes],
    [AC_MSG_ERROR([--with-rust-client=$with_rust_client: $zk_rust_why; --with-rust-client=no builds the legacy C client])])],
  [auto], [AS_IF([test "x$zk_rust_ok" = xyes], [with_rust_client=yes],
    [test -n "$zk_rust_requested_by"],
      [AC_MSG_ERROR([$zk_rust_requested_by needs the Rust client, which this host cannot build: $zk_rust_why])],
    [AC_MSG_NOTICE([building the legacy C client: $zk_rust_why]); with_rust_client=no])])
AM_CONDITIONAL([RUST_CLIENT], [test "x$with_rust_client" != xno])
AM_CONDITIONAL([LEGACY_CLIENT], [test "x$with_rust_client" = xno])
AM_CONDITIONAL([ZKRS_PREBUILT], [test "x$with_rust_client" != xno && test -n "$with_rust_staticlib"])
dnl rust.am gives these DIR flags back to the programs. They are empty
dnl with the legacy core.
ZK_OPENSSL_DIR_CPPFLAGS=
ZK_SASL_DIR_CPPFLAGS=
zk_rust_tls=no
zk_rust_sasl=no
AS_IF([test "x$with_rust_client" != xno], [
  AC_MSG_NOTICE([building the Rust client core from $RUST_WORKSPACE])
  dnl The -I and -L flags of the OpenSSL probe never reach the shim or the
  dnl Rust link. The -I flag of the SASL probe moves to
  dnl ZK_SASL_DIR_CPPFLAGS. The Cyrus glue gets the directory as -isystem.
  dnl The -L flag of the SASL probe stays.
  AS_IF([test "x$have_sasl" = xyes && test "x$with_sasl" != xno && test "x$with_sasl" != xyes],
    [AS_CASE([$CPPFLAGS], [*" -I$with_sasl/include"],
      [CPPFLAGS=${CPPFLAGS%" -I$with_sasl/include"}
       ZK_SASL_DIR_CPPFLAGS="-I$with_sasl/include"])])
  dnl with_openssl is a directory only when the probe passes with that
  dnl directory. Then the probe appends its flags to the initial values.
  AS_CASE([$with_openssl], [yes|no], [], [
    zk_rust_post="$zk_rust_init_CPPFLAGS -I$with_openssl/include"
    AS_CASE([$CPPFLAGS], ["$zk_rust_post"*],
      [CPPFLAGS=$zk_rust_init_CPPFLAGS${CPPFLAGS@%:@"$zk_rust_post"}])
    zk_rust_post="$zk_rust_init_LDFLAGS -L$with_openssl/lib"
    AS_CASE([$LDFLAGS], ["$zk_rust_post"*],
      [LDFLAGS=$zk_rust_init_LDFLAGS${LDFLAGS@%:@"$zk_rust_post"}])])
  dnl RUST_TARGET is the option, else the host triple of rustc.
  AS_IF([test -n "$with_rust_target"],
    [RUST_TARGET=$with_rust_target; ZKRS_TARGET_ARGS="--target $RUST_TARGET"],
    [RUST_TARGET=`"$RUSTC" -vV | sed -n 's/^host: //p'`; ZKRS_TARGET_ARGS=])
  RUST_TARGET_ENV=`echo "$RUST_TARGET" | tr '.-' '__'`
  ZKRS_PROFILE=capi
  ZKS_FEATURE_CPPFLAGS=
  AS_IF([test "x$enable_debug" = xyes],
    [ZKRS_PROFILE=capi-dev; ZKS_FEATURE_CPPFLAGS=-DZKS_HANDLE_REGISTRY])
  AS_IF([test -n "$with_rust_staticlib"],
    [ZKRS_STATICLIB=`cd "$(dirname "$with_rust_staticlib")" && pwd`/`basename "$with_rust_staticlib"`],
    [test -n "$with_rust_target"],
    [ZKRS_STATICLIB='$(abs_builddir)/cargo/$(RUST_TARGET)/$(ZKRS_PROFILE)/libzk_ffi.a'],
    [ZKRS_STATICLIB='$(abs_builddir)/cargo/$(ZKRS_PROFILE)/libzk_ffi.a'])
  AS_IF([test "x$enable_werror" != xno], [ZKS_WERROR=-Werror], [ZKS_WERROR=])
  AS_CASE([$host_os],
    [darwin*], [ZKRS_GC_LDFLAGS=-Wl,-dead_strip],
    [ZKRS_GC_LDFLAGS=-Wl,--gc-sections
     AC_CHECK_TOOL([OBJCOPY], [objcopy])
     AS_IF([test -z "$OBJCOPY"], [AC_MSG_ERROR([the Rust client pre-link needs objcopy])])])
  ZK_RUST_PROBE
  ZK_RUST_TLS_CONFIG
  dnl These values give the feature flags of gen-exports.awk and the golden
  dnl configuration of the ABI checks.
  AS_IF([test "x$zk_rust_tls" = xyes], [HAVE_SSL01=1], [HAVE_SSL01=0])
  AS_IF([test "x$zk_rust_sasl" = xyes], [HAVE_SASL01=1], [HAVE_SASL01=0])
  AS_CASE([$HAVE_SSL01$HAVE_SASL01],
    [00], [ZKRS_ABI_CONFIG=plain], [10], [ZKRS_ABI_CONFIG=ssl],
    [01], [ZKRS_ABI_CONFIG=sasl], [ZKRS_ABI_CONFIG=full])
])
AC_SUBST([RUST_WORKSPACE]) AC_SUBST([RUST_TARGET]) AC_SUBST([RUST_TARGET_ENV])
AC_SUBST([ZKRS_TARGET_ARGS]) AC_SUBST([ZKRS_PROFILE]) AC_SUBST([ZKRS_STATICLIB])
AC_SUBST([ZKRS_CARGO_SOURCE_ARGS]) AC_SUBST([ZKRS_CARGO_SOURCE_CONFIG])
AC_SUBST([ZKRS_NATIVE_LIBS]) AC_SUBST([ZKRS_GC_LDFLAGS]) AC_SUBST([ZKS_FEATURE_CPPFLAGS])
AC_SUBST([ZKS_CFLAGS]) AC_SUBST([ZKS_HARDEN_CFLAGS]) AC_SUBST([ZKS_WERROR])
AC_SUBST([ZKRS_CARGO_FEATURES]) AC_SUBST([ZKS_CONFIG_CPPFLAGS]) AC_SUBST([ZKRS_SASL_LIBS])
AC_SUBST([ZKS_SASL_CFLAGS]) AC_SUBST([ZK_TLS_DEFAULT_CERT_FILE]) AC_SUBST([ZK_TLS_DEFAULT_CERT_DIR])
AC_SUBST([ZKS_HARDEN_SASL_CFLAGS]) AC_SUBST([ZK_OPENSSL_DIR_CPPFLAGS])
AC_SUBST([ZK_SASL_DIR_CPPFLAGS]) AC_SUBST([HAVE_SSL01]) AC_SUBST([HAVE_SASL01]) AC_SUBST([ZKRS_ABI_CONFIG])
AM_CONDITIONAL([RUST_TLS], [test "x$zk_rust_tls" = xyes])
AM_CONDITIONAL([RUST_SASL], [test "x$zk_rust_sasl" = xyes])
dnl With --with-rust-client=yes, WANT_OPENSSL gives HAVE_OPENSSL_H to the
dnl programs only when they can see the OpenSSL headers. The legacy core
dnl keeps the legacy rule.
AS_IF([test "x$with_rust_client" = xyes], [zk_want_openssl=$zk_rust_cli_ssl],
  [test "x$with_openssl" != xno], [zk_want_openssl=yes], [zk_want_openssl=no])
AM_CONDITIONAL([WANT_OPENSSL], [test "x$zk_want_openssl" = xyes])
dnl This text makes the pkg-config files. Only the Rust core makes and
dnl installs them, so the legacy install does not change. Libs.private has
dnl each link library of the flavor once. The text runs at the end of
dnl configure, because it needs CLOCK_GETTIME_LIBS.
AC_CONFIG_COMMANDS_PRE([
AS_IF([test "x$with_rust_client" = xyes], [
  AS_IF([test "x$HAVE_SASL01" = x1], [zk_pc_sasl=-lsasl2], [zk_pc_sasl=])
  for zk_pc_fl in st mt; do
    zk_pc_all="-lm $CLOCK_GETTIME_LIBS"
    AS_IF([test $zk_pc_fl = mt], [zk_pc_all="$zk_pc_all -lpthread"])
    zk_pc_out=
    for zk_pc_l in $zk_pc_all $ZKRS_NATIVE_LIBS $zk_pc_sasl; do
      AS_CASE([" $zk_pc_out "], [*" $zk_pc_l "*], [],
        [zk_pc_out="${zk_pc_out:+$zk_pc_out }$zk_pc_l"])
    done
    eval "ZKRS_PC_PRIVATE_$zk_pc_fl=\$zk_pc_out"
  done
  AC_CONFIG_FILES([zookeeper_st.pc:]ZK_RUST_C_DIR[/zookeeper_st.pc.in zookeeper_mt.pc:]ZK_RUST_C_DIR[/zookeeper_mt.pc.in])
])])
AC_SUBST([ZKRS_PC_PRIVATE_st]) AC_SUBST([ZKRS_PC_PRIVATE_mt])
])

# ZK_RUST_CHECK
# -------------
# Decides whether this host can build the Rust client core.
# The macro sets zk_rust_ok to yes or no. When the check fails, zk_rust_why
# names the first condition that failed. When the check passes, the macro
# sets RUST_WORKSPACE, RUSTC, CARGO and ZKRS_CARGO_SOURCE_ARGS. A prebuilt
# staticlib needs no cargo.
# TLS and SASL do not affect the check. ZK_RUST_TLS_CONFIG selects them.
# --without-syncapi passes: the Rust core then builds only the st library,
# as the legacy core does.
AC_DEFUN([ZK_RUST_CHECK], [
zk_rust_ok=yes
zk_rust_why=
AC_PATH_PROG([RUSTC], [rustc])
AC_PATH_PROG([CARGO], [cargo])
AC_MSG_CHECKING([whether this host can build the Rust client])
AS_CASE([$host_os],
  [cygwin*], [zk_rust_ok=no; zk_rust_why="the Rust client does not support Cygwin"])
dnl The workspace is the option, else the parent of the Rust C tree.
dnl rust.am compiles the shim of the Rust C tree. cargo builds zk-ffi from
dnl the workspace. Thus another workspace must have the same zkrs.h, so
dnl that the shim and the staticlib agree.
AS_IF([test "x$zk_rust_ok" = xyes], [
  AS_IF([test "x$with_rust_workspace" != xauto && test -n "$with_rust_workspace"],
    [zk_rust_ws=$with_rust_workspace],
    [zk_rust_ws=$zk_rust_c_dir/..])
  AS_IF([test -f "$zk_rust_ws/Cargo.toml"],
    [RUST_WORKSPACE=`cd "$zk_rust_ws" && pwd`],
    [zk_rust_ok=no; zk_rust_why="no Rust workspace at $zk_rust_ws (give --with-rust-workspace=DIR)"])
])
AS_IF([test "x$zk_rust_ok" = xyes], [
  zk_rust_ws_phys=`cd "$RUST_WORKSPACE" && pwd -P`
  zk_rust_own_phys=`cd "$zk_rust_c_dir/.." && pwd -P`
  AS_IF([test "x$zk_rust_ws_phys" != "x$zk_rust_own_phys" &&
         ! cmp -s "$RUST_WORKSPACE/c/shim/zkrs.h" "$zk_rust_c_dir/shim/zkrs.h"],
    [zk_rust_ok=no
     zk_rust_why="the workspace $RUST_WORKSPACE does not have the shim header of $zk_rust_own_phys/c (give the workspace of the drop-in sources)"])
])
dnl The workspace version must equal ZOO_VERSION, as zk-ffi/build.rs checks.
AS_IF([test "x$zk_rust_ok" = xyes], [
  zk_rust_ws_version=`sed -n '/^\@<:@workspace.package\@:>@/,/^\@<:@/s/^version *= *"\(.*\)"/\1/p' "$RUST_WORKSPACE/Cargo.toml"`
  zk_rust_zoo_version=`sed -n 's/^#define ZOO_VERSION "\(.*\)"/\1/p' "$srcdir/include/zookeeper_version.h"`
  AS_IF([test "x$zk_rust_ws_version" != "x$zk_rust_zoo_version"],
    [zk_rust_ok=no
     zk_rust_why="the Rust workspace version $zk_rust_ws_version is not ZOO_VERSION $zk_rust_zoo_version"])
])
dnl The toolchain: rustc for a prebuilt staticlib, else cargo and rustc 1.85 or later.
AS_IF([test "x$zk_rust_ok" = xyes], [
  AS_IF([test -n "$with_rust_staticlib"], [
    AS_IF([test ! -f "$with_rust_staticlib"],
      [zk_rust_ok=no; zk_rust_why="the staticlib $with_rust_staticlib does not exist"],
      [test -z "$RUSTC"],
      [zk_rust_ok=no; zk_rust_why="rustc not found (needed with --with-rust-staticlib)"])
  ], [
    zk_rust_tools_ok=no
    AS_IF([test -n "$RUSTC" && test -n "$CARGO"], [
      zk_rust_v1=`"$RUSTC" --version 2>/dev/null | awk '{ split($[2], v, "."); print (v[[1]] * 1000 + v[[2]]) }'`
      zk_rust_v2=`"$CARGO" --version 2>/dev/null | awk '{ split($[2], v, "."); print (v[[1]] * 1000 + v[[2]]) }'`
      AS_IF([test -n "$zk_rust_v1" && test -n "$zk_rust_v2" &&
             test "$zk_rust_v1" -ge 1085 && test "$zk_rust_v2" -ge 1085],
        [zk_rust_tools_ok=yes])
    ])
    AS_IF([test "x$zk_rust_tools_ok" != xyes],
      [zk_rust_ok=no; zk_rust_why="cargo and rustc 1.85 or later not found"],
      [test "x$host" != "x$build" && test -z "$with_rust_target"],
      [zk_rust_ok=no; zk_rust_why="a cross build needs --with-rust-target=TRIPLE"])
  ])
])
AS_IF([test "x$zk_rust_ok" = xyes], [ZK_RUST_CRATE_SOURCES])
AS_IF([test "x$zk_rust_ok" = xyes], [AC_MSG_RESULT([yes])], [AC_MSG_RESULT([no: $zk_rust_why])])
AS_IF([test "x$zk_rust_ok" = xyes && test -n "$zk_rust_src_note"], [AC_MSG_NOTICE([$zk_rust_src_note])])
])

# ZK_RUST_CRATE_SOURCES
# ---------------------
# Checks the crate sources, the last condition of ZK_RUST_CHECK.
# Without a crate option, cargo uses its default sources, and cargo fetch
# --locked must pass. A vendor directory or a system crate directory
# replaces crates.io. The macro writes the replacement to
# cargo-sources.toml in the build directory. ZKRS_CARGO_SOURCE_CONFIG
# names that file. ZKRS_CARGO_SOURCE_ARGS gives --offline and that file to
# each cargo call of make. The make recipes do not quote these arguments,
# so the macro rejects a path with a space, a quote or a backslash.
# The source replacement changes no tracked file. System crates can have
# other versions than Cargo.lock, so system-crates mode writes the
# workspace Cargo.lock again. A prebuilt staticlib skips cargo fetch, but
# make abi-check uses the sources. On a failure, the macro sets zk_rust_ok
# and zk_rust_why, and it removes cargo-sources.toml.
AC_DEFUN([ZK_RUST_CRATE_SOURCES], [
zk_rust_src_config=`pwd`/cargo-sources.toml
rm -f "$zk_rust_src_config"
zk_rust_src_note=
zk_rust_src_opt=
zk_rust_src_dir=
AS_IF([test -n "$with_cargo_vendor"],
  [zk_rust_src_opt=--with-cargo-vendor; zk_rust_src_dir=$with_cargo_vendor],
  [test -n "$with_system_rust_crates"],
  [zk_rust_src_opt=--with-system-rust-crates; zk_rust_src_dir=$with_system_rust_crates])
AS_IF([test -n "$zk_rust_src_opt" && test -d "$zk_rust_src_dir"],
  [zk_rust_src_dir=`cd "$zk_rust_src_dir" && pwd`])
zk_rust_src_bad=no
AS_CASE([$zk_rust_src_config$zk_rust_src_dir], [*@<:@\ \"\'\\@:>@*], [zk_rust_src_bad=yes])
AS_IF([test -z "$zk_rust_src_opt"], [
  dnl cargo fetch succeeds with network access or a full CARGO_HOME.
  AS_IF([test -z "$with_rust_staticlib" &&
         ! (cd "$RUST_WORKSPACE" && "$CARGO" fetch --locked) >&AS_MESSAGE_LOG_FD 2>&1],
    [zk_rust_ok=no; zk_rust_why="no crate source: cargo fetch --locked failed"])
], [test ! -d "$zk_rust_src_dir"], [
  zk_rust_ok=no
  zk_rust_why="the crate directory $zk_rust_src_dir of $zk_rust_src_opt does not exist"
], [test -z "$CARGO"], [
  zk_rust_ok=no; zk_rust_why="cargo not found (needed with $zk_rust_src_opt)"
], [test "x$zk_rust_src_bad" = xyes], [
  zk_rust_ok=no
  zk_rust_why="the build directory or the crate directory $zk_rust_src_dir of $zk_rust_src_opt has a space, a quote or a backslash"
], [
  zk_rust_src_kind=directory
  AS_IF([test "x$zk_rust_src_opt" = x--with-system-rust-crates && test -d "$zk_rust_src_dir/index"],
    [zk_rust_src_kind=local-registry])
  {
    echo '# The crate sources of this build. configure writes this file.'
    echo '@<:@source.crates-io@:>@'
    echo 'replace-with = "zk-local"'
    echo '@<:@source.zk-local@:>@'
    echo "$zk_rust_src_kind = \"$zk_rust_src_dir\""
  } >"$zk_rust_src_config"
  ZKRS_CARGO_SOURCE_ARGS="--offline --config $zk_rust_src_config"
  ZKRS_CARGO_SOURCE_CONFIG=$zk_rust_src_config
  zk_rust_src_note="cargo runs offline with the crates of $zk_rust_src_dir ($zk_rust_src_kind)"
  AS_IF([test "x$zk_rust_src_opt" = x--with-system-rust-crates], [
    AS_IF([(cd "$RUST_WORKSPACE" && "$CARGO" generate-lockfile $ZKRS_CARGO_SOURCE_ARGS) >&AS_MESSAGE_LOG_FD 2>&1],
      [zk_rust_src_note="$zk_rust_src_note; cargo generate-lockfile wrote $RUST_WORKSPACE/Cargo.lock again"],
      [zk_rust_ok=no
       zk_rust_why="the system crates of $zk_rust_src_dir do not resolve the workspace: cargo generate-lockfile --offline failed"])
  ])
  AS_IF([test "x$zk_rust_ok" = xyes && test -z "$with_rust_staticlib" &&
         ! (cd "$RUST_WORKSPACE" && "$CARGO" fetch --locked $ZKRS_CARGO_SOURCE_ARGS) >&AS_MESSAGE_LOG_FD 2>&1],
    [zk_rust_ok=no
     zk_rust_why="the crate directory $zk_rust_src_dir of $zk_rust_src_opt does not have all crates of Cargo.lock: cargo fetch --locked --offline failed"])
])
AS_IF([test "x$zk_rust_ok" != xyes],
  [rm -f "$zk_rust_src_config"; ZKRS_CARGO_SOURCE_ARGS=; ZKRS_CARGO_SOURCE_CONFIG=])
])

# ZK_RUST_CC_FLAG(FLAG, VARIABLE)
# -------------------------------
# Appends FLAG to VARIABLE when the C compiler accepts it without a warning.
# The test compiles and links a small program with -Werror.
AC_DEFUN([ZK_RUST_CC_FLAG], [
AC_MSG_CHECKING([whether $CC accepts $1])
zk_rust_saved_CFLAGS=$CFLAGS
CFLAGS="$CFLAGS -Werror $1"
AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <stdio.h>
#include <string.h>]], [[char b[8]; snprintf(b, sizeof b, "%d", 1); return (int)strlen(b);]])],
  [AC_MSG_RESULT([yes]); $2="${$2:+$$2 }$1"; zk_rust_flag_ok=yes],
  [AC_MSG_RESULT([no]); zk_rust_flag_ok=no])
CFLAGS=$zk_rust_saved_CFLAGS
])

# ZK_RUST_PROBE
# -------------
# Probes the link and compile flags of the Rust core.
# ZKRS_NATIVE_LIBS gets the native libraries of a Rust staticlib,
# without -lc and -lSystem, which the C driver adds. ZKS_CFLAGS and
# ZKS_HARDEN_CFLAGS get the flags that the compiler accepts. The macro
# drops each hardening flag that the compiler rejects, with a notice.
AC_DEFUN([ZK_RUST_PROBE], [
AC_MSG_CHECKING([for the native libraries of a Rust staticlib])
zk_rust_tmp=`mktemp -d 2>/dev/null || echo ./conftest.rust`
mkdir -p "$zk_rust_tmp"
: >"$zk_rust_tmp/conftest.rs"
zk_rust_native=`"$RUSTC" --crate-type staticlib --crate-name conftest $ZKRS_TARGET_ARGS \
  --print native-static-libs -o "$zk_rust_tmp/libconftest.a" "$zk_rust_tmp/conftest.rs" 2>&1 |
  sed -n 's/.*native-static-libs: //p'`
rm -rf "$zk_rust_tmp"
ZKRS_NATIVE_LIBS=
for zk_rust_lib in $zk_rust_native; do
  AS_CASE([$zk_rust_lib], [-lc|-lSystem], [continue])
  AS_CASE([" $ZKRS_NATIVE_LIBS "], [*" $zk_rust_lib "*], [continue])
  ZKRS_NATIVE_LIBS="${ZKRS_NATIVE_LIBS:+$ZKRS_NATIVE_LIBS }$zk_rust_lib"
done
AC_MSG_RESULT([${ZKRS_NATIVE_LIBS:-none}])
ZKS_CFLAGS=
ZK_RUST_CC_FLAG([-fsemantic-interposition], [ZKS_CFLAGS])
ZK_RUST_CC_FLAG([-fexceptions], [ZKS_CFLAGS])
ZKS_HARDEN_CFLAGS=
ZK_RUST_CC_FLAG([-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3], [ZKS_HARDEN_CFLAGS])
AS_IF([test "x$zk_rust_flag_ok" != xyes], [
  ZK_RUST_CC_FLAG([-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2], [ZKS_HARDEN_CFLAGS])
  AS_IF([test "x$zk_rust_flag_ok" != xyes], [AC_MSG_NOTICE([dropped the hardening flag -D_FORTIFY_SOURCE])])
])
for zk_rust_flag in -fstack-protector-strong -fstack-clash-protection -ftrivial-auto-var-init=zero \
    -fno-strict-overflow -Wformat=2 -Wformat-security; do
  ZK_RUST_CC_FLAG([$zk_rust_flag], [ZKS_HARDEN_CFLAGS])
  AS_IF([test "x$zk_rust_flag_ok" != xyes], [AC_MSG_NOTICE([dropped the hardening flag $zk_rust_flag])])
done
AS_CASE([$host_cpu], [aarch64*|arm64*], [
  ZK_RUST_CC_FLAG([-mbranch-protection=standard], [ZKS_HARDEN_CFLAGS])
  AS_IF([test "x$zk_rust_flag_ok" != xyes], [AC_MSG_NOTICE([dropped the hardening flag -mbranch-protection=standard])])
])
])

# ZK_RUST_TLS_DEFAULT_PATHS
# -------------------------
# Sets ZK_TLS_DEFAULT_CERT_FILE and ZK_TLS_DEFAULT_CERT_DIR, the default
# trust locations of the Rust core. The option
# --with-rust-tls-default-paths=FILE:DIR has priority. Else the macro uses
# the OPENSSLDIR of one openssl command: DIR/bin/openssl for
# --with-openssl=DIR, else the first openssl on PATH. A PATH command never
# applies to a named installation, because it can come from a different
# library. When the command does not exist, the first directory of the
# platform list that exists gives the two values. Else both are empty.
# The macro checks the option also without TLS, but it records a default
# only with TLS. Windows hosts record nothing. The values describe the
# build host, so a cross build must give the option.
AC_DEFUN([ZK_RUST_TLS_DEFAULT_PATHS], [
ZK_TLS_DEFAULT_CERT_FILE=
ZK_TLS_DEFAULT_CERT_DIR=
zk_rust_paths_from=none
AS_CASE([$with_rust_tls_default_paths],
  [auto], [
    AS_CASE([$zk_rust_tls:$host_os], [no:*|*:mingw*|*:msys*|*:windows*], [], [
      zk_rust_ossl_bin=
      AS_CASE([$zk_user_with_openssl],
        [yes], [AC_PATH_PROG([OPENSSL_CLI], [openssl])
                zk_rust_ossl_bin=$OPENSSL_CLI],
        [no], [],
        [AS_IF([test -x "$zk_user_with_openssl/bin/openssl"],
           [zk_rust_ossl_bin=$zk_user_with_openssl/bin/openssl])])
      zk_rust_ossl_dir=
      AS_IF([test -n "$zk_rust_ossl_bin"], [
        zk_rust_ossl_dir=`"$zk_rust_ossl_bin" version -d 2>/dev/null | sed -n 's/^OPENSSLDIR: "\(.*\)"$/\1/p'`
        AS_IF([test -n "$zk_rust_ossl_dir"], [zk_rust_paths_from="$zk_rust_ossl_bin version -d"])
      ])
      AS_IF([test -z "$zk_rust_ossl_dir"], [
        for zk_rust_d in /usr/lib/ssl /etc/pki/tls /etc/ssl /usr/local/ssl \
            /usr/local/etc/openssl@3 /opt/homebrew/etc/openssl@3; do
          AS_IF([test -d "$zk_rust_d"],
            [zk_rust_ossl_dir=$zk_rust_d; zk_rust_paths_from="the platform list"; break])
        done
      ])
      AS_IF([test -n "$zk_rust_ossl_dir"], [
        ZK_TLS_DEFAULT_CERT_FILE="$zk_rust_ossl_dir/cert.pem"
        ZK_TLS_DEFAULT_CERT_DIR="$zk_rust_ossl_dir/certs"
      ])
    ])],
  [*:*:*], [AC_MSG_ERROR([--with-rust-tls-default-paths=$with_rust_tls_default_paths: give FILE:DIR with one colon])],
  [*:*], [
    ZK_TLS_DEFAULT_CERT_FILE=`echo "$with_rust_tls_default_paths" | sed 's/:.*//'`
    ZK_TLS_DEFAULT_CERT_DIR=`echo "$with_rust_tls_default_paths" | sed 's/^@<:@^:@:>@*://'`
    for zk_rust_d in "$ZK_TLS_DEFAULT_CERT_FILE" "$ZK_TLS_DEFAULT_CERT_DIR"; do
      AS_CASE([$zk_rust_d], [""|/*], [],
        [AC_MSG_ERROR([--with-rust-tls-default-paths=$with_rust_tls_default_paths: give absolute paths (FILE or DIR can be empty)])])
    done
    zk_rust_paths_from=--with-rust-tls-default-paths],
  [AC_MSG_ERROR([--with-rust-tls-default-paths=$with_rust_tls_default_paths: give FILE:DIR])])
AS_IF([test "x$zk_rust_tls" = xyes], [
  AC_MSG_CHECKING([for the default trust locations of the Rust client])
  AC_MSG_RESULT([file=${ZK_TLS_DEFAULT_CERT_FILE:-none} dir=${ZK_TLS_DEFAULT_CERT_DIR:-none} (from $zk_rust_paths_from)])
])
])

# ZK_RUST_TLS_CONFIG
# ------------------
# Computes the TLS and SASL build of the Rust core.
# configure.ac runs the legacy probes first.
# TLS is on when the OpenSSL probe passes or --with-rust-tls=yes is given.
# The probe decides only the TLS feature and the export of
# zookeeper_init_ssl. The build never links -lssl or -lcrypto. SASL is on
# when the SASL probe passes. SASL links -lsasl2 and compiles the Cyrus
# glue with its own flags.
#
# The macro reads zk_user_with_openssl, the --with-openssl value before the
# probe, and zk_rust_provider_given. It sets zk_rust_tls and zk_rust_sasl
# to yes or no, and zk_rust_cli_ssl to yes when the programs can see the
# OpenSSL declarations of zookeeper.h. It also sets ZKRS_CARGO_FEATURES,
# ZKS_CONFIG_CPPFLAGS, ZKS_SASL_CFLAGS, ZKS_HARDEN_SASL_CFLAGS,
# ZKRS_SASL_LIBS, ZK_OPENSSL_DIR_CPPFLAGS and the two trust locations.
AC_DEFUN([ZK_RUST_TLS_CONFIG], [
AS_CASE([$with_rust_tls], [yes|no], [],
  [AC_MSG_ERROR([--with-rust-tls=$with_rust_tls: give yes or no])])
AS_IF([test "x$with_rust_tls" = xyes && test "x$zk_user_with_openssl" = xno],
  [AC_MSG_ERROR([--with-rust-tls=yes contradicts --with-openssl=no: give only one of them])])
dnl The provider is checked also when TLS is off, so a bad value always stops.
AS_CASE([$with_rust_tls_provider],
  [ring|aws-lc-rs], [],
  [aws-lc-rs-fips], [
    AS_CASE([$host_os], [linux*], [],
      [AC_MSG_ERROR([--with-rust-tls-provider=aws-lc-rs-fips needs a Linux host, not $host_os])])
    AS_CASE([$host_cpu], [x86_64|aarch64], [],
      [AC_MSG_ERROR([--with-rust-tls-provider=aws-lc-rs-fips needs an x86_64 or aarch64 host, not $host_cpu])])],
  [AC_MSG_ERROR([--with-rust-tls-provider=$with_rust_tls_provider: give ring, aws-lc-rs or aws-lc-rs-fips])])
zk_rust_tls=no
AS_IF([test "x$with_openssl" != xno || test "x$with_rust_tls" = xyes], [zk_rust_tls=yes])
zk_rust_sasl=no
AS_IF([test "x$have_sasl" = xyes && test "x$with_sasl" != xno], [zk_rust_sasl=yes])
AS_IF([test "x$zk_rust_tls" = xno && test -n "$zk_rust_provider_given"],
  [AC_MSG_NOTICE([TLS is not built: --with-rust-tls-provider=$with_rust_tls_provider is not used])])
dnl The FIPS module builds with cmake and go. A prebuilt staticlib needs neither.
AS_IF([test "x$zk_rust_tls" = xyes && test "x$with_rust_tls_provider" = xaws-lc-rs-fips &&
       test -z "$with_rust_staticlib"], [
  AC_PATH_PROG([ZKRS_CMAKE], [cmake])
  AC_PATH_PROG([ZKRS_GO], [go])
  AS_IF([test -z "$ZKRS_CMAKE" || test -z "$ZKRS_GO"],
    [AC_MSG_ERROR([--with-rust-tls-provider=aws-lc-rs-fips needs cmake and go])])
])
ZKRS_CARGO_FEATURES=
ZKS_CONFIG_CPPFLAGS=
ZKS_SASL_CFLAGS=
ZKS_HARDEN_SASL_CFLAGS=
ZKRS_SASL_LIBS=
zk_rust_features=
AS_IF([test "x$zk_rust_tls" = xyes], [
  zk_rust_features="tls-$with_rust_tls_provider"
  ZKS_CONFIG_CPPFLAGS="-DZKS_WITH_TLS -DHAVE_OPENSSL_H"
])
dnl The Cyrus glue units get the Cyrus include directory as a system
dnl directory, and the hardening set with the conversion warnings.
AS_IF([test "x$zk_rust_sasl" = xyes], [
  zk_rust_features="${zk_rust_features:+$zk_rust_features,}sasl"
  ZKS_CONFIG_CPPFLAGS="${ZKS_CONFIG_CPPFLAGS:+$ZKS_CONFIG_CPPFLAGS }-DZKS_WITH_SASL -DHAVE_CYRUS_SASL_H"
  ZKRS_SASL_LIBS=-lsasl2
  ZKS_SASL_CFLAGS=-DHAVE_CYRUS_SASL_H
  AS_CASE([$with_sasl], [yes], [],
    [ZKS_SASL_CFLAGS="$ZKS_SASL_CFLAGS -isystem $with_sasl/include"])
  ZKS_HARDEN_SASL_CFLAGS=$ZKS_HARDEN_CFLAGS
  zk_rust_sasl_flags="-Wconversion -Wsign-conversion"
  AS_CASE([$host_cpu], [x86_64|i?86], [zk_rust_sasl_flags="$zk_rust_sasl_flags -fcf-protection"])
  dnl The macOS SDK marks the Cyrus API as deprecated. Without a SASL
  dnl directory the glue uses the SDK headers, and -Werror must not stop it.
  AS_CASE([$host_os:$with_sasl], [darwin*:yes],
    [zk_rust_sasl_flags="$zk_rust_sasl_flags -Wno-deprecated-declarations"])
  for zk_rust_flag in $zk_rust_sasl_flags; do
    ZK_RUST_CC_FLAG([$zk_rust_flag], [ZKS_HARDEN_SASL_CFLAGS])
    AS_IF([test "x$zk_rust_flag_ok" != xyes], [AC_MSG_NOTICE([dropped the SASL glue flag $zk_rust_flag])])
  done
])
AS_IF([test -n "$zk_rust_features"], [ZKRS_CARGO_FEATURES="--features=$zk_rust_features"])
dnl The programs see the OpenSSL declarations of zookeeper.h only when the
dnl header exists, as in legacy. Their -I flag is the --with-openssl=DIR
dnl include directory. The shim units never get it.
zk_rust_cli_ssl=no
ZK_OPENSSL_DIR_CPPFLAGS=
AS_IF([test "x$zk_rust_tls" = xyes], [
  AS_CASE([$zk_user_with_openssl], [yes|no], [],
    [ZK_OPENSSL_DIR_CPPFLAGS="-I$zk_user_with_openssl/include"])
  zk_rust_saved_CPPFLAGS=$CPPFLAGS
  CPPFLAGS="$CPPFLAGS $ZK_OPENSSL_DIR_CPPFLAGS"
  AC_CHECK_HEADER([openssl/ossl_typ.h], [zk_rust_cli_ssl=yes])
  CPPFLAGS=$zk_rust_saved_CPPFLAGS
  AS_IF([test "x$zk_rust_cli_ssl" != xyes], [
    ZK_OPENSSL_DIR_CPPFLAGS=
    AC_MSG_WARN([no OpenSSL headers: cli and load_gen have no TLS option, and applications that define HAVE_OPENSSL_H need the headers])
  ])
])
dnl A prebuilt staticlib must have the TLS feature exactly when TLS is on.
dnl zk-ffi defines zkrs_feature_tls only with that feature. Apple nm cannot
dnl read the bitcode of a newer LLVM and then skips that member. The
dnl --no-llvm-bc option reads the machine code. GNU nm does not know the
dnl option, so the check also reads the plain nm output.
AS_IF([test -n "$with_rust_staticlib"], [
  AC_MSG_CHECKING([whether $with_rust_staticlib has the TLS feature])
  zk_rust_lib_tls=no
  AS_IF([{ $NM --no-llvm-bc "$with_rust_staticlib"; $NM "$with_rust_staticlib"; } 2>/dev/null | grep -E ' @<:@A-Z@:>@ _?zkrs_feature_tls$' >/dev/null],
    [zk_rust_lib_tls=yes])
  AC_MSG_RESULT([$zk_rust_lib_tls])
  AS_IF([test "x$zk_rust_lib_tls" != "x$zk_rust_tls"],
    [AC_MSG_ERROR([the staticlib $with_rust_staticlib has tls=$zk_rust_lib_tls, but this configure has tls=$zk_rust_tls: build the staticlib with the TLS decision of abi/tls-probe.sh and the same --with-openssl and --with-rust-tls])])
])
ZK_RUST_TLS_DEFAULT_PATHS
AC_MSG_CHECKING([for the TLS and SASL build of the Rust client])
AC_MSG_RESULT([tls=$zk_rust_tls provider=$with_rust_tls_provider sasl=$zk_rust_sasl])
])
