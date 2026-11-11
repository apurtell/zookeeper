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

package org.apache.zookeeper.recipes.interop;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * One Rust interop peer process.
 *
 * <p>The peer is the {@code interop_peer} example of zk-recipes. It reads one
 * command for each line of stdin and writes one reply line to stdout.
 * The README.md of this project gives the protocol. The close sends
 * {@code QUIT} and then ends the process.
 *
 * <p>The peer serves one command at a time. {@link #call} is synchronized, so
 * a second command waits for the reply of the first. {@link #callAsync} runs
 * a command on a thread of the peer, so the test can act while the peer
 * waits, for example for a lock.
 */
final class RustPeer implements AutoCloseable {

    /** The system property with the path of the peer binary. */
    static final String BIN_PROPERTY = "rust.peer.bin";

    /** The longest wait for one reply. */
    static final Duration REPLY_WAIT = Duration.ofSeconds(30);

    private final Process process;
    private final BufferedWriter in;
    private final BufferedReader out;
    private final ExecutorService reader = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "rust-peer-reader");
        t.setDaemon(true);
        return t;
    });
    private final ExecutorService caller = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "rust-peer-caller");
        t.setDaemon(true);
        return t;
    });

    private RustPeer(Process process) {
        this.process = process;
        this.in = new BufferedWriter(
            new OutputStreamWriter(process.getOutputStream(), StandardCharsets.UTF_8));
        this.out = new BufferedReader(
            new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8));
    }

    /** The peer binary, or null when the property is not set or the file is missing. */
    static File binary() {
        String path = System.getProperty(BIN_PROPERTY, "");
        File f = new File(path);
        return !path.isEmpty() && f.canExecute() ? f : null;
    }

    /**
     * Starts a peer against {@code connect} and waits for its {@code READY}
     * line.
     */
    static RustPeer start(String connect) throws IOException, TimeoutException {
        File bin = binary();
        if (bin == null) {
            throw new IOException("no Rust peer binary in " + BIN_PROPERTY);
        }
        Process p = new ProcessBuilder(bin.getPath(), connect)
            .redirectError(ProcessBuilder.Redirect.INHERIT)
            .start();
        RustPeer peer = new RustPeer(p);
        String first;
        try {
            first = peer.readLine();
        } catch (IOException | TimeoutException e) {
            peer.close();
            throw e;
        }
        if (!"READY".equals(first)) {
            peer.close();
            throw new IOException("the Rust peer did not start: " + first);
        }
        return peer;
    }

    /** Sends one command and gives its reply line. */
    synchronized String call(String command) throws IOException, TimeoutException {
        in.write(command);
        in.newLine();
        in.flush();
        return readLine();
    }

    /** Sends one command on the caller thread of the peer. */
    Future<String> callAsync(String command) {
        return caller.submit(() -> call(command));
    }

    /**
     * {@code LOCK}: waits for the lock up to {@code timeoutMs}. The reply is
     * {@code OK <node-name>} or {@code TIMEOUT}.
     */
    Future<String> lock(String path, long timeoutMs) {
        return callAsync("LOCK " + path + " " + timeoutMs);
    }

    /**
     * {@code LOCK} with node data: the lock node holds {@code id} as UTF-8,
     * so the Java side can read the id of the Rust holder.
     */
    Future<String> lock(String path, long timeoutMs, String id) {
        return callAsync("LOCK " + path + " " + timeoutMs + " " + id);
    }

    /** {@code TRYLOCK}: the node name, or null when another holder has the lock. */
    String tryLock(String path) throws IOException, TimeoutException {
        return tryLockReply(call("TRYLOCK " + path));
    }

    /** {@code TRYLOCK} with node data, as {@link #lock(String, long, String)}. */
    String tryLock(String path, String id) throws IOException, TimeoutException {
        return tryLockReply(call("TRYLOCK " + path + " " + id));
    }

    private static String tryLockReply(String reply) throws IOException {
        return "NONE".equals(reply) ? null : ok(reply);
    }

    /** {@code UNLOCK}: releases the held lock. */
    void unlock() throws IOException, TimeoutException {
        ok(call("UNLOCK"));
    }

    /**
     * {@code DROP_LOCK}: drops the held guard. The reply comes at once, and
     * the delete of the node goes on in the background of the peer.
     */
    void dropLock() throws IOException, TimeoutException {
        ok(call("DROP_LOCK"));
    }

    /**
     * {@code ABANDON_LOCK}: starts an acquire and drops it after
     * {@code afterMs}. The reply comes after the delete of the node.
     */
    Future<String> abandonLock(String path, long afterMs) {
        return callAsync("ABANDON_LOCK " + path + " " + afterMs);
    }

    /** {@code LATCH}: starts a latch and gives the name of its node. */
    String latch(String path, String id) throws IOException, TimeoutException {
        return ok(call("LATCH " + path + " " + id));
    }

    /** {@code AWAIT_LEADER}: true when the peer leads within {@code timeoutMs}. */
    boolean awaitLeader(long timeoutMs) throws IOException, TimeoutException {
        String reply = call("AWAIT_LEADER " + timeoutMs);
        if ("TIMEOUT".equals(reply)) {
            return false;
        }
        ok(reply);
        return true;
    }

    /** {@code IS_LEADER}: the last evaluated leadership of the peer. */
    boolean isLeader() throws IOException, TimeoutException {
        return Boolean.parseBoolean(ok(call("IS_LEADER")));
    }

    /**
     * {@code PARTICIPANTS}: one {@code <id>:<0 or 1>} entry for each
     * participant, in latch order.
     */
    List<String> participants() throws IOException, TimeoutException {
        String rest = ok(call("PARTICIPANTS"));
        return rest.isEmpty() ? new ArrayList<>() : new ArrayList<>(Arrays.asList(rest.split(" ")));
    }

    /** {@code CLOSE_LATCH}: deletes the latch node. */
    void closeLatch() throws IOException, TimeoutException {
        ok(call("CLOSE_LATCH"));
    }

    /** {@code SESSION}: the session id and the password of the peer. */
    Session session() throws IOException, TimeoutException {
        String[] parts = ok(call("SESSION")).split(" ");
        if (parts.length != 2) {
            throw new IOException("bad SESSION reply: " + String.join(" ", parts));
        }
        byte[] password = new byte[parts[1].length() / 2];
        for (int i = 0; i < password.length; i++) {
            password[i] = (byte) Integer.parseInt(parts[1].substring(2 * i, 2 * i + 2), 16);
        }
        return new Session(Long.parseUnsignedLong(parts[0], 16), password);
    }

    /**
     * Checks that {@code reply} is {@code OK} and gives the text after
     * {@code OK }. A reply that is not {@code OK} is an error of the test.
     */
    static String ok(String reply) throws IOException {
        if ("OK".equals(reply)) {
            return "";
        }
        if (reply.startsWith("OK ")) {
            return reply.substring(3);
        }
        throw new IOException("the Rust peer replied: " + reply);
    }

    private String readLine() throws IOException, TimeoutException {
        Future<String> line = reader.submit(out::readLine);
        try {
            String s = line.get(REPLY_WAIT.toMillis(), TimeUnit.MILLISECONDS);
            if (s == null) {
                throw new IOException("the Rust peer closed stdout");
            }
            return s;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException(e);
        } catch (ExecutionException e) {
            throw new IOException(e.getCause());
        }
    }

    /** Ends the process at once, as a crash does. The session stays until it expires. */
    void kill() {
        process.destroyForcibly();
        try {
            process.waitFor(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    @Override
    public void close() {
        // The interrupt ends a call that waits on the caller thread. The
        // peer reads QUIT after its current command. A peer that does not
        // exit in 5 s is killed.
        caller.shutdownNow();
        try {
            if (process.isAlive() && caller.awaitTermination(1, TimeUnit.SECONDS)) {
                call("QUIT");
            }
        } catch (IOException | TimeoutException e) {
            // The process ends below in any case.
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        try {
            if (!process.waitFor(5, TimeUnit.SECONDS)) {
                process.destroyForcibly();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            process.destroyForcibly();
        }
        reader.shutdownNow();
    }

    /** The session of a peer, so a test can expire it. */
    static final class Session {
        final long id;
        final byte[] password;

        Session(long id, byte[] password) {
            this.id = id;
            this.password = password;
        }
    }
}
