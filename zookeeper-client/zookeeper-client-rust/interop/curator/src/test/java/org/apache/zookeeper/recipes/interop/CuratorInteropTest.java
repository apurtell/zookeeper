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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import org.apache.curator.framework.CuratorFramework;
import org.apache.curator.framework.CuratorFrameworkFactory;
import org.apache.curator.framework.imps.ProtectedUtils;
import org.apache.curator.framework.recipes.leader.LeaderLatch;
import org.apache.curator.framework.recipes.leader.Participant;
import org.apache.curator.framework.recipes.locks.InterProcessMutex;
import org.apache.curator.framework.recipes.locks.LockInternals;
import org.apache.curator.framework.recipes.locks.StandardLockInternalsDriver;
import org.apache.curator.retry.RetryOneTime;
import org.apache.curator.utils.ZKPaths;
import org.apache.zookeeper.CreateMode;
import org.apache.zookeeper.KeeperException;
import org.apache.zookeeper.Watcher;
import org.apache.zookeeper.ZooKeeper;
import org.apache.zookeeper.data.ACL;
import org.apache.zookeeper.data.Stat;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;

/**
 * Curator interop of the Rust recipes.
 *
 * <p>Each test runs Curator {@code InterProcessMutex} or {@code LeaderLatch}
 * and Rust peers on the same path. The server comes from the system property
 * {@code zk.connect}: a standalone server or a three-node ensemble, of the
 * 3.9.6 release or of the HEAD server. With no server, or with no peer
 * binary, the tests skip.
 *
 * <p>The tests know the node of each participant from the order of the
 * starts: each start waits until one new child shows. The expected order
 * then comes from Curator's own sort of the children. In an ensemble, the
 * Curator client and a Rust peer can use different servers. Thus each check
 * of the children polls until it holds or the wait ends.
 *
 * <p>The layout checks compare each Rust node with a node that Curator
 * 5.7.1 makes, byte by byte. The expected name comes from Curator's own
 * {@code ProtectedUtils}, so the check does not copy the format.
 *
 * <p>The recovery test puts a {@link CutProxy} between a Rust peer and the
 * first server of {@code zk.connect}. The system property
 * {@code interop.proxy.port} gives its port. The default 0 takes a free
 * port.
 */
class CuratorInteropTest {

    /** The longest wait for one expected result. */
    private static final Duration WAIT = Duration.ofSeconds(20);

    /** The time during which a waiter must not proceed. */
    private static final Duration STILL = Duration.ofMillis(500);

    /** The marker of the lock node names (Curator {@code InterProcessMutex}). */
    private static final String LOCK_NAME = "lock-";

    /** The marker of the latch node names (Curator {@code LeaderLatch}). */
    private static final String LATCH_NAME = "latch-";

    /**
     * A foreign child that sorts first only when the order uses the text
     * after the last marker. That text is empty. The text after the first
     * marker would sort after every sequence number.
     */
    private static final String FIRST_LOCK = "lock-9-lock-";

    /** The latch form of {@link #FIRST_LOCK}. */
    private static final String FIRST_LATCH = "latch-9-latch-";

    /** A foreign child with no marker. It sorts after every sequence number. */
    private static final String LAST = "foreign";


    private String connect;
    private CuratorFramework curator;
    private String root;
    private final List<AutoCloseable> resources = new ArrayList<>();

    @BeforeEach
    void setUp(TestInfo info) throws Exception {
        connect = System.getProperty("zk.connect", "");
        assumeTrue(!connect.isEmpty(), "no zk.connect");
        assumeTrue(RustPeer.binary() != null, "no Rust peer binary");
        curator = CuratorFrameworkFactory.newClient(connect, new RetryOneTime(100));
        curator.start();
        assertTrue(curator.blockUntilConnected((int) WAIT.getSeconds(), TimeUnit.SECONDS),
            "Curator did not connect to " + connect);
        String test = info.getTestMethod().map(m -> m.getName()).orElse("test");
        root = "/curator-interop/" + test + "-" + UUID.randomUUID().toString().substring(0, 8);
    }

    @AfterEach
    void tearDown() throws Exception {
        for (int i = resources.size() - 1; i >= 0; i--) {
            try {
                resources.get(i).close();
            } catch (Exception e) {
                // The next resource closes in any case.
            }
        }
        resources.clear();
        if (curator != null) {
            try {
                curator.delete().quietly().deletingChildrenIfNeeded().forPath(root);
            } catch (KeeperException.NoNodeException e) {
                // The containers are gone already.
            }
            curator.close();
        }
    }

    /**
     * Mutual exclusion holds across both languages. Two Curator mutexes and
     * two Rust peers contend on one path, and the lock goes in creation
     * order whatever the language.
     */
    @Test
    void lockIsExclusiveAndFairAcrossLanguages() throws Exception {
        String path = root + "/lock";
        Holder c1 = track(new Holder(curator, path, "c1"));
        Holder c2 = track(new Holder(curator, path, "c2"));
        RustPeer r1 = track(RustPeer.start(connect));
        RustPeer r2 = track(RustPeer.start(connect));
        long r1Session = r1.session().id;
        long r2Session = r2.session().id;

        // The contenders start one after another: C1, R1, C2, R2.
        List<String> created = new ArrayList<>();
        assertTrue(c1.acquire(WAIT).get(WAIT.toMillis(), TimeUnit.MILLISECONDS));
        created.add(awaitNewChild(path, created));
        Future<String> r1Lock = r1.lock(path, WAIT.toMillis(), "rust-1");
        created.add(awaitNewChild(path, created));
        Future<Boolean> c2Lock = c2.acquire(WAIT);
        created.add(awaitNewChild(path, created));
        Future<String> r2Lock = r2.lock(path, WAIT.toMillis(), "rust-2");
        created.add(awaitNewChild(path, created));

        // Curator orders the nodes of both languages in creation order.
        assertEquals(created, sorted(path, LOCK_NAME));
        assertEquals(paths(path, created), new ArrayList<>(c1.mutex.getParticipantNodes()));

        // The Rust nodes have the Curator layout, and Java reads the Rust ids.
        assertCuratorLayout(created.get(1), created.get(0), LOCK_NAME);
        assertCuratorLayout(created.get(3), created.get(2), LOCK_NAME);
        assertDistinctIds(created);
        assertArrayEquals(utf8("rust-1"), data(path + "/" + created.get(1)));
        assertArrayEquals(utf8("rust-2"), data(path + "/" + created.get(3)));
        assertOwner(path + "/" + created.get(0), curatorSession());
        assertOwner(path + "/" + created.get(1), r1Session);
        assertOwner(path + "/" + created.get(2), curatorSession());
        assertOwner(path + "/" + created.get(3), r2Session);

        // Each grant goes to the next contender, and only to it.
        assertStillPending(r1Lock, c2Lock, r2Lock);
        c1.release();
        assertEquals("OK " + created.get(1), get(r1Lock));
        assertFalse(c1.mutex.isAcquiredInThisProcess());
        assertStillPending(c2Lock, r2Lock);
        r1.unlock();
        assertTrue(get(c2Lock));
        assertStillPending(r2Lock);
        c2.release();
        assertEquals("OK " + created.get(3), get(r2Lock));

        // While a Rust peer holds the lock, neither language takes it.
        assertFalse(c1.acquire(Duration.ZERO).get(WAIT.toMillis(), TimeUnit.MILLISECONDS));
        assertNull(r1.tryLock(path));
        awaitChildren(path, c -> c.equals(List.of(created.get(3))));
        r2.unlock();

        // A free lock goes to a Rust try at once.
        String r1Node = r1.tryLock(path);
        assertNotNull(r1Node);
        assertProtected(r1Node, LOCK_NAME);
        assertFalse(c1.acquire(Duration.ZERO).get(WAIT.toMillis(), TimeUnit.MILLISECONDS));
        r1.unlock();
        awaitChildren(path, List::isEmpty);
    }

    /**
     * Leadership passes in creation order across both languages. Each side
     * reads the participant ids of the other side.
     */
    @Test
    void latchOrderAndParticipantsAcrossLanguages() throws Exception {
        String path = root + "/latch";
        RustPeer r1 = track(RustPeer.start(connect));
        RustPeer r2 = track(RustPeer.start(connect));
        long r1Session = r1.session().id;
        long r2Session = r2.session().id;

        // The participants start one after another: C1, R1, C2, R2.
        List<String> created = new ArrayList<>();
        LeaderLatch c1 = track(new LeaderLatch(curator, path, "curator-1"));
        c1.start();
        assertTrue(c1.await(WAIT.toMillis(), TimeUnit.MILLISECONDS));
        created.add(awaitNewChild(path, created));
        String r1Node = r1.latch(path, "rust-1");
        assertEquals(r1Node, awaitNewChild(path, created));
        created.add(r1Node);
        LeaderLatch c2 = track(new LeaderLatch(curator, path, "curator-2"));
        c2.start();
        created.add(awaitNewChild(path, created));
        String r2Node = r2.latch(path, "rust-2");
        assertEquals(r2Node, awaitNewChild(path, created));
        created.add(r2Node);

        assertEquals(created, sorted(path, LATCH_NAME));
        assertEquals(c1.getOurPath(), path + "/" + created.get(0));
        awaitOurPath(c2, path + "/" + created.get(2));
        assertCuratorLayout(r1Node, created.get(0), LATCH_NAME);
        assertCuratorLayout(r2Node, created.get(2), LATCH_NAME);
        assertDistinctIds(created);

        // The node data is the participant id, the same bytes on both sides.
        assertArrayEquals(utf8("curator-1"), data(path + "/" + created.get(0)));
        assertArrayEquals(utf8("rust-1"), data(path + "/" + r1Node));
        assertArrayEquals(utf8("curator-2"), data(path + "/" + created.get(2)));
        assertArrayEquals(utf8("rust-2"), data(path + "/" + r2Node));
        assertOwner(path + "/" + r1Node, r1Session);
        assertOwner(path + "/" + r2Node, r2Session);
        assertOwner(path + "/" + created.get(0), curatorSession());

        // Each side reads the ids of the other side in latch order.
        List<String> all = List.of("curator-1:1", "rust-1:0", "curator-2:0", "rust-2:0");
        assertEquals(all, curatorParticipants(c2));
        awaitParticipants(r1, all);
        awaitParticipants(r2, all);

        // Leadership passes in creation order, across the languages.
        assertFalse(r1.awaitLeader(STILL.toMillis()));
        assertFalse(r1.isLeader());
        c1.close();
        assertTrue(r1.awaitLeader(WAIT.toMillis()));
        assertTrue(r1.isLeader());
        assertFalse(c2.hasLeadership());
        assertEquals("rust-1", c2.getLeader().getId());
        assertFalse(r2.awaitLeader(STILL.toMillis()));

        r1.closeLatch();
        assertTrue(c2.await(WAIT.toMillis(), TimeUnit.MILLISECONDS));
        awaitParticipants(r2, List.of("curator-2:1", "rust-2:0"));
        assertFalse(r2.awaitLeader(STILL.toMillis()));

        c2.close();
        assertTrue(r2.awaitLeader(WAIT.toMillis()));
        awaitParticipants(r2, List.of("rust-2:1"));
        r2.closeLatch();
        awaitChildren(path, List::isEmpty);
    }

    /**
     * A Rust participant that loses its connection during the create
     * recovers its protected-mode node. Neither side leaves an orphan node.
     *
     * <p>The proxy cuts the connection of the peer at the participant create.
     * In the case APPLIED, the server makes the node and the proxy drops the
     * reply. The peer must adopt the node that the server made. In the case
     * LOST, the proxy drops the request. The peer must create the node again
     * with the same protected prefix.
     */
    @Test
    void rustCreateRecoveryLeavesNoOrphan() throws Exception {
        CutProxy proxy = track(CutProxy.start(firstServer(connect), proxyPort()));
        RustPeer peer = track(RustPeer.start(proxy.connectString()));
        long session = peer.session().id;

        // The lock, with the reply of the applied create lost.
        String applied = root + "/lock-applied";
        curator.create().creatingParentsIfNeeded().forPath(applied);
        CompletableFuture<String> cut = proxy.arm(CutProxy.Mode.APPLIED, applied + "/_c_");
        Future<String> lock = peer.lock(applied, WAIT.toMillis());
        String made = name(get(cut));
        assertEquals("OK " + made, get(lock));
        assertProtected(made, LOCK_NAME);
        assertOwner(applied + "/" + made, session);
        assertEquals(1, proxy.cuts());
        awaitChildren(applied, c -> c.equals(List.of(made)));
        peer.unlock();
        awaitChildren(applied, List::isEmpty);

        // The lock, with the create request lost.
        String lost = root + "/lock-lost";
        curator.create().creatingParentsIfNeeded().forPath(lost);
        cut = proxy.arm(CutProxy.Mode.LOST, lost + "/_c_");
        lock = peer.lock(lost, WAIT.toMillis());
        String prefix = name(get(cut));
        String again = RustPeer.ok(get(lock));
        assertTrue(again.startsWith(prefix), again + " does not keep the prefix " + prefix);
        assertEquals(2, proxy.cuts());
        awaitChildren(lost, c -> c.equals(List.of(again)));
        Holder c1 = track(new Holder(curator, lost, "c1"));
        Future<Boolean> c1Lock = c1.acquire(WAIT);
        assertStillPending(c1Lock);
        peer.unlock();
        assertTrue(get(c1Lock));
        c1.release();
        awaitChildren(lost, List::isEmpty);

        // The latch, with the reply of the applied create lost. The Curator
        // latch leads, and both sides see the one Rust participant.
        String latchPath = root + "/latch-applied";
        LeaderLatch leader = track(new LeaderLatch(curator, latchPath, "curator-1"));
        leader.start();
        assertTrue(leader.await(WAIT.toMillis(), TimeUnit.MILLISECONDS));
        cut = proxy.arm(CutProxy.Mode.APPLIED, latchPath + "/_c_");
        Future<String> latch = peer.callAsync("LATCH " + latchPath + " rust-1");
        String latchNode = name(get(cut));
        assertEquals("OK " + latchNode, get(latch));
        assertEquals(3, proxy.cuts());
        awaitChildren(latchPath, c -> c.size() == 2 && c.contains(latchNode));
        assertEquals(List.of("curator-1:1", "rust-1:0"), curatorParticipants(leader));
        awaitParticipants(peer, List.of("curator-1:1", "rust-1:0"));
        leader.close();
        assertTrue(peer.awaitLeader(WAIT.toMillis()));
        peer.closeLatch();
        awaitChildren(latchPath, List::isEmpty);

        // The latch, with the create request lost. The peer makes the node
        // again with the same protected prefix, after the Curator node.
        String latchLost = root + "/latch-lost";
        LeaderLatch second = track(new LeaderLatch(curator, latchLost, "curator-2"));
        second.start();
        assertTrue(second.await(WAIT.toMillis(), TimeUnit.MILLISECONDS));
        cut = proxy.arm(CutProxy.Mode.LOST, latchLost + "/_c_");
        latch = peer.callAsync("LATCH " + latchLost + " rust-2");
        String latchPrefix = name(get(cut));
        String latchAgain = RustPeer.ok(get(latch));
        assertTrue(latchAgain.startsWith(latchPrefix),
            latchAgain + " does not keep the prefix " + latchPrefix);
        assertProtected(latchAgain, LATCH_NAME);
        assertEquals(4, proxy.cuts());
        awaitChildren(latchLost, c -> c.size() == 2 && c.get(1).equals(latchAgain));
        assertEquals(List.of("curator-2:1", "rust-2:0"), curatorParticipants(second));
        awaitParticipants(peer, List.of("curator-2:1", "rust-2:0"));
        second.close();
        assertTrue(peer.awaitLeader(WAIT.toMillis()));
        peer.closeLatch();
        awaitChildren(latchLost, List::isEmpty);

        // The peer session owns no node at all under the test root.
        awaitNoNodeOf(session);
    }

    /**
     * The Rust peer sends the same create requests as Curator 5.7.1 for the
     * same work, and the nodes match byte by byte.
     *
     * <p>A client {@link Stat} does not show a container: the server gives
     * the owner 0 for it. Thus each side talks through its own
     * {@link CutProxy}, and the test compares the create requests on the
     * wire. Apart from the side name and the protected ids, the two lists
     * must be equal. That covers the container parents, the participant
     * create, the node data, the ACL and the flags.
     */
    @Test
    void createsAndNodesMatchCurator() throws Exception {
        CutProxy rustWire = track(CutProxy.start(firstServer(connect), proxyPort(1)));
        CutProxy javaWire = track(CutProxy.start(firstServer(connect), proxyPort(2)));
        // The lock data of Curator is the default data of its client. The
        // Java client and the Rust peer write the same bytes.
        String lockData = "holder-1";
        CuratorFramework java = track(CuratorFrameworkFactory.builder()
            .connectString(javaWire.connectString())
            .retryPolicy(new RetryOneTime(100))
            .defaultData(utf8(lockData))
            .build());
        java.start();
        assertTrue(java.blockUntilConnected((int) WAIT.getSeconds(), TimeUnit.SECONDS));
        long javaSession = java.getZookeeperClient().getZooKeeper().getSessionId();
        RustPeer peer = track(RustPeer.start(rustWire.connectString()));
        long rustSession = peer.session().id;

        // The Rust peer goes first, so it also makes the test root.
        String rust = root + "/rust";
        String jside = root + "/java";
        String rustNode = peer.tryLock(rust + "/a/lock", lockData);
        assertNotNull(rustNode);
        Holder c1 = track(new Holder(java, jside + "/a/lock", "c1"));
        assertTrue(c1.acquire(Duration.ZERO).get(WAIT.toMillis(), TimeUnit.MILLISECONDS));
        String rustLatchNode = peer.latch(rust + "/b/latch", "p-1");
        LeaderLatch latch = track(new LeaderLatch(java, jside + "/b/latch", "p-1"));
        latch.start();
        assertTrue(latch.await(WAIT.toMillis(), TimeUnit.MILLISECONDS));
        String javaNode = awaitChildren(jside + "/a/lock", c -> c.size() == 1).get(0);
        String javaLatchNode = name(latch.getOurPath());
        awaitChildren(rust + "/a/lock", c -> c.equals(List.of(rustNode)));
        awaitChildren(rust + "/b/latch", c -> c.equals(List.of(rustLatchNode)));

        // The node names, byte by byte.
        assertCuratorLayout(rustNode, javaNode, LOCK_NAME);
        assertCuratorLayout(rustLatchNode, javaLatchNode, LATCH_NAME);
        assertDistinctIds(List.of(rustNode, javaNode, rustLatchNode, javaLatchNode));

        // The create requests. Each side retries its participant create
        // after NoNode with the same protected id.
        List<CutProxy.Create> rustCreates = rustWire.creates(rust);
        List<CutProxy.Create> javaCreates = javaWire.creates(jside);
        assertEquals(CutProxy.Create.forms(javaCreates, jside),
            CutProxy.Create.forms(rustCreates, rust));
        assertOneId(rustCreates, rustNode, rustLatchNode);
        assertOneId(javaCreates, javaNode, javaLatchNode);
        for (String level : List.of("", "/a", "/a/lock", "/b", "/b/latch")) {
            assertContainerCreate(rustCreates, rust + level);
            assertContainerCreate(javaCreates, jside + level);
        }
        assertContainerCreate(rustWire.creates(root), root);

        // The nodes: the data, the owner and the ACL.
        String rl = rust + "/a/lock/" + rustNode;
        String jl = jside + "/a/lock/" + javaNode;
        String rn = rust + "/b/latch/" + rustLatchNode;
        String jn = jside + "/b/latch/" + javaLatchNode;
        assertArrayEquals(data(jl), data(rl));
        assertArrayEquals(utf8("p-1"), data(rn));
        assertArrayEquals(utf8("p-1"), data(jn));
        assertOwner(rl, rustSession);
        assertOwner(rn, rustSession);
        assertOwner(jl, javaSession);
        assertOwner(jn, javaSession);
        assertSameAcl(rl, jl);
        assertSameAcl(rn, jn);

        peer.unlock();
        c1.release();
        peer.closeLatch();
        latch.close();
        awaitChildren(rust + "/a/lock", List::isEmpty);
        awaitChildren(jside + "/a/lock", List::isEmpty);
        awaitChildren(rust + "/b/latch", List::isEmpty);
        awaitChildren(jside + "/b/latch", List::isEmpty);
        awaitNoNodeOf(rustSession);
    }

    /**
     * Foreign children take part in the lock order on both sides, as
     * Curator orders them. A foreign node that comes first blocks both
     * languages, and its delete passes the lock on.
     */
    @Test
    void lockOrderCountsForeignChildren() throws Exception {
        String path = root + "/lock";
        curator.create().creatingParentContainersIfNeeded()
            .forPath(path + "/" + LAST, utf8("foreign-last"));
        curator.create().forPath(path + "/" + FIRST_LOCK, utf8("foreign-first"));
        Holder c1 = track(new Holder(curator, path, "c1"));
        Holder c2 = track(new Holder(curator, path, "c2"));
        RustPeer r1 = track(RustPeer.start(connect));
        RustPeer r2 = track(RustPeer.start(connect));

        // R1 and C1, then a foreign sequential node, then R2 and C2. Each
        // Rust waiter comes just after a foreign node, so a Rust order that
        // differs from Curator's lets it take the lock too early.
        List<String> known = new ArrayList<>(List.of(LAST, FIRST_LOCK));
        Future<String> r1Lock = r1.lock(path, WAIT.toMillis(), "rust-1");
        String r1Node = awaitNewChild(path, known);
        known.add(r1Node);
        Future<Boolean> c1Lock = c1.acquire(WAIT);
        String c1Node = awaitNewChild(path, known);
        known.add(c1Node);
        String mid = name(curator.create().withMode(CreateMode.PERSISTENT_SEQUENTIAL)
            .forPath(path + "/other-lock-", utf8("foreign-mid")));
        known.add(mid);
        Future<String> r2Lock = r2.lock(path, WAIT.toMillis(), "rust-2");
        String r2Node = awaitNewChild(path, known);
        known.add(r2Node);
        Future<Boolean> c2Lock = c2.acquire(WAIT);
        String c2Node = awaitNewChild(path, known);

        List<String> order = List.of(FIRST_LOCK, r1Node, c1Node, mid, r2Node, c2Node, LAST);
        assertEquals(order, sorted(path, LOCK_NAME));
        assertEquals(paths(path, order), new ArrayList<>(c1.mutex.getParticipantNodes()));

        // The foreign first node blocks both languages.
        assertStillPending(r1Lock, c1Lock, r2Lock, c2Lock);
        curator.delete().forPath(path + "/" + FIRST_LOCK);
        assertEquals("OK " + r1Node, get(r1Lock));
        assertStillPending(c1Lock, r2Lock, c2Lock);
        r1.unlock();
        assertTrue(get(c1Lock));
        assertStillPending(r2Lock, c2Lock);

        // After C1, the foreign sequential node comes first. R2 waits on it.
        c1.release();
        assertStillPending(r2Lock, c2Lock);
        curator.delete().forPath(path + "/" + mid);
        assertEquals("OK " + r2Node, get(r2Lock));
        assertStillPending(c2Lock);
        r2.unlock();
        assertTrue(get(c2Lock));
        c2.release();
        awaitChildren(path, c -> c.equals(List.of(LAST)));
    }

    /**
     * Foreign children take part in the latch order on both sides. Both
     * sides read the foreign ids at the same places, and a foreign node
     * that comes first holds the leadership away from both languages.
     */
    @Test
    void latchOrderCountsForeignChildren() throws Exception {
        String path = root + "/latch";
        curator.create().creatingParentContainersIfNeeded()
            .forPath(path + "/" + LAST, utf8("foreign-last"));
        curator.create().forPath(path + "/" + FIRST_LATCH, utf8("foreign-first"));
        RustPeer r1 = track(RustPeer.start(connect));
        RustPeer r2 = track(RustPeer.start(connect));

        // C1 and R1, then a foreign sequential node, then C2 and R2.
        List<String> known = new ArrayList<>(List.of(LAST, FIRST_LATCH));
        LeaderLatch c1 = track(new LeaderLatch(curator, path, "curator-1"));
        c1.start();
        String c1Node = awaitNewChild(path, known);
        known.add(c1Node);
        String r1Node = r1.latch(path, "rust-1");
        assertEquals(r1Node, awaitNewChild(path, known));
        known.add(r1Node);
        String mid = name(curator.create().withMode(CreateMode.PERSISTENT_SEQUENTIAL)
            .forPath(path + "/other-latch-", utf8("foreign-mid")));
        known.add(mid);
        LeaderLatch c2 = track(new LeaderLatch(curator, path, "curator-2"));
        c2.start();
        String c2Node = awaitNewChild(path, known);
        known.add(c2Node);
        String r2Node = r2.latch(path, "rust-2");
        assertEquals(r2Node, awaitNewChild(path, known));

        List<String> order = List.of(FIRST_LATCH, c1Node, r1Node, mid, c2Node, r2Node, LAST);
        assertEquals(order, sorted(path, LATCH_NAME));
        awaitOurPath(c1, path + "/" + c1Node);
        awaitOurPath(c2, path + "/" + c2Node);
        List<String> all = List.of("foreign-first:1", "curator-1:0", "rust-1:0",
            "foreign-mid:0", "curator-2:0", "rust-2:0", "foreign-last:0");
        assertEquals(all, curatorParticipants(c1));
        awaitParticipants(r1, all);
        awaitParticipants(r2, all);

        // No participant leads while the foreign first node stays.
        assertFalse(c1.await(STILL.toMillis(), TimeUnit.MILLISECONDS));
        assertFalse(r1.awaitLeader(STILL.toMillis()));
        curator.delete().forPath(path + "/" + FIRST_LATCH);
        assertTrue(c1.await(WAIT.toMillis(), TimeUnit.MILLISECONDS));
        assertFalse(r1.awaitLeader(STILL.toMillis()));
        c1.close();
        assertTrue(r1.awaitLeader(WAIT.toMillis()));
        assertFalse(c2.hasLeadership());

        // After R1, the foreign sequential node comes first. C2 waits on it.
        r1.closeLatch();
        List<String> rest = List.of("foreign-mid:1", "curator-2:0", "rust-2:0", "foreign-last:0");
        awaitParticipants(r2, rest);
        assertEquals(rest, curatorParticipants(c2));
        assertFalse(c2.await(STILL.toMillis(), TimeUnit.MILLISECONDS));
        curator.delete().forPath(path + "/" + mid);
        assertTrue(c2.await(WAIT.toMillis(), TimeUnit.MILLISECONDS));
        assertFalse(r2.awaitLeader(STILL.toMillis()));
        c2.close();
        assertTrue(r2.awaitLeader(WAIT.toMillis()));
        awaitParticipants(r2, List.of("rust-2:1", "foreign-last:0"));
        r2.closeLatch();
        awaitChildren(path, c -> c.equals(List.of(LAST)));
    }

    /**
     * A Rust acquire that is dropped while it waits deletes its node, and the
     * next Curator waiter gets the lock.
     */
    @Test
    void abandonedRustAcquireLeavesNoNode() throws Exception {
        String path = root + "/lock";
        Holder c1 = track(new Holder(curator, path, "c1"));
        Holder c2 = track(new Holder(curator, path, "c2"));
        RustPeer peer = track(RustPeer.start(connect));

        List<String> created = new ArrayList<>();
        assertTrue(c1.acquire(WAIT).get(WAIT.toMillis(), TimeUnit.MILLISECONDS));
        created.add(awaitNewChild(path, created));

        // A LOCK that times out drops its acquire, and its node goes.
        assertEquals("TIMEOUT", peer.call("LOCK " + path + " " + STILL.toMillis()));
        awaitChildren(path, c -> c.equals(created));

        // The abandoned acquire waits between C1 and C2. C2 watches it.
        Future<String> abandon = peer.abandonLock(path, 3000);
        String rustNode = awaitNewChild(path, created);
        assertProtected(rustNode, LOCK_NAME);
        Future<Boolean> c2Lock = c2.acquire(WAIT);
        List<String> withRust = new ArrayList<>(created);
        withRust.add(rustNode);
        String c2Node = awaitNewChild(path, withRust);
        assertEquals("OK", get(abandon));
        created.add(c2Node);
        awaitChildren(path, c -> c.equals(created));

        // The release of C1 goes to C2 past the dropped Rust waiter.
        assertStillPending(c2Lock);
        c1.release();
        assertTrue(get(c2Lock));
        c2.release();
        awaitChildren(path, List::isEmpty);
    }

    /**
     * The node of a Rust holder that crashes stays while its session lives.
     * When Java expires that session, the next Curator waiter gets the lock.
     */
    @Test
    void killedRustHolderFreesTheLockAtExpiry() throws Exception {
        String path = root + "/lock";
        Holder c1 = track(new Holder(curator, path, "c1"));
        RustPeer peer = track(RustPeer.start(connect));

        String rustNode = peer.tryLock(path);
        assertNotNull(rustNode);
        // With no data, a Rust lock node is empty.
        assertArrayEquals(new byte[0], data(path + "/" + rustNode));
        RustPeer.Session session = peer.session();
        peer.kill();

        Future<Boolean> c1Lock = c1.acquire(WAIT);
        awaitChildren(path, c -> c.size() == 2 && c.get(0).equals(rustNode));
        assertStillPending(c1Lock);
        expire(session);
        assertTrue(get(c1Lock));
        c1.release();
        awaitChildren(path, List::isEmpty);
    }

    /**
     * A Rust holder whose delete is lost leaves a ghost node, and a Curator
     * waiter waits behind it. The Rust guaranteed delete sends the delete
     * again after the reconnect, with no further command, and the Curator
     * waiter gets the lock.
     *
     * <p>The proxy cuts the connection of the peer in place of the delete, so
     * the server never sees the first delete. The peer session lives through
     * the cut, so only the retry of the peer can remove the node.
     */
    @Test
    void lostRustDeleteIsRetriedInTheBackground() throws Exception {
        String path = root + "/lock";
        CutProxy proxy = track(CutProxy.start(firstServer(connect), proxyPort()));
        RustPeer peer = track(RustPeer.start(proxy.connectString()));
        long session = peer.session().id;
        Holder c1 = track(new Holder(curator, path, "c1"));

        String rustNode = peer.tryLock(path);
        assertNotNull(rustNode);
        Future<Boolean> c1Lock = c1.acquire(WAIT);
        awaitChildren(path, c -> c.size() == 2 && c.get(0).equals(rustNode));
        assertStillPending(c1Lock);

        CompletableFuture<String> cut = proxy.arm(CutProxy.Mode.DELETE, path + "/" + rustNode);
        peer.dropLock();
        assertEquals(path + "/" + rustNode, get(cut));
        assertEquals(1, proxy.cuts());
        assertTrue(get(c1Lock));
        awaitChildren(path, c -> c.size() == 1 && !c.contains(rustNode));
        assertEquals(session, peer.session().id);
        c1.release();
        awaitChildren(path, List::isEmpty);
        awaitNoNodeOf(session);
    }

    // ---- Helpers -------------------------------------------------------

    private <T extends AutoCloseable> T track(T resource) {
        resources.add(resource);
        return resource;
    }

    /** The children of {@code path}, or an empty list when it is missing. */
    private List<String> children(String path) throws Exception {
        try {
            return curator.getChildren().forPath(path);
        } catch (KeeperException.NoNodeException e) {
            return new ArrayList<>();
        }
    }

    /** The children of {@code path} in Curator's own order for {@code marker}. */
    private List<String> sorted(String path, String marker) throws Exception {
        return LockInternals.getSortedChildren(marker, new StandardLockInternalsDriver(),
            children(path));
    }

    /** Waits until the children of {@code path}, in Curator order, meet {@code check}. */
    private List<String> awaitChildren(String path, Predicate<List<String>> check)
        throws Exception {
        long end = System.nanoTime() + WAIT.toNanos();
        List<String> now = sorted(path, marker(path));
        while (!check.test(now)) {
            if (System.nanoTime() > end) {
                fail("the children of " + path + " stay " + now);
            }
            Thread.sleep(50);
            now = sorted(path, marker(path));
        }
        return now;
    }

    /** The marker of the participant nodes under {@code path}. */
    private static String marker(String path) {
        return name(path).startsWith("latch") ? LATCH_NAME : LOCK_NAME;
    }

    /**
     * Waits until {@code path} has one child that is not in {@code known},
     * and gives it. The other children must be {@code known}.
     */
    private String awaitNewChild(String path, Collection<String> known) throws Exception {
        List<String> now = awaitChildren(path, c -> c.size() == known.size() + 1);
        Set<String> fresh = new HashSet<>(now);
        fresh.removeAll(known);
        assertEquals(1, fresh.size(), "children " + now + ", known " + known);
        return fresh.iterator().next();
    }

    /** Checks the protected name {@code _c_<uuid>-<marker><seq>}. */
    private static void assertProtected(String name, String marker) {
        String re = "_c_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}-"
            + marker + "[0-9]{10}";
        assertTrue(name.matches(re), name + " is not a protected " + marker + " node");
    }

    /**
     * Checks a Rust node name against a Curator node name, byte by byte.
     *
     * <p>For each name, Curator's own {@code ProtectedUtils} must read the
     * protected id, and must build the same bytes from that id, the marker
     * and the sequence suffix. The id must be a canonical version-4 UUID.
     * The two names must then agree at each byte outside the id and the
     * suffix.
     */
    private static void assertCuratorLayout(String rustName, String curatorName, String marker) {
        assertProtected(rustName, marker);
        assertProtected(curatorName, marker);
        for (String n : List.of(rustName, curatorName)) {
            assertTrue(ProtectedUtils.isProtectedZNode(n), n + " is not protected for Curator");
            String id = ProtectedUtils.extractProtectedId(n).orElse("");
            UUID uuid = UUID.fromString(id);
            assertEquals(id, uuid.toString(), n + " has no canonical UUID");
            assertEquals(4, uuid.version(), n + " has no version-4 UUID");
            assertEquals(2, uuid.variant(), n + " has no RFC 4122 UUID");
            String seq = ZKPaths.extractSequentialSuffix(n);
            assertEquals(10, seq.length(), n + " has no 10-digit suffix");
            assertArrayEquals(utf8(ProtectedUtils.toProtectedZNode(marker, id) + seq), utf8(n),
                n + " differs from the Curator name");
            assertEquals(marker + seq, ProtectedUtils.normalize(n));
        }
        assertArrayEquals(skeleton(curatorName), skeleton(rustName),
            rustName + " differs from " + curatorName);
    }

    /**
     * The bytes of a protected name with each UUID digit as {@code x} and
     * each digit of the suffix as {@code n}.
     */
    private static byte[] skeleton(String name) {
        byte[] b = utf8(name);
        int idEnd = "_c_".length() + 36;
        for (int i = "_c_".length(); i < idEnd && i < b.length; i++) {
            if (b[i] != '-') {
                b[i] = 'x';
            }
        }
        for (int i = Math.max(0, b.length - 10); i < b.length; i++) {
            b[i] = 'n';
        }
        return b;
    }

    /** Checks that no two names share a protected id. */
    private static void assertDistinctIds(Collection<String> names) {
        Set<String> ids = names.stream()
            .map(n -> ProtectedUtils.extractProtectedId(n).orElse(n))
            .collect(Collectors.toSet());
        assertEquals(names.size(), ids.size(), "the names " + names + " share an id");
    }

    /** The UTF-8 bytes of a string. */
    private static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    /** The full paths of the children {@code names} of {@code parent}. */
    private static List<String> paths(String parent, List<String> names) {
        return names.stream().map(n -> ZKPaths.makePath(parent, n)).collect(Collectors.toList());
    }

    /** The session of the Curator client. */
    private long curatorSession() throws Exception {
        return curator.getZookeeperClient().getZooKeeper().getSessionId();
    }

    /**
     * The stat of {@code path}. In an ensemble, the server of the Curator
     * client can see a new node a little later, so the read polls.
     */
    private Stat stat(String path) throws Exception {
        long end = System.nanoTime() + WAIT.toNanos();
        Stat s = curator.checkExists().forPath(path);
        while (s == null) {
            if (System.nanoTime() > end) {
                fail(path + " does not exist");
            }
            Thread.sleep(50);
            s = curator.checkExists().forPath(path);
        }
        return s;
    }

    /** The data of {@code path}. */
    private byte[] data(String path) throws Exception {
        stat(path);
        return curator.getData().forPath(path);
    }

    /** Checks that {@code path} is an ephemeral node of {@code session}. */
    private void assertOwner(String path, long session) throws Exception {
        assertEquals(Long.toHexString(session), Long.toHexString(stat(path).getEphemeralOwner()),
            "the owner of " + path);
    }

    /** Checks that two nodes have the same ACL. */
    private void assertSameAcl(String rustPath, String curatorPath) throws Exception {
        List<ACL> rust = curator.getACL().forPath(rustPath);
        assertEquals(curator.getACL().forPath(curatorPath), rust, "the ACL of " + rustPath);
    }

    /** Checks that {@code creates} make {@code path} once, as an empty container. */
    private static void assertContainerCreate(List<CutProxy.Create> creates, String path) {
        List<CutProxy.Create> made = creates.stream()
            .filter(c -> c.path.equals(path))
            .collect(Collectors.toList());
        assertEquals(1, made.size(), "the creates of " + path + ": " + made);
        CutProxy.Create c = made.get(0);
        assertEquals(CutProxy.OP_CREATE_CONTAINER, c.op, path + " is not a container create");
        assertEquals(CreateMode.CONTAINER.toFlag(), c.flags, path + " has no container flag");
        assertArrayEquals(new byte[0], c.data, path + " has data");
    }

    /**
     * Checks that the participant creates in {@code creates} use one
     * protected id for each node, and that the node has that id.
     */
    private static void assertOneId(List<CutProxy.Create> creates, String... nodes) {
        for (String node : nodes) {
            String id = ProtectedUtils.extractProtectedId(node).orElse("");
            List<CutProxy.Create> mine = creates.stream()
                .filter(c -> name(c.path).startsWith("_c_" + id + "-"))
                .collect(Collectors.toList());
            assertEquals(2, mine.size(), "the creates of " + node + ": " + creates);
            for (CutProxy.Create c : mine) {
                assertEquals(CreateMode.EPHEMERAL_SEQUENTIAL.toFlag(), c.flags, c.toString());
            }
        }
    }

    /**
     * Waits until no node under the test root has {@code session} as its
     * owner. An orphan participant node fails the wait.
     */
    private void awaitNoNodeOf(long session) throws Exception {
        long end = System.nanoTime() + WAIT.toNanos();
        List<String> owned = nodesOf(session, root);
        while (!owned.isEmpty()) {
            if (System.nanoTime() > end) {
                fail("the session " + Long.toHexString(session) + " still owns " + owned);
            }
            Thread.sleep(50);
            owned = nodesOf(session, root);
        }
    }

    /** The nodes at or under {@code path} that {@code session} owns. */
    private List<String> nodesOf(long session, String path) throws Exception {
        List<String> out = new ArrayList<>();
        Stat s = curator.checkExists().forPath(path);
        if (s == null) {
            return out;
        }
        if (s.getEphemeralOwner() == session) {
            out.add(path);
        }
        for (String child : children(path)) {
            out.addAll(nodesOf(session, ZKPaths.makePath(path, child)));
        }
        return out;
    }

    /** Checks that no future in {@code waiters} completes for {@link #STILL}. */
    private static void assertStillPending(Future<?>... waiters) throws InterruptedException {
        Thread.sleep(STILL.toMillis());
        for (Future<?> w : waiters) {
            assertFalse(w.isDone(), "a waiter proceeded");
        }
    }

    private static <T> T get(Future<T> f) throws Exception {
        return f.get(WAIT.toMillis(), TimeUnit.MILLISECONDS);
    }

    /** The participants of a Curator latch as {@code <id>:<0 or 1>} entries. */
    private static List<String> curatorParticipants(LeaderLatch latch) throws Exception {
        return latch.getParticipants().stream()
            .map(CuratorInteropTest::entry)
            .collect(Collectors.toList());
    }

    private static String entry(Participant p) {
        return p.getId() + ":" + (p.isLeader() ? 1 : 0);
    }

    /**
     * Waits until a Rust latch reads {@code expected} as the participants.
     * In an ensemble, the server of the peer can see a change a little
     * later than the server of the writer.
     */
    private static void awaitParticipants(RustPeer peer, List<String> expected)
        throws Exception {
        long end = System.nanoTime() + WAIT.toNanos();
        List<String> now = peer.participants();
        while (!expected.equals(now)) {
            if (System.nanoTime() > end) {
                fail("the Rust participants stay " + now);
            }
            Thread.sleep(50);
            now = peer.participants();
        }
    }

    /** Waits until the background create of a Curator latch completes. */
    private static void awaitOurPath(LeaderLatch latch, String expected) throws Exception {
        long end = System.nanoTime() + WAIT.toNanos();
        while (!expected.equals(latch.getOurPath())) {
            if (System.nanoTime() > end) {
                fail("the latch path stays " + latch.getOurPath());
            }
            Thread.sleep(50);
        }
    }

    /** The last component of a path. */
    private static String name(String path) {
        return path.substring(path.lastIndexOf('/') + 1);
    }

    /**
     * Expires a session: a Java client attaches to the session and closes
     * it. The server then deletes the ephemeral nodes of the session.
     */
    private void expire(RustPeer.Session session) throws Exception {
        CountDownLatch connected = new CountDownLatch(1);
        Watcher watcher = e -> {
            // An expired state also ends the wait: the session is gone.
            Watcher.Event.KeeperState state = e.getState();
            if (state == Watcher.Event.KeeperState.SyncConnected
                || state == Watcher.Event.KeeperState.Expired) {
                connected.countDown();
            }
        };
        ZooKeeper zk = new ZooKeeper(connect, 10000, watcher, session.id, session.password);
        try {
            assertTrue(connected.await(WAIT.toMillis(), TimeUnit.MILLISECONDS),
                "no connection to the session " + Long.toHexString(session.id));
        } finally {
            zk.close();
        }
    }

    /** The first {@code host:port} of a connect string, without a chroot. */
    private static InetSocketAddress firstServer(String connect) {
        String hosts = connect.contains("/") ? connect.substring(0, connect.indexOf('/')) : connect;
        String first = hosts.split(",")[0].trim();
        int colon = first.lastIndexOf(':');
        return new InetSocketAddress(first.substring(0, colon),
            Integer.parseInt(first.substring(colon + 1)));
    }

    private static int proxyPort() {
        return proxyPort(0);
    }

    /**
     * The port of the proxy {@code n} of a test: {@code interop.proxy.port}
     * plus {@code n}, or 0 for a free port when that property is 0.
     */
    private static int proxyPort(int n) {
        int base = Integer.getInteger("interop.proxy.port", 0);
        return base == 0 ? 0 : base + n;
    }

    /**
     * One Curator mutex on its own thread. {@code InterProcessMutex} must
     * release on the thread that acquires, so both run on one thread.
     */
    private static final class Holder implements AutoCloseable {
        final InterProcessMutex mutex;
        private final ExecutorService thread;

        Holder(CuratorFramework curator, String path, String name) {
            mutex = new InterProcessMutex(curator, path);
            thread = Executors.newSingleThreadExecutor(r -> {
                Thread t = new Thread(r, "curator-holder-" + name);
                t.setDaemon(true);
                return t;
            });
        }

        /** Starts an acquire that waits up to {@code wait}. */
        Future<Boolean> acquire(Duration wait) {
            return thread.submit(() -> mutex.acquire(wait.toMillis(), TimeUnit.MILLISECONDS));
        }

        /** Releases the lock on the thread that holds it. */
        void release() throws Exception {
            thread.submit(() -> {
                mutex.release();
                return null;
            }).get(WAIT.toMillis(), TimeUnit.MILLISECONDS);
        }

        @Override
        public void close() throws Exception {
            try {
                thread.submit(() -> {
                    while (mutex.isOwnedByCurrentThread()) {
                        mutex.release();
                    }
                    return null;
                }).get(WAIT.toMillis(), TimeUnit.MILLISECONDS);
            } finally {
                thread.shutdownNow();
            }
        }
    }

    /**
     * A loopback TCP proxy that cuts one connection at a chosen create or
     * delete.
     *
     * <p>The proxy reads the frames of the ZooKeeper protocol in both
     * directions: a 4-byte length, then the body. The first frame of each
     * direction is the connect handshake. Each later request starts with the
     * xid and the op code, and each later reply with the xid, the zxid and
     * the error code. A create (op 1, 15, 19 or 21) starts with its path.
     *
     * <p>An armed proxy waits for one create whose path starts with the
     * armed prefix. In the mode {@link Mode#APPLIED}, it sends the create and
     * cuts the connection in place of the successful reply. The future then
     * gives the path that the server made. In the mode {@link Mode#LOST}, it
     * cuts the connection in place of the request. The future then gives
     * the path of the request. In the mode {@link Mode#DELETE}, it does the
     * same for one delete (op 2) in place of a create. After the cut, the
     * proxy forwards each new connection unchanged.
     *
     * <p>The proxy also records each create request that it forwards, so a
     * test can compare the requests of two clients.
     */
    static final class CutProxy implements AutoCloseable {

        /** Where the proxy cuts the connection. */
        enum Mode {
            /** After the server applies the create, in place of its reply. */
            APPLIED,
            /** In place of the create request. */
            LOST,
            /** In place of a delete request. */
            DELETE
        }

        /** The op code {@code delete}. */
        private static final int OP_DELETE = 2;

        /** The op code {@code createContainer}. */
        static final int OP_CREATE_CONTAINER = 19;

        /** The op code {@code createTTL}. Its request has a TTL after the flags. */
        private static final int OP_CREATE_TTL = 21;

        /** One create request as the proxy read it. */
        static final class Create {
            final int op;
            final String path;
            final byte[] data;
            final List<String> acl;
            final int flags;

            Create(int op, String path, byte[] data, List<String> acl, int flags) {
                this.op = op;
                this.path = path;
                this.data = data;
                this.acl = acl;
                this.flags = flags;
            }

            /**
             * The request in a form for a compare: the path below
             * {@code side}, with each protected id as {@code <id>}.
             */
            String form(String side) {
                String rel = path.startsWith(side) ? path.substring(side.length()) : path;
                rel = rel.replaceAll("_c_[0-9a-f-]{36}-", "_c_<id>-");
                return "op=" + op + " path=" + rel + " flags=" + flags
                    + " data=" + (data == null ? "null" : new String(data, StandardCharsets.UTF_8))
                    + " acl=" + acl;
            }

            /** The {@link #form} of each request. */
            static List<String> forms(List<Create> creates, String side) {
                return creates.stream().map(c -> c.form(side)).collect(Collectors.toList());
            }

            @Override
            public String toString() {
                return form("");
            }

            /** Reads the body of a create request after the op code. */
            static Create read(int op, ByteBuffer b) throws IOException {
                String path = string(b);
                int len = b.getInt();
                byte[] data = null;
                if (len >= 0) {
                    data = new byte[len];
                    b.get(data);
                }
                List<String> acl = new ArrayList<>();
                int n = b.getInt();
                for (int i = 0; i < n; i++) {
                    int perms = b.getInt();
                    String scheme = string(b);
                    String id = string(b);
                    acl.add(perms + ":" + scheme + ":" + id);
                }
                int flags = b.getInt();
                if (op == OP_CREATE_TTL) {
                    b.getLong();
                }
                return new Create(op, path, data, acl, flags);
            }
        }

        /** The largest frame that the proxy accepts. */
        private static final int MAX_FRAME = 64 << 20;

        private final ServerSocket listener;
        private final InetSocketAddress target;
        private final ExecutorService pumps = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "cut-proxy");
            t.setDaemon(true);
            return t;
        });
        private final List<Socket> sockets = new ArrayList<>();
        private final List<Create> creates = new ArrayList<>();
        private Mode mode;
        private String prefix;
        private CompletableFuture<String> cut;
        private int cuts;

        private CutProxy(ServerSocket listener, InetSocketAddress target) {
            this.listener = listener;
            this.target = target;
        }

        /** Starts a proxy on 127.0.0.1:{@code port} in front of {@code target}. */
        static CutProxy start(InetSocketAddress target, int port) throws IOException {
            ServerSocket s = new ServerSocket();
            s.setReuseAddress(true);
            s.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), port));
            CutProxy proxy = new CutProxy(s, target);
            proxy.pumps.execute(proxy::acceptLoop);
            return proxy;
        }

        /** The connect string of the proxy. */
        String connectString() {
            return "127.0.0.1:" + listener.getLocalPort();
        }

        /**
         * Arms one cut at the next create under {@code pathPrefix}, or at the
         * next delete in the mode {@link Mode#DELETE}.
         */
        synchronized CompletableFuture<String> arm(Mode m, String pathPrefix) {
            mode = m;
            prefix = pathPrefix;
            cut = new CompletableFuture<>();
            return cut;
        }

        /** The create requests so far at {@code root} or below it, in wire order. */
        synchronized List<Create> creates(String root) {
            return creates.stream()
                .filter(c -> c.path.equals(root) || c.path.startsWith(root + "/"))
                .collect(Collectors.toList());
        }

        /** Records one create request. A request that does not parse records its op only. */
        private synchronized void record(int op, ByteBuffer body) {
            try {
                creates.add(Create.read(op, body));
            } catch (IOException | RuntimeException e) {
                creates.add(new Create(op, "", null, List.of(), -1));
            }
        }

        /** The number of cuts so far. */
        synchronized int cuts() {
            return cuts;
        }

        /**
         * Decides on one create or delete request. It gives the mode of the
         * cut and disarms the proxy, or gives null to forward the request.
         * A delete matches only the mode {@link Mode#DELETE}, and a create
         * matches only the other modes.
         */
        private synchronized Mode match(int op, String path) {
            if (mode == null || !path.startsWith(prefix)
                || (mode == Mode.DELETE) != (op == OP_DELETE)) {
                return null;
            }
            Mode m = mode;
            if (m != Mode.APPLIED) {
                disarm(path);
            }
            return m;
        }

        /** Records one cut and disarms the proxy. */
        private synchronized void disarm(String path) {
            mode = null;
            cuts++;
            cut.complete(path);
        }

        private void acceptLoop() {
            while (!listener.isClosed()) {
                try {
                    Socket client = listener.accept();
                    Socket server = new Socket();
                    try {
                        server.connect(target, 5000);
                    } catch (IOException e) {
                        client.close();
                        continue;
                    }
                    synchronized (this) {
                        sockets.add(client);
                        sockets.add(server);
                    }
                    Connection c = new Connection(client, server);
                    pumps.execute(c::requests);
                    pumps.execute(c::replies);
                } catch (IOException e) {
                    return;
                }
            }
        }

        @Override
        public void close() throws IOException {
            listener.close();
            synchronized (this) {
                for (Socket s : sockets) {
                    s.close();
                }
            }
            pumps.shutdownNow();
        }

        /** One proxied connection: the client side and the server side. */
        private final class Connection {
            private final Socket client;
            private final Socket server;
            /** The xid of a create sent in the mode APPLIED, or null. */
            private volatile Integer appliedXid;

            Connection(Socket client, Socket server) {
                this.client = client;
                this.server = server;
            }

            /** Cuts both sides, as a network failure does. */
            private void cutBoth() {
                try {
                    client.close();
                } catch (IOException e) {
                    // The other side closes below in any case.
                }
                try {
                    server.close();
                } catch (IOException e) {
                    // Nothing is left to close.
                }
            }

            /** Pumps the frames from the client to the server. */
            void requests() {
                try (DataInputStream in = new DataInputStream(client.getInputStream());
                     DataOutputStream out = new DataOutputStream(server.getOutputStream())) {
                    forward(out, frame(in));
                    while (true) {
                        byte[] f = frame(in);
                        ByteBuffer b = ByteBuffer.wrap(f);
                        if (f.length >= 12) {
                            int xid = b.getInt();
                            int op = b.getInt();
                            if (isCreate(op) || op == OP_DELETE) {
                                if (isCreate(op)) {
                                    record(op, b.duplicate());
                                }
                                Mode m = match(op, string(b));
                                if (m == Mode.LOST || m == Mode.DELETE) {
                                    cutBoth();
                                    return;
                                }
                                if (m == Mode.APPLIED) {
                                    appliedXid = xid;
                                }
                            }
                        }
                        forward(out, f);
                    }
                } catch (IOException e) {
                    cutBoth();
                }
            }

            /** Pumps the frames from the server to the client. */
            void replies() {
                try (DataInputStream in = new DataInputStream(server.getInputStream());
                     DataOutputStream out = new DataOutputStream(client.getOutputStream())) {
                    forward(out, frame(in));
                    while (true) {
                        byte[] f = frame(in);
                        Integer wanted = appliedXid;
                        if (wanted != null && f.length >= 16) {
                            ByteBuffer b = ByteBuffer.wrap(f);
                            int xid = b.getInt();
                            b.getLong();
                            int err = b.getInt();
                            if (xid == wanted) {
                                appliedXid = null;
                                if (err == 0) {
                                    disarm(string(b));
                                    cutBoth();
                                    return;
                                }
                            }
                        }
                        forward(out, f);
                    }
                } catch (IOException e) {
                    cutBoth();
                }
            }
        }

        private static boolean isCreate(int op) {
            return op == 1 || op == 15 || op == 19 || op == 21;
        }

        private static byte[] frame(DataInputStream in) throws IOException {
            int len = in.readInt();
            if (len < 0 || len > MAX_FRAME) {
                throw new IOException("bad frame length " + len);
            }
            byte[] f = new byte[len];
            in.readFully(f);
            return f;
        }

        private static void forward(DataOutputStream out, byte[] f) throws IOException {
            out.writeInt(f.length);
            out.write(f);
            out.flush();
        }

        /** Reads one jute string: a 4-byte length, then UTF-8 bytes. */
        private static String string(ByteBuffer b) throws IOException {
            if (b.remaining() < 4) {
                throw new EOFException("no string");
            }
            int len = b.getInt();
            if (len < 0 || len > b.remaining()) {
                return "";
            }
            byte[] s = new byte[len];
            b.get(s);
            return new String(s, StandardCharsets.UTF_8);
        }
    }
}
