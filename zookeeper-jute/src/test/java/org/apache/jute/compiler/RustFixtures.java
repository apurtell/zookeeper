/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.jute.compiler;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import org.apache.jute.BinaryOutputArchive;
import org.apache.jute.Record;
import org.apache.jute.compiler.generated.Rcc;

/**
 * Writes cross-language fixtures for the Rust jute records.
 *
 * <p>For each record of the client modules, the writer builds seeded
 * instances and serializes them with the Java {@link BinaryOutputArchive}.
 * The Rust tests decode each instance, encode it again and compare the bytes.
 *
 * <p>There is one file for each record, named {@code <module>.<Record>.bin},
 * where the module is {@code data} or {@code proto}. The file is a sequence
 * of entries. Each entry is a four-byte big-endian length and the serialized
 * record of that length. The seed of a record is fixed, so the output is the
 * same on each run.
 *
 * <p>Run {@code main} with the fixture directory as its argument to write the
 * fixtures again after a change to {@code zookeeper.jute}.
 */
public final class RustFixtures {

    /** The number of instances for each record. */
    static final int INSTANCES = 24;

    private static final Map<String, String> MODULES = new LinkedHashMap<>();

    static {
        MODULES.put("org.apache.zookeeper.data", "data");
        MODULES.put("org.apache.zookeeper.proto", "proto");
    }

    /** Code points for strings: ASCII, two-byte, three-byte and four-byte UTF-8. */
    private static final int[] CODE_POINTS = {
        'a', 'z', 'A', '/', '0', '9', '-', '_', ' ', 0xe9, 0x4e2d, 0x1f600,
    };

    private RustFixtures() {
    }

    /**
     * Writes the fixtures.
     *
     * @param args the fixture directory, and optionally the jute file
     * @throws Exception if a record cannot be built or a file cannot be written
     */
    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            throw new IllegalArgumentException("usage: RustFixtures <fixture-dir> [zookeeper.jute]");
        }
        File jute = new File(args.length > 1 ? args[1] : "src/main/resources/zookeeper.jute");
        write(jute, new File(args[0]));
    }

    /**
     * Writes one fixture file for each client record of a jute file.
     *
     * @param jute the jute file
     * @param dir  the output directory
     * @return the names of the written files, in jute order
     * @throws Exception if a record cannot be built or a file cannot be written
     */
    static List<String> write(File jute, File dir) throws Exception {
        if (!dir.isDirectory() && !dir.mkdirs()) {
            throw new IOException("unable to create " + dir);
        }
        List<String> names = new ArrayList<>();
        for (Map.Entry<String, byte[]> e : build(jute).entrySet()) {
            Files.write(new File(dir, e.getKey()).toPath(), e.getValue());
            names.add(e.getKey());
        }
        return names;
    }

    /**
     * Builds the fixture content for each client record of a jute file.
     *
     * @param jute the jute file
     * @return the fixture file names mapped to their content, in jute order
     * @throws Exception if a record cannot be built
     */
    static Map<String, byte[]> build(File jute) throws Exception {
        Map<String, byte[]> out = new LinkedHashMap<>();
        for (JRecord jr : records(jute)) {
            String module = MODULES.get(jr.getJavaPackage());
            if (module == null) {
                continue;
            }
            String name = module + "." + jr.getName() + ".bin";
            Random random = new Random(seed(jr.getJavaFQName()));
            ByteArrayOutputStream file = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(file);
            for (int i = 0; i < INSTANCES; i++) {
                Record r = instance(jr, random, i);
                ByteArrayOutputStream bytes = new ByteArrayOutputStream();
                r.serialize(BinaryOutputArchive.getArchive(bytes), "");
                dos.writeInt(bytes.size());
                bytes.writeTo(dos);
            }
            dos.flush();
            out.put(name, file.toByteArray());
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    private static List<JRecord> records(File jute) throws Exception {
        JFile jf = Rcc.parseFile(jute);
        Field f = JFile.class.getDeclaredField("mRecords");
        f.setAccessible(true);
        return (List<JRecord>) f.get(jf);
    }

    /** Returns a seed that depends only on the record name. */
    private static long seed(String name) {
        long h = 1125899906842597L;
        for (int i = 0; i < name.length(); i++) {
            h = 31 * h + name.charAt(i);
        }
        return h;
    }

    /**
     * Builds one instance. Instance 0 has null or zero values. Instance 1 has
     * empty or extreme values. The other instances have random values.
     */
    private static Record instance(JRecord jr, Random random, int index) throws Exception {
        Class<?> cls = Class.forName(jr.getJavaFQName());
        Record r = (Record) cls.getDeclaredConstructor().newInstance();
        for (JField f : jr.getFields()) {
            Object value = value(f.getType(), random, index);
            Method setter = setter(cls, f.getName());
            setter.invoke(r, value);
        }
        return r;
    }

    private static Method setter(Class<?> cls, String field) throws NoSuchMethodException {
        String name = "set" + Character.toUpperCase(field.charAt(0)) + field.substring(1);
        for (Method m : cls.getMethods()) {
            if (m.getName().equals(name) && m.getParameterCount() == 1) {
                return m;
            }
        }
        throw new NoSuchMethodException(cls.getName() + "." + name);
    }

    private static Object value(JType t, Random random, int index) throws Exception {
        if (t instanceof JInt) {
            if (index == 0) {
                return 0;
            } else if (index == 1) {
                return random.nextBoolean() ? Integer.MIN_VALUE : Integer.MAX_VALUE;
            }
            return random.nextInt();
        } else if (t instanceof JLong) {
            if (index == 0) {
                return 0L;
            } else if (index == 1) {
                return random.nextBoolean() ? Long.MIN_VALUE : Long.MAX_VALUE;
            }
            return random.nextLong();
        } else if (t instanceof JBoolean) {
            return index != 0 && (index == 1 || random.nextBoolean());
        } else if (t instanceof JString) {
            if (index == 0 || (index > 1 && random.nextInt(6) == 0)) {
                return null;
            }
            int len = index == 1 ? 0 : random.nextInt(24);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < len; i++) {
                sb.appendCodePoint(CODE_POINTS[random.nextInt(CODE_POINTS.length)]);
            }
            return sb.toString();
        } else if (t instanceof JBuffer) {
            if (index == 0 || (index > 1 && random.nextInt(6) == 0)) {
                return null;
            }
            byte[] b = new byte[index == 1 ? 0 : random.nextInt(40)];
            random.nextBytes(b);
            return b;
        } else if (t instanceof JVector) {
            if (index == 0 || (index > 1 && random.nextInt(6) == 0)) {
                return null;
            }
            int len = index == 1 ? 0 : random.nextInt(5);
            List<Object> list = new ArrayList<>();
            for (int i = 0; i < len; i++) {
                list.add(value(((JVector) t).getElementType(), random, 2 + random.nextInt(4)));
            }
            return list;
        } else if (t instanceof JRecord) {
            return instance((JRecord) t, random, index);
        }
        throw new IllegalArgumentException("unsupported jute type " + t.getSignature());
    }
}
