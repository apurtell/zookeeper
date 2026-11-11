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

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Rust code generator for the client records of a jute file.
 *
 * <p>The generator writes one file. The file has one Rust module for each
 * client jute module. It omits the server modules. Each record becomes a
 * struct that implements the {@code zk_jute::Record} trait. The output is
 * deterministic: it has no timestamp, no path and no hash-ordered iteration.
 */
class RustGenerator {

    /**
     * The jute modules that the generator emits, mapped to their Rust module
     * names. The map order is the output order.
     */
    private static final Map<String, String> MODULES = new LinkedHashMap<>();

    static {
        MODULES.put("org.apache.zookeeper.data", "data");
        MODULES.put("org.apache.zookeeper.proto", "proto");
    }

    /**
     * Rust keywords that a raw identifier can replace.
     */
    private static final Set<String> RAW_KEYWORDS = new HashSet<>(Arrays.asList(
            "as", "break", "const", "continue", "else", "enum", "extern", "false",
            "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod", "move",
            "mut", "pub", "ref", "return", "static", "struct", "trait", "true",
            "type", "unsafe", "use", "where", "while", "async", "await", "dyn",
            "abstract", "become", "box", "do", "final", "macro", "override",
            "priv", "typeof", "unsized", "virtual", "yield", "try", "gen"));

    /**
     * Rust keywords that a raw identifier cannot replace.
     */
    private static final Set<String> NON_RAW_KEYWORDS = new HashSet<>(Arrays.asList(
            "crate", "self", "Self", "super", "_"));

    private final String mName;
    private final List<JRecord> mRecList;
    private final File outputDirectory;

    /**
     * Creates a new instance of RustGenerator.
     *
     * @param name            possibly full pathname to the file
     * @param ilist           included files (as JFile)
     * @param rlist           List of records defined within this file
     * @param outputDirectory the directory that receives the generated file
     */
    RustGenerator(String name, List<JFile> ilist, List<JRecord> rlist,
                  File outputDirectory) {
        this.outputDirectory = outputDirectory;
        this.mName = (new File(name)).getName();
        this.mRecList = rlist;
    }

    /**
     * Returns the name of the generated file for a jute file name.
     *
     * @param juteName the base name of the jute file
     * @return the jute name with each dot replaced by an underscore, plus ".rs"
     */
    static String outputFileName(String juteName) {
        return juteName.replace('.', '_') + ".rs";
    }

    /**
     * Generates the Rust file in the output directory.
     *
     * @throws IOException if a record uses a type that has no Rust mapping,
     *                     or if the file cannot be written
     */
    void genCode() throws IOException {
        String text = generate();
        if (!outputDirectory.exists()) {
            if (!outputDirectory.mkdirs()) {
                throw new IOException("unable to create output directory "
                        + outputDirectory);
            }
        }
        File out = new File(outputDirectory, outputFileName(mName));
        try (OutputStream os = Files.newOutputStream(out.toPath())) {
            os.write(text.getBytes(StandardCharsets.UTF_8));
        }
    }

    /**
     * Generates the Rust source text.
     *
     * @return the complete file content
     * @throws IOException if a record uses a type that has no Rust mapping
     */
    String generate() throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("// Licensed to the Apache Software Foundation (ASF) under one\n");
        sb.append("// or more contributor license agreements.  See the NOTICE file\n");
        sb.append("// distributed with this work for additional information\n");
        sb.append("// regarding copyright ownership.  The ASF licenses this file\n");
        sb.append("// to you under the Apache License, Version 2.0 (the\n");
        sb.append("// \"License\"); you may not use this file except in compliance\n");
        sb.append("// with the License.  You may obtain a copy of the License at\n");
        sb.append("//\n");
        sb.append("//     http://www.apache.org/licenses/LICENSE-2.0\n");
        sb.append("//\n");
        sb.append("// Unless required by applicable law or agreed to in writing, software\n");
        sb.append("// distributed under the License is distributed on an \"AS IS\" BASIS,\n");
        sb.append("// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n");
        sb.append("// See the License for the specific language governing permissions and\n");
        sb.append("// limitations under the License.\n");
        sb.append("\n");
        sb.append("// Generated by RustGenerator from ").append(mName).append(". Do not edit.\n");

        for (Map.Entry<String, String> module : MODULES.entrySet()) {
            List<JRecord> records = new ArrayList<>();
            for (JRecord r : mRecList) {
                if (module.getKey().equals(r.getJavaPackage())) {
                    records.add(r);
                }
            }
            if (records.isEmpty()) {
                continue;
            }
            sb.append("\n");
            sb.append("/// Records of the jute module `").append(module.getKey()).append("`.\n");
            sb.append("pub mod ").append(module.getValue()).append(" {");
            for (JRecord r : records) {
                sb.append("\n");
                genRecord(sb, r);
            }
            sb.append("}\n");
        }
        return sb.toString();
    }

    private void genRecord(StringBuilder sb, JRecord r) throws IOException {
        String name = r.getName();
        List<JField> fields = r.getFields();
        List<String> idents = new ArrayList<>();
        List<String> types = new ArrayList<>();
        for (JField f : fields) {
            idents.add(fieldIdent(f.getName()));
            types.add(rustType(f.getType(), r, f));
        }

        sb.append("    /// Jute record `").append(r.getJavaFQName()).append("`.\n");
        sb.append("    #[derive(Debug, Clone, PartialEq, Eq, Default)]\n");
        if (name.length() > 1 && name.equals(name.toUpperCase(Locale.ROOT))) {
            sb.append("    #[allow(clippy::upper_case_acronyms)]\n");
        }
        if (fields.isEmpty()) {
            sb.append("    pub struct ").append(name).append(" {}\n");
        } else {
            sb.append("    pub struct ").append(name).append(" {\n");
            for (int i = 0; i < fields.size(); i++) {
                JField f = fields.get(i);
                sb.append("        /// Jute field `").append(f.getName()).append("` of type `")
                        .append(juteTypeName(f.getType())).append("`.\n");
                sb.append("        pub ").append(idents.get(i)).append(": ")
                        .append(types.get(i)).append(",\n");
            }
            sb.append("    }\n");
        }

        sb.append("\n");
        sb.append("    impl ").append(name).append(" {\n");
        sb.append("        /// The jute signature of this record, as the Java `signature()` gives it.\n");
        sb.append("        pub const SIGNATURE: &'static str = \"").append(r.getSignature()).append("\";\n");
        sb.append("    }\n");

        sb.append("\n");
        sb.append("    impl crate::Record for ").append(name).append(" {\n");
        sb.append("        const MIN_ENCODED_LEN: usize = ").append(minEncodedLen(r, new HashSet<>()))
                .append(";\n");
        sb.append("\n");
        if (fields.isEmpty()) {
            sb.append("        fn encode(&self, _out: &mut Vec<u8>) {}\n");
        } else {
            sb.append("        fn encode(&self, out: &mut Vec<u8>) {\n");
            for (String ident : idents) {
                sb.append("            crate::Record::encode(&self.").append(ident).append(", out);\n");
            }
            sb.append("        }\n");
        }
        sb.append("\n");
        if (fields.isEmpty()) {
            sb.append("        fn decode(_r: &mut crate::Reader<'_>) -> Result<Self, crate::DecodeError> {\n");
            sb.append("            Ok(Self {})\n");
        } else {
            sb.append("        fn decode(r: &mut crate::Reader<'_>) -> Result<Self, crate::DecodeError> {\n");
            sb.append("            Ok(Self {\n");
            for (String ident : idents) {
                sb.append("                ").append(ident).append(": crate::Record::decode(r)?,\n");
            }
            sb.append("            })\n");
        }
        sb.append("        }\n");
        sb.append("\n");
        sb.append("        fn encoded_len(&self) -> usize {\n");
        if (fields.isEmpty()) {
            sb.append("            0\n");
        } else {
            // One short statement for each field keeps the output in the
            // rustfmt layout. Method calls keep the call arguments short.
            int last = idents.size() - 1;
            for (int i = 0; i <= last; i++) {
                String len = "self." + idents.get(i) + ".encoded_len()";
                String sum = i == 0 ? len : "n.saturating_add(" + len + ")";
                if (i < last) {
                    sb.append("            let n = ").append(sum).append(";\n");
                } else {
                    sb.append("            ").append(sum).append("\n");
                }
            }
        }
        sb.append("        }\n");
        sb.append("    }\n");
    }

    /**
     * Returns the Rust type of a jute type, or fails for a type that has no
     * mapping. A record in the same module uses its plain name. A record in
     * another emitted module uses a path through the parent module.
     */
    private static String rustType(JType t, JRecord rec, JField f) throws IOException {
        if (t instanceof JInt) {
            return "i32";
        } else if (t instanceof JLong) {
            return "i64";
        } else if (t instanceof JBoolean) {
            return "bool";
        } else if (t instanceof JString) {
            return "crate::JString";
        } else if (t instanceof JBuffer) {
            return "crate::JBuffer";
        } else if (t instanceof JVector) {
            return "crate::JVec<" + rustType(((JVector) t).getElementType(), rec, f) + ">";
        } else if (t instanceof JRecord) {
            JRecord ref = (JRecord) t;
            String module = MODULES.get(ref.getJavaPackage());
            if (module == null) {
                throw unsupported(rec, f, "record " + ref.getJavaFQName()
                        + " from a module that the Rust generator does not emit");
            }
            if (ref.getJavaPackage().equals(rec.getJavaPackage())) {
                return ref.getName();
            }
            return "super::" + module + "::" + ref.getName();
        }
        throw unsupported(rec, f, juteTypeName(t));
    }

    private static IOException unsupported(JRecord rec, JField f, String what) {
        return new IOException("RustGenerator: record " + rec.getJavaFQName()
                + ", field " + f.getName() + ": unsupported type " + what
                + " has no Rust mapping");
    }

    /**
     * Returns the jute spelling of a type, for doc comments and diagnostics.
     */
    private static String juteTypeName(JType t) {
        if (t instanceof JInt) {
            return "int";
        } else if (t instanceof JLong) {
            return "long";
        } else if (t instanceof JBoolean) {
            return "boolean";
        } else if (t instanceof JString) {
            return "ustring";
        } else if (t instanceof JBuffer) {
            return "buffer";
        } else if (t instanceof JByte) {
            return "byte";
        } else if (t instanceof JFloat) {
            return "float";
        } else if (t instanceof JDouble) {
            return "double";
        } else if (t instanceof JMap) {
            return "map";
        } else if (t instanceof JVector) {
            return "vector<" + juteTypeName(((JVector) t).getElementType()) + ">";
        } else if (t instanceof JRecord) {
            return ((JRecord) t).getJavaFQName();
        }
        return t.getSignature();
    }

    /**
     * Returns the smallest wire size of a record. A string, buffer or vector
     * needs at least its four-byte length prefix. The decoder uses this value
     * to bound the capacity that it reserves for a vector.
     */
    private static long minEncodedLen(JRecord r, Set<String> active) throws IOException {
        if (!active.add(r.getJavaFQName())) {
            throw new IOException("RustGenerator: record " + r.getJavaFQName()
                    + " contains itself");
        }
        long total = 0;
        for (JField f : r.getFields()) {
            JType t = f.getType();
            if (t instanceof JInt) {
                total += 4;
            } else if (t instanceof JLong) {
                total += 8;
            } else if (t instanceof JBoolean) {
                total += 1;
            } else if (t instanceof JString || t instanceof JBuffer || t instanceof JVector) {
                total += 4;
            } else if (t instanceof JRecord) {
                total += minEncodedLen((JRecord) t, active);
            } else {
                throw unsupported(r, f, juteTypeName(t));
            }
        }
        active.remove(r.getJavaFQName());
        return total;
    }

    /**
     * Converts a jute field name to a Rust field identifier. The name becomes
     * snake case. A keyword becomes a raw identifier, or gets a trailing
     * underscore when Rust does not permit a raw form.
     */
    static String fieldIdent(String name) {
        String snake = toSnakeCase(name);
        if (RAW_KEYWORDS.contains(snake)) {
            return "r#" + snake;
        }
        if (NON_RAW_KEYWORDS.contains(snake)) {
            return snake + "_";
        }
        return snake;
    }

    /**
     * Converts a camel case name to snake case. An underscore goes before an
     * upper case letter that starts a new word. A run of upper case letters
     * stays as one word.
     */
    static String toSnakeCase(String name) {
        StringBuilder sb = new StringBuilder();
        int n = name.length();
        for (int i = 0; i < n; i++) {
            char c = name.charAt(i);
            if (Character.isUpperCase(c)) {
                boolean prevLowerOrDigit = i > 0
                        && (Character.isLowerCase(name.charAt(i - 1)) || Character.isDigit(name.charAt(i - 1)));
                boolean prevUpper = i > 0 && Character.isUpperCase(name.charAt(i - 1));
                boolean nextLower = i + 1 < n && Character.isLowerCase(name.charAt(i + 1));
                if (prevLowerOrDigit || (prevUpper && nextLower)) {
                    sb.append('_');
                }
                sb.append(Character.toLowerCase(c));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }
}
