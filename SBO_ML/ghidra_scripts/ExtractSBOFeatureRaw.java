// Ghidra Java Script
// @category SBO
// Rich SBO-oriented feature extractor.
// Optimized version: precompiled/cached regex + safer UTF-8 writing, schema unchanged.
// Output JSON schema: sbo_rich_v6_context_java

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.*;
import ghidra.program.model.pcode.PcodeOp;

import java.io.*;
import java.util.*;
import java.util.regex.*;

public class ExtractSBOFeatureRaw extends GhidraScript {

    private static final Set<String> DANGEROUS = set(
        "gets",
        "memcpy", "memmove", "wmemcpy", "wmemmove",
        "read", "recv", "recvfrom",
        "sprintf", "swprintf", "vsprintf", "vswprintf", "sprintf_chk",
        "strcat", "strcpy", "wcscat", "wcscpy", "strcpy_chk", "strcat_chk"
    );

    private static final Set<String> BOUNDED = set(
        "fgets", "fgetws",
        "snprintf", "vsnprintf", "snprintf_chk", "vsnprintf_chk",
        "strncpy", "strncat", "wcsncpy", "wcsncat", "strncpy_chk", "strncat_chk",
        "memcpy", "memmove", "wmemcpy", "wmemmove", "memcpy_chk", "memmove_chk", "strcpy_chk", "strcat_chk"
    );

    private static final Set<String> UNBOUNDED = set(
        "gets", "sprintf", "swprintf", "vsprintf", "vswprintf", "strcpy", "strcat", "wcscpy", "wcscat"
    );

    private static final Set<String> INPUT_APIS = set(
        "gets", "fgets", "fgetws",
        "scanf", "sscanf", "fscanf",
        "__isoc99_scanf", "__isoc99_sscanf", "isoc99_scanf", "isoc99_sscanf",
        "__isoc23_scanf", "__isoc23_sscanf", "isoc23_scanf", "isoc23_sscanf",
        "read", "recv", "recvfrom"
    );

    private static final Set<String> LEN_APIS = set(
        "strlen", "wcslen", "strnlen", "wcsnlen", "sizeof"
    );

    private static final Set<String> BUFFER_INIT = set(
        "memset", "wmemset", "bzero"
    );

    private static final Set<String> INTERESTING = union(
        DANGEROUS, BOUNDED, INPUT_APIS, LEN_APIS, BUFFER_INIT
    );

    // Precompiled patterns: giữ nguyên regex gốc nhưng tránh compile lặp lại ở mỗi function/line.
    private static final Pattern LOCAL_BUFFER_PATTERN = Pattern.compile(
        "\\b((?:const\\s+|static\\s+|unsigned\\s+|signed\\s+|volatile\\s+)*" +
        "(?:char|wchar_t|char16_t|char32_t|byte|undefined|int|uint|int64_t|uint64_t|long|short|float|double)[\\w\\s\\*]*)\\s+" +
        "([A-Za-z_]\\w*)\\s*\\[\\s*(0x[0-9a-fA-F]+|\\d+)\\s*\\]",
        Pattern.MULTILINE
    );
    private static final Pattern CALL_PATTERN = Pattern.compile("\\b([A-Za-z_]\\w*)\\s*\\((.*)\\)\\s*;");
    private static final Pattern LOOP_PATTERN = Pattern.compile("\\b(for|while)\\s*\\(");
    private static final Pattern INPUT_SOURCE_PATTERN = Pattern.compile(
        "\\b(argv|envp|getenv|stdin|scanf|sscanf|fscanf|fgets|gets|read|recv|recvfrom|getchar)\\b"
    );
    private static final Pattern CLEAN_VAR_PATTERN = Pattern.compile("\\b([A-Za-z_]\\w*)\\b");
    private static final Pattern STRING_LITERAL_PATTERN = Pattern.compile("L?\"((?:\\\\.|[^\"\\\\])*)\"");
    private static final Pattern RBP_OFFSET_PATTERN = Pattern.compile("\\b(?:r|e)?bp([+-](?:0x[0-9a-f]+|\\d+))");
    private static final Pattern RSP_OFFSET_PATTERN = Pattern.compile("\\b(?:r|e)?sp([+-](?:0x[0-9a-f]+|\\d+))");
    private static final Pattern STACK_NAME_OFFSET_PATTERN = Pattern.compile(
        "(?:local|stack|austack|acstack|aistack)_([0-9a-f]+)",
        Pattern.CASE_INSENSITIVE
    );
    private static final Pattern INT_TEXT_PATTERN = Pattern.compile("[-+]?0x[0-9a-fA-F]+|[-+]?\\d+");

    // Cache cho regex động có tên biến/buffer. Không đổi logic, chỉ tránh compile lại nhiều lần.
    private final HashMap<String, Pattern> patternCache = new HashMap<String, Pattern>();

    private static Set<String> set(String... xs) {
        LinkedHashSet<String> s = new LinkedHashSet<String>();
        for (String x : xs) s.add(x);
        return s;
    }

    @SafeVarargs
    private static Set<String> union(Set<String>... sets) {
        LinkedHashSet<String> out = new LinkedHashSet<String>();
        for (Set<String> s : sets) out.addAll(s);
        return out;
    }

    private Pattern cachedPattern(String regex, int flags) {
        String key = flags + "::" + regex;
        Pattern p = patternCache.get(key);
        if (p == null) {
            p = Pattern.compile(regex, flags);
            patternCache.put(key, p);
        }
        return p;
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();

        if (args.length < 1) {
            println("Usage: -postScript ExtractSBOFeatureV6.java <out_json>");
            return;
        }

        File outFile = resolveOutputFile(args[0]);
        File parent = outFile.getParentFile();
        if (parent != null) parent.mkdirs();

        DecompInterface ifc = new DecompInterface();
        try {
            ifc.setOptions(new DecompileOptions());
        } catch (Exception ignored) {}
        ifc.openProgram(currentProgram);

        ArrayList<Object> funcs = new ArrayList<Object>();
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);

        int n = 0;
        while (it.hasNext()) {
            if (monitor.isCancelled()) break;

            Function f = it.next();
            n++;

            try {
                funcs.add(analyzeFunction(ifc, f));
            } catch (Throwable t) {
                LinkedHashMap<String, Object> err = new LinkedHashMap<String, Object>();
                err.put("name", s(f.getName()));
                err.put("entry", addr(f.getEntryPoint()));
                err.put("error", s(t.toString()));
                funcs.add(err);
            }
        }

        LinkedHashMap<String, Object> root = new LinkedHashMap<String, Object>();
        root.put("schema", "sbo_rich_v6_context_java");
        root.put("program", programMeta());
        root.put("function_count", funcs.size());
        root.put("functions", funcs);

        PrintWriter pw = null;
        try {
            pw = new PrintWriter(new OutputStreamWriter(new FileOutputStream(outFile), "UTF-8"));
            pw.write(toJson(root));
        } finally {
            if (pw != null) pw.close();
        }

        println("[SBO_RICH_V6_JAVA] wrote: " + outFile.getAbsolutePath());
        println("[SBO_RICH_V6_JAVA] functions: " + funcs.size());
    }

    private File resolveOutputFile(String arg) {
        File target = new File(arg);
        String lower = arg.toLowerCase();

        // One-binary mode: exact JSON path.
        if (lower.endsWith(".json")) {
            return target;
        }

        // Chunk mode: arg is output directory.
        target.mkdirs();

        String name = s(currentProgram.getName());
        name = name.replaceAll("[^A-Za-z0-9_.-]+", "_");

        if (!name.endsWith(".json")) {
            name = name + ".json";
        }

        return new File(target, name);
    }

    private Map<String, Object> programMeta() {
        LinkedHashMap<String, Object> m = new LinkedHashMap<String, Object>();
        m.put("program_name", s(currentProgram.getName()));
        try {
            m.put("executable_path", s(currentProgram.getExecutablePath()));
        } catch (Exception e) {
            m.put("executable_path", "");
        }
        try {
            m.put("language", s(currentProgram.getLanguageID()));
        } catch (Exception e) {
            m.put("language", "");
        }
        try {
            m.put("compiler", s(currentProgram.getCompilerSpec().getCompilerSpecID()));
        } catch (Exception e) {
            m.put("compiler", "");
        }
        m.put("image_base", s(currentProgram.getImageBase()));
        m.put("creation_time", System.currentTimeMillis() / 1000L);
        return m;
    }

    private Map<String, Object> analyzeFunction(DecompInterface ifc, Function func) {
        LinkedHashMap<String, Object> out = new LinkedHashMap<String, Object>();

        String c = decompile(ifc, func);
        ArrayList<String> params = getParams(func);
        ArrayList<Object> buffers = parseLocalBuffers(c);
        ArrayList<Object> sinks = parseSinks(c, buffers, params);

        ArrayList<Object> v6Aliases = analyzeAliasesV6(c, buffers);
        Map<String, Object> v6LoopSummary = analyzeLoopsV6(c, buffers, params);

        enrichSinksV6(c, buffers, params, sinks, v6Aliases);

        Map<String, Object> instr = analyzeInstructions(func);
        Map<String, Object> cfg = cfgInfo(func);
        Map<String, Object> cg = callGraphInfoV5(func);

        out.put("name", s(func.getName()));
        out.put("name_norm", normName(func.getName()));
        out.put("entry", addr(func.getEntryPoint()));
        out.put("is_external", bool(func.isExternal()));
        out.put("is_thunk", bool(func.isThunk()));
        out.put("params", params);
        out.put("decompiled_ok", bool(c.length() > 0));
        out.put("decompiled_line_count", c.length() == 0 ? 0 : c.split("\\R").length);
        out.put("decompiled_text", c);

        out.put("summary", instr.get("summary"));
        out.put("cfg", cfg);
        out.put("stack", instr.get("stack"));
        out.put("callgraph", cg);

        out.put("local_buffers", buffers);
        out.put("buffer_summary", summarizeBuffers(buffers));

        out.put("sinks", sinks);
        out.put("sink_summary", summarizeSinks(sinks));
        out.put("v4_summary", summarizeV4(sinks));

        out.put("v6_aliases", v6Aliases);
        out.put("v6_alias_summary", summarizeAliasesV6(v6Aliases));
        out.put("v6_loop_summary", v6LoopSummary);
        out.put("v6_function_role", functionRoleV6(func, c, sinks));
        out.put("v6_summary", summarizeV6Context(c, buffers, params, sinks, v6Aliases));

        out.put("pcode_counts", instr.get("pcode_counts"));
        out.put("mnemonic_counts", instr.get("mnemonic_counts"));

        return out;
    }

    private String decompile(DecompInterface ifc, Function func) {
        try {
            if (func.isExternal()) return "";
            DecompileResults res = ifc.decompileFunction(func, 30, monitor);
            if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                return s(res.getDecompiledFunction().getC());
            }
        } catch (Throwable ignored) {}
        return "";
    }

    private ArrayList<String> getParams(Function func) {
        ArrayList<String> out = new ArrayList<String>();
        try {
            Parameter[] ps = func.getParameters();
            for (Parameter p : ps) out.add(s(p.getName()));
        } catch (Throwable ignored) {}
        return out;
    }

    private Map<String, Object> analyzeInstructions(Function func) {
        LinkedHashMap<String, Object> root = new LinkedHashMap<String, Object>();
        LinkedHashMap<String, Object> summary = new LinkedHashMap<String, Object>();
        LinkedHashMap<String, Object> stack = new LinkedHashMap<String, Object>();
        LinkedHashMap<String, Integer> pcode = new LinkedHashMap<String, Integer>();
        LinkedHashMap<String, Integer> mnems = new LinkedHashMap<String, Integer>();

        int insCount = 0;
        int callCount = 0;
        int branchCount = 0;
        int condBranchCount = 0;
        int compareCount = 0;
        int leaCount = 0;
        int stackAccessCount = 0;
        int stackWriteLikeCount = 0;

        TreeSet<Long> stackOffsets = new TreeSet<Long>();

        try {
            if (!func.isExternal() && func.getBody() != null) {
                Listing listing = currentProgram.getListing();
                InstructionIterator it = listing.getInstructions(func.getBody(), true);

                while (it.hasNext()) {
                    Instruction ins = it.next();
                    insCount++;

                    String m = s(ins.getMnemonicString()).toLowerCase();
                    inc(mnems, m);

                    String ops = operandsText(ins);
                    boolean stackAccess = containsStackRef(ops);
                    if (stackAccess) {
                        stackAccessCount++;
                        Long off = parseStackOffset(ops);
                        if (off != null) stackOffsets.add(off);
                        if (m.startsWith("mov") || m.startsWith("stos") || m.startsWith("rep")) {
                            stackWriteLikeCount++;
                        }
                    }

                    if (m.contains("call")) callCount++;
                    if (m.startsWith("j") || m.equals("b") || m.equals("bl")) branchCount++;
                    if (m.startsWith("j") && !m.equals("jmp")) condBranchCount++;
                    if (m.equals("cmp") || m.equals("test")) compareCount++;
                    if (m.equals("lea")) leaCount++;

                    try {
                        PcodeOp[] opsPc = ins.getPcode();
                        for (PcodeOp op : opsPc) {
                            inc(pcode, s(op.getMnemonic()));
                        }
                    } catch (Throwable ignored) {}
                }
            }
        } catch (Throwable ignored) {}

        summary.put("instruction_count", insCount);
        summary.put("call_instruction_count", callCount);
        summary.put("branch_count", branchCount);
        summary.put("conditional_branch_count", condBranchCount);
        summary.put("compare_count", compareCount);
        summary.put("lea_count", leaCount);

        ArrayList<Object> offs = new ArrayList<Object>();
        for (Long x : stackOffsets) offs.add(x.longValue());

        stack.put("stack_offsets", offs);
        stack.put("stack_offset_count", stackOffsets.size());
        stack.put("stack_mem_access_count", stackAccessCount);
        stack.put("stack_write_like_count", stackWriteLikeCount);

        root.put("summary", summary);
        root.put("stack", stack);
        root.put("pcode_counts", pcode);
        root.put("mnemonic_counts", mnems);

        return root;
    }

    private Map<String, Object> cfgInfo(Function func) {
        LinkedHashMap<String, Object> m = new LinkedHashMap<String, Object>();

        int blocks = 0;
        int edges = 0;

        try {
            if (!func.isExternal() && func.getBody() != null) {
                BasicBlockModel model = new BasicBlockModel(currentProgram);
                CodeBlockIterator it = model.getCodeBlocksContaining(func.getBody(), monitor);

                while (it.hasNext()) {
                    CodeBlock b = it.next();
                    blocks++;

                    CodeBlockReferenceIterator dests = b.getDestinations(monitor);
                    while (dests.hasNext()) {
                        dests.next();
                        edges++;
                    }
                }
            }
        } catch (Throwable ignored) {}

        m.put("basic_block_count", blocks);
        m.put("edge_count", edges);
        m.put("cyclomatic", Math.max(1, edges - blocks + 2));

        return m;
    }


    private Map<String, Object> callGraphInfoV5(Function func) {
        LinkedHashMap<String, Object> m = new LinkedHashMap<String, Object>();

        int callee = 0;
        int caller = 0;
        int internal = 0;
        int external = 0;

        ArrayList<String> calleeNames = new ArrayList<String>();
        ArrayList<String> callerNames = new ArrayList<String>();

        try {
            Set<Function> cs = func.getCalledFunctions(monitor);
            for (Function f : cs) {
                callee++;

                String nm = normName(f.getName());
                calleeNames.add(nm);

                if (f.isExternal()) external++;
                else internal++;
            }
        } catch (Throwable ignored) {}

        try {
            Set<Function> ps = func.getCallingFunctions(monitor);
            for (Function f : ps) {
                caller++;
                callerNames.add(normName(f.getName()));
            }
        } catch (Throwable ignored) {}

        m.put("callee_count", callee);
        m.put("caller_count", caller);
        m.put("internal_callee_count", internal);
        m.put("external_callee_count", external);
        m.put("external_callee_ratio", callee > 0 ? ((double) external / (double) callee) : 0.0);
        m.put("callee_names", calleeNames);
        m.put("caller_names", callerNames);

        return m;
    }

    private Map<String, Object> callGraphInfo(Function func) {
        LinkedHashMap<String, Object> m = new LinkedHashMap<String, Object>();

        int callee = 0;
        int caller = 0;
        int internal = 0;
        int external = 0;

        try {
            Set<Function> cs = func.getCalledFunctions(monitor);
            for (Function f : cs) {
                callee++;
                if (f.isExternal()) external++;
                else internal++;
            }
        } catch (Throwable ignored) {}

        try {
            Set<Function> ps = func.getCallingFunctions(monitor);
            for (Function f : ps) caller++;
        } catch (Throwable ignored) {}

        m.put("callee_count", callee);
        m.put("caller_count", caller);
        m.put("internal_callee_count", internal);
        m.put("external_callee_count", external);

        return m;
    }

    private ArrayList<Object> parseLocalBuffers(String c) {
        ArrayList<Object> out = new ArrayList<Object>();
        HashSet<String> seen = new HashSet<String>();

        Matcher mm = LOCAL_BUFFER_PATTERN.matcher(c);
        while (mm.find()) {
            String typ = mm.group(1).trim();
            String name = mm.group(2).trim();
            Long count = intFromText(mm.group(3));

            if (count == null || count.longValue() <= 0) continue;
            if (seen.contains(name)) continue;
            seen.add(name);

            long elem = typeSize(typ);
            long bytes = count.longValue() * elem;

            LinkedHashMap<String, Object> b = new LinkedHashMap<String, Object>();
            b.put("name", name);
            b.put("datatype", typ);
            b.put("element_count", count.longValue());
            b.put("element_size", elem);
            b.put("byte_size", bytes);
            b.put("stack_offset", parseStackOffset(name));
            b.put("storage", "stack_or_local");

            out.add(b);
        }

        return out;
    }

    private ArrayList<Object> parseSinks(String c, ArrayList<Object> buffers, ArrayList<String> params) {
        ArrayList<Object> out = new ArrayList<Object>();
        String[] lines = c.split("\\R");

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            Matcher m = CALL_PATTERN.matcher(line);

            while (m.find()) {
                String api = normName(m.group(1));

                if (!INTERESTING.contains(api)) continue;

                ArrayList<String> args = splitArgs(m.group(2));
                int[] sig = dstSrcSizeIndices(api);

                String dstExpr = sig[0] >= 0 && sig[0] < args.size() ? args.get(sig[0]) : "";
                String srcExpr = sig[1] >= 0 && sig[1] < args.size() ? args.get(sig[1]) : "";
                String sizeExpr = sig[2] >= 0 && sig[2] < args.size() ? args.get(sig[2]) : "";

                String dstVar = cleanVar(dstExpr);
                String srcVar = cleanVar(srcExpr);

                Map<String, Object> dstBuf = findBuffer(dstExpr, buffers);
                Map<String, Object> srcBuf = findBuffer(srcExpr, buffers);

                long dstSize = dstBuf == null ? 0L : longVal(dstBuf.get("byte_size"));
                long srcSize = 0L;

                Long litLen = literalLen(srcExpr);
                if (litLen != null) srcSize = litLen.longValue();
                else if (srcBuf != null) srcSize = longVal(srcBuf.get("byte_size"));

                Long sizeVal = parseSizeExprSmart(sizeExpr, dstVar, dstSize);
                long sizeNumber = sizeVal == null ? 0L : sizeVal.longValue();
                boolean sizeExprKnown = sizeVal != null;

                boolean sizeGtDst = sizeExprKnown && dstSize > 0 && sizeNumber > dstSize;
                boolean srcGtDst = dstSize > 0 && srcSize > dstSize;

                LinkedHashMap<String, Object> item = new LinkedHashMap<String, Object>();
                item.put("api", api);
                item.put("line_index", i);
                item.put("line", line.trim());
                item.put("args", args);

                item.put("dst_arg", dstExpr);
                item.put("src_arg", srcExpr);
                item.put("size_arg", sizeExpr);
                item.put("dst_var", dstVar);
                item.put("src_var", srcVar);

                item.put("dst_is_local_buffer", bool(dstBuf != null));
                item.put("dst_buffer_size", dstSize);
                item.put("dst_stack_offset", dstBuf == null ? null : dstBuf.get("stack_offset"));

                String srcOriginV4 = classifySource(srcExpr, buffers, params);

                item.put("src_is_local_buffer", bool(srcBuf != null));
                item.put("src_size_est", srcSize);
                item.put("src_origin", srcOriginV4);

                item.put("size_value", sizeNumber);
                item.put("size_expr_known", bool(sizeExprKnown));
                item.put("size_expr_raw", sizeExpr);
                item.put("size_gt_dst", bool(sizeGtDst));
                item.put("overflow_margin", dstSize > 0 ? sizeNumber - dstSize : 0L);

                item.put("size_to_dst_ratio", dstSize > 0 ? ((double) sizeNumber / (double) dstSize) : 0.0);

                item.put("src_gt_dst", bool(srcGtDst));
                item.put("src_overflow_margin", dstSize > 0 ? srcSize - dstSize : 0L);

                item.put("is_dangerous", bool(DANGEROUS.contains(api)));
                item.put("is_bounded", bool(BOUNDED.contains(api)));
                item.put("is_unbounded", bool(UNBOUNDED.contains(api)));
                item.put("is_input", bool(INPUT_APIS.contains(api)));
                item.put("is_len_check", bool(LEN_APIS.contains(api)));
                item.put("is_buffer_init", bool(BUFFER_INIT.contains(api)));

                Map<String, Object> guardV4 = guardInfo(lines, i, dstVar, srcVar, sizeExpr);
                item.putAll(guardV4);

                addV4CallsiteFeatures(
                    item,
                    api,
                    dstBuf,
                    srcOriginV4,
                    guardV4,
                    dstSize,
                    sizeNumber,
                    sizeVal,
                    srcSize,
                    sizeGtDst,
                    srcGtDst
                );

                out.add(item);
            }
        }

        return out;
    }

    private Map<String, Object> guardInfo(String[] lines, int idx, String dst, String src, String size) {
        LinkedHashMap<String, Object> g = new LinkedHashMap<String, Object>();

        int start = Math.max(0, idx - 8);
        StringBuilder sb = new StringBuilder();

        for (int i = start; i < idx; i++) {
            sb.append(lines[i]).append("\n");
        }

        String text = sb.toString();
        String low = text.toLowerCase();

        boolean hasIf = low.contains("if");
        boolean hasCmp = low.contains("<") || low.contains(">") || low.contains("<=") ||
                         low.contains(">=") || low.contains("==") || low.contains("!=");
        boolean hasLen = low.contains("strlen") || low.contains("wcslen") ||
                         low.contains("strnlen") || low.contains("wcsnlen") ||
                         low.contains("sizeof");
        boolean hasBoundWord = low.contains("len") || low.contains("size") ||
                               low.contains("count") || low.contains("bound");

        g.put("has_guard_before", bool(hasIf && (hasCmp || hasLen || hasBoundWord)));
        g.put("has_if_before", bool(hasIf));
        g.put("has_len_check_before", bool(hasLen));
        g.put("has_compare_before", bool(hasCmp));
        g.put("guard_mentions_dst", bool(dst != null && dst.length() > 0 && low.contains(dst.toLowerCase())));
        g.put("guard_mentions_src", bool(src != null && src.length() > 0 && low.contains(src.toLowerCase())));
        g.put("guard_mentions_size_arg", bool(size != null && size.length() > 0 && low.contains(size.toLowerCase())));
        boolean mentionsDstV4 = dst != null && dst.length() > 0 && low.contains(dst.toLowerCase());
        boolean mentionsSrcV4 = src != null && src.length() > 0 && low.contains(src.toLowerCase());
        boolean mentionsSizeV4 = size != null && size.length() > 0 && low.contains(size.toLowerCase());

        boolean usesStrlenSrc = false;
        boolean usesSizeofDst = false;

        try {
            if (src != null && src.length() > 0) {
                usesStrlenSrc = cachedPattern(
                    "\\b(?:strlen|wcslen|strnlen|wcsnlen)\\s*\\(\\s*" + Pattern.quote(src.toLowerCase()) + "\\s*\\)",
                    0
                ).matcher(low).find();
            }

            if (dst != null && dst.length() > 0) {
                usesSizeofDst = cachedPattern(
                    "\\bsizeof\\s*\\(\\s*" + Pattern.quote(dst.toLowerCase()) + "\\s*\\)",
                    0
                ).matcher(low).find();
            }
        } catch (Throwable ignored) {}

        double guardQuality = 0.0;

        if (hasIf && (hasCmp || hasLen || hasBoundWord)) guardQuality += 1.0;
        if (hasCmp) guardQuality += 1.0;
        if (mentionsDstV4) guardQuality += 1.5;
        if (mentionsSrcV4) guardQuality += 1.5;
        if (mentionsSizeV4) guardQuality += 1.0;
        if (hasLen) guardQuality += 1.0;
        if (usesStrlenSrc) guardQuality += 1.5;
        if (usesSizeofDst) guardQuality += 1.5;
        if (hasBoundWord) guardQuality += 0.5;

        boolean highQualityGuard =
            guardQuality >= 4.0 &&
            (mentionsDstV4 || mentionsSrcV4 || mentionsSizeV4 || usesStrlenSrc || usesSizeofDst);

        g.put("v4_guard_mentions_dst", bool(mentionsDstV4));
        g.put("v4_guard_mentions_src", bool(mentionsSrcV4));
        g.put("v4_guard_mentions_size_arg", bool(mentionsSizeV4));
        g.put("v4_guard_uses_strlen_src", bool(usesStrlenSrc));
        g.put("v4_guard_uses_sizeof_dst", bool(usesSizeofDst));
        g.put("v4_guard_quality_score", guardQuality);
        g.put("v4_high_quality_guard", bool(highQualityGuard));

        g.put("guard_text", text.length() > 400 ? text.substring(text.length() - 400) : text);

        return g;
    }

    private Map<String, Object> summarizeBuffers(ArrayList<Object> buffers) {
        LinkedHashMap<String, Object> m = new LinkedHashMap<String, Object>();

        long min = Long.MAX_VALUE;
        long max = 0;
        long total = 0;
        int known = 0;
        int offsetKnown = 0;

        for (Object o : buffers) {
            Map<?, ?> b = (Map<?, ?>) o;
            long sz = longVal(b.get("byte_size"));

            if (sz > 0) {
                known++;
                total += sz;
                if (sz < min) min = sz;
                if (sz > max) max = sz;
            }

            if (b.get("stack_offset") != null) offsetKnown++;
        }

        m.put("local_buffer_count", buffers.size());
        m.put("local_buffer_size_known_count", known);
        m.put("local_buffer_size_min", known > 0 ? min : 0);
        m.put("local_buffer_size_max", max);
        m.put("local_buffer_size_total", total);
        m.put("local_buffer_stack_offset_known_count", offsetKnown);

        return m;
    }

    private Map<String, Object> summarizeSinks(ArrayList<Object> sinks) {
        LinkedHashMap<String, Object> m = new LinkedHashMap<String, Object>();

        int sinkCount = sinks.size();
        int dangerous = 0, bounded = 0, unbounded = 0, input = 0, init = 0;
        int dstLocal = 0, dstSizeKnown = 0, sizeConst = 0, sizeGtDst = 0, srcGtDst = 0;
        int guarded = 0, unguarded = 0, unboundedStack = 0, safeMisuse = 0;
        int srcParam = 0, srcLiteral = 0, srcLocal = 0, srcUnknown = 0;
        long maxSize = 0, maxDst = 0, maxMargin = 0;
        double maxRatio = 0.0;

        for (Object o : sinks) {
            Map<?, ?> s = (Map<?, ?>) o;

            boolean isDanger = truth(s.get("is_dangerous"));
            boolean isBounded = truth(s.get("is_bounded"));
            boolean isUnbounded = truth(s.get("is_unbounded"));
            boolean isInput = truth(s.get("is_input"));
            boolean isInit = truth(s.get("is_buffer_init"));
            boolean dstIsLocal = truth(s.get("dst_is_local_buffer"));
            boolean hasGuard = truth(s.get("has_guard_before"));
            boolean sizeOver = truth(s.get("size_gt_dst"));
            boolean srcOver = truth(s.get("src_gt_dst"));

            long sizeVal = longVal(s.get("size_value"));
            long dstSize = longVal(s.get("dst_buffer_size"));
            long margin = longVal(s.get("overflow_margin"));
            double ratio = doubleVal(s.get("size_to_dst_ratio"));

            String srcOrigin = stringVal(s.get("src_origin"));

            if (isDanger) dangerous++;
            if (isBounded) bounded++;
            if (isUnbounded) unbounded++;
            if (isInput) input++;
            if (isInit) init++;

            if (dstIsLocal) dstLocal++;
            if (dstSize > 0) dstSizeKnown++;
            if (sizeVal > 0) sizeConst++;
            if (sizeOver) sizeGtDst++;
            if (srcOver) srcGtDst++;

            if (hasGuard) guarded++;
            if (!hasGuard && (isDanger || isBounded)) unguarded++;

            if (isUnbounded && dstIsLocal) unboundedStack++;
            if (isBounded && sizeOver) safeMisuse++;

            if ("parameter".equals(srcOrigin)) srcParam++;
            else if ("literal".equals(srcOrigin)) srcLiteral++;
            else if ("local_buffer".equals(srcOrigin)) srcLocal++;
            else if ("unknown".equals(srcOrigin) || "local_or_unknown".equals(srcOrigin)) srcUnknown++;

            if (sizeVal > maxSize) maxSize = sizeVal;
            if (dstSize > maxDst) maxDst = dstSize;
            if (margin > maxMargin) maxMargin = margin;
            if (ratio > maxRatio) maxRatio = ratio;
        }

        m.put("sink_count", sinkCount);
        m.put("dangerous_sink_count", dangerous);
        m.put("bounded_sink_count", bounded);
        m.put("unbounded_sink_count", unbounded);
        m.put("input_api_count", input);
        m.put("buffer_init_count", init);
        m.put("dst_local_buffer_count", dstLocal);
        m.put("dst_size_known_count", dstSizeKnown);
        m.put("size_const_count", sizeConst);
        m.put("size_gt_dst_count", sizeGtDst);
        m.put("src_gt_dst_count", srcGtDst);
        m.put("guarded_sink_count", guarded);
        m.put("unguarded_sink_count", unguarded);
        m.put("unbounded_stack_sink_count", unboundedStack);
        m.put("safe_api_misuse_count", safeMisuse);
        m.put("max_size_value", maxSize);
        m.put("max_dst_buffer_size", maxDst);
        m.put("max_overflow_margin", maxMargin);
        m.put("max_size_to_dst_ratio", maxRatio);
        m.put("source_parameter_count", srcParam);
        m.put("source_literal_count", srcLiteral);
        m.put("source_local_buffer_count", srcLocal);
        m.put("source_unknown_count", srcUnknown);

        return m;
    }


    private void addV4CallsiteFeatures(
        LinkedHashMap<String, Object> item,
        String api,
        Map<String, Object> dstBuf,
        String srcOrigin,
        Map<String, Object> guard,
        long dstSize,
        long sizeNumber,
        Long sizeVal,
        long srcSize,
        boolean sizeGtDst,
        boolean srcGtDst
    ) {
        boolean dstLocal = dstBuf != null;

        boolean isDanger = DANGEROUS.contains(api);
        boolean isBounded = BOUNDED.contains(api);
        boolean isUnbounded = UNBOUNDED.contains(api);
        boolean isInput = INPUT_APIS.contains(api);
        boolean isFormat = "sprintf".equals(api) || "snprintf".equals(api) ||
                           "swprintf".equals(api) || "vsprintf".equals(api) ||
                           "vsnprintf".equals(api) || "vswprintf".equals(api);

        boolean hasGuard = truth(guard.get("has_guard_before"));
        boolean highQualityGuard = truth(guard.get("v4_high_quality_guard"));
        double guardQuality = doubleVal(guard.get("v4_guard_quality_score"));

        boolean sizeKnown = sizeVal != null && sizeNumber > 0;
        boolean sizeLeDst = dstSize > 0 && sizeKnown && sizeNumber <= dstSize;
        boolean srcLeDst = dstSize > 0 && srcSize > 0 && srcSize <= dstSize;

        boolean srcLiteral = "literal".equals(srcOrigin);
        boolean srcExternal =
            "parameter".equals(srcOrigin) ||
            "input_like".equals(srcOrigin) ||
            "local_or_unknown".equals(srcOrigin) ||
            "unknown".equals(srcOrigin);

        double riskScore = 0.0;
        double safeScore = 0.0;

        if (dstLocal && isDanger) riskScore += 3.0;
        if (dstLocal && isUnbounded) riskScore += 4.0;
        if (dstLocal && isInput) riskScore += 3.0;
        if (dstLocal && srcExternal) riskScore += 2.0;
        if (dstLocal && isDanger && !hasGuard) riskScore += 2.0;
        if (dstLocal && isUnbounded && !highQualityGuard) riskScore += 2.5;
        if (dstLocal && isUnbounded && !sizeKnown) riskScore += 1.5;
        if (sizeGtDst) riskScore += 5.0;
        if (srcGtDst) riskScore += 3.0;

        if (srcLiteral) safeScore += 2.5;
        if (srcLiteral && srcLeDst) safeScore += 2.0;
        if (isBounded && dstLocal) safeScore += 1.0;
        if (sizeLeDst) safeScore += 2.0;
        if (highQualityGuard) safeScore += 3.0;
        if (guardQuality >= 5.0) safeScore += 1.0;
        if (!dstLocal && isDanger) safeScore += 1.5;

        boolean likelyVuln = riskScore >= 6.0 && riskScore > safeScore;
        boolean likelySafe = safeScore >= 4.0 && safeScore >= riskScore;

        item.put("v4_direct_stack_sink", bool(dstLocal && (isDanger || isBounded || isInput || isFormat)));
        item.put("v4_dangerous_stack_sink", bool(dstLocal && isDanger));
        item.put("v4_unbounded_stack_sink", bool(dstLocal && isUnbounded));
        item.put("v4_bounded_stack_sink", bool(dstLocal && isBounded));
        item.put("v4_input_stack_sink", bool(dstLocal && isInput));
        item.put("v4_format_stack_sink", bool(dstLocal && isFormat));

        item.put("v4_external_source_to_stack", bool(dstLocal && srcExternal));
        item.put("v4_literal_source_to_stack", bool(dstLocal && srcLiteral));
        item.put("v4_unknown_source_to_stack", bool(dstLocal && "unknown".equals(srcOrigin)));

        item.put("v4_size_unknown_unbounded_stack_sink", bool(dstLocal && isUnbounded && !sizeKnown));
        item.put("v4_unbounded_stack_no_guard", bool(dstLocal && isUnbounded && !hasGuard));
        item.put("v4_unbounded_stack_weak_guard", bool(dstLocal && isUnbounded && hasGuard && !highQualityGuard));
        item.put("v4_dangerous_stack_no_guard", bool(dstLocal && isDanger && !hasGuard));

        item.put("v4_stack_size_overflow", bool(sizeGtDst || srcGtDst));
        item.put("v4_stack_size_safe", bool(sizeLeDst || srcLeDst));

        item.put("v4_high_quality_guard", bool(highQualityGuard));
        item.put("v4_guard_quality_score", guardQuality);

        item.put("v4_risk_score", riskScore);
        item.put("v4_safe_score", safeScore);
        item.put("v4_risk_minus_safe", riskScore - safeScore);

        item.put("v4_likely_vulnerable_callsite", bool(likelyVuln));
        item.put("v4_likely_safe_callsite", bool(likelySafe));
    }

    private Map<String, Object> summarizeV4(ArrayList<Object> sinks) {
        LinkedHashMap<String, Object> m = new LinkedHashMap<String, Object>();

        int directStack = 0;
        int dangerStack = 0;
        int unboundedStack = 0;
        int boundedStack = 0;
        int inputStack = 0;
        int formatStack = 0;

        int externalStack = 0;
        int literalStack = 0;
        int unknownStack = 0;

        int sizeUnknownUnboundedStack = 0;
        int unboundedStackNoGuard = 0;
        int unboundedStackWeakGuard = 0;
        int dangerStackNoGuard = 0;

        int stackOverflow = 0;
        int stackSizeSafe = 0;
        int highGuard = 0;
        int likelyVuln = 0;
        int likelySafe = 0;

        double riskTotal = 0.0;
        double safeTotal = 0.0;
        double riskMinusSafeMax = -999999.0;
        double guardQualityTotal = 0.0;
        double guardQualityMax = 0.0;

        for (Object o : sinks) {
            Map<?, ?> s = (Map<?, ?>) o;

            if (truth(s.get("v4_direct_stack_sink"))) directStack++;
            if (truth(s.get("v4_dangerous_stack_sink"))) dangerStack++;
            if (truth(s.get("v4_unbounded_stack_sink"))) unboundedStack++;
            if (truth(s.get("v4_bounded_stack_sink"))) boundedStack++;
            if (truth(s.get("v4_input_stack_sink"))) inputStack++;
            if (truth(s.get("v4_format_stack_sink"))) formatStack++;

            if (truth(s.get("v4_external_source_to_stack"))) externalStack++;
            if (truth(s.get("v4_literal_source_to_stack"))) literalStack++;
            if (truth(s.get("v4_unknown_source_to_stack"))) unknownStack++;

            if (truth(s.get("v4_size_unknown_unbounded_stack_sink"))) sizeUnknownUnboundedStack++;
            if (truth(s.get("v4_unbounded_stack_no_guard"))) unboundedStackNoGuard++;
            if (truth(s.get("v4_unbounded_stack_weak_guard"))) unboundedStackWeakGuard++;
            if (truth(s.get("v4_dangerous_stack_no_guard"))) dangerStackNoGuard++;

            if (truth(s.get("v4_stack_size_overflow"))) stackOverflow++;
            if (truth(s.get("v4_stack_size_safe"))) stackSizeSafe++;
            if (truth(s.get("v4_high_quality_guard"))) highGuard++;

            if (truth(s.get("v4_likely_vulnerable_callsite"))) likelyVuln++;
            if (truth(s.get("v4_likely_safe_callsite"))) likelySafe++;

            double r = doubleVal(s.get("v4_risk_score"));
            double sf = doubleVal(s.get("v4_safe_score"));
            double rms = doubleVal(s.get("v4_risk_minus_safe"));
            double gq = doubleVal(s.get("v4_guard_quality_score"));

            riskTotal += r;
            safeTotal += sf;
            guardQualityTotal += gq;

            if (rms > riskMinusSafeMax) riskMinusSafeMax = rms;
            if (gq > guardQualityMax) guardQualityMax = gq;
        }

        double denom = sinks.size() + 1.0;

        m.put("v4_direct_stack_sink_count", directStack);
        m.put("v4_dangerous_stack_sink_count", dangerStack);
        m.put("v4_unbounded_stack_sink_count", unboundedStack);
        m.put("v4_bounded_stack_sink_count", boundedStack);
        m.put("v4_input_stack_sink_count", inputStack);
        m.put("v4_format_stack_sink_count", formatStack);

        m.put("v4_external_source_stack_sink_count", externalStack);
        m.put("v4_literal_source_stack_sink_count", literalStack);
        m.put("v4_unknown_source_stack_sink_count", unknownStack);

        m.put("v4_size_unknown_unbounded_stack_sink_count", sizeUnknownUnboundedStack);
        m.put("v4_unbounded_stack_no_guard_count", unboundedStackNoGuard);
        m.put("v4_unbounded_stack_weak_guard_count", unboundedStackWeakGuard);
        m.put("v4_dangerous_stack_no_guard_count", dangerStackNoGuard);

        m.put("v4_stack_size_overflow_count", stackOverflow);
        m.put("v4_stack_size_safe_count", stackSizeSafe);
        m.put("v4_high_quality_guard_count", highGuard);
        m.put("v4_likely_vulnerable_callsite_count", likelyVuln);
        m.put("v4_likely_safe_callsite_count", likelySafe);

        m.put("v4_risk_score_total", riskTotal);
        m.put("v4_safe_score_total", safeTotal);
        m.put("v4_risk_minus_safe_total", riskTotal - safeTotal);
        m.put("v4_risk_minus_safe_max", riskMinusSafeMax == -999999.0 ? 0.0 : riskMinusSafeMax);

        m.put("v4_guard_quality_total", guardQualityTotal);
        m.put("v4_guard_quality_max", guardQualityMax);

        m.put("v4_direct_stack_sink_ratio", directStack / denom);
        m.put("v4_unbounded_stack_sink_ratio", unboundedStack / denom);
        m.put("v4_external_source_stack_ratio", externalStack / denom);
        m.put("v4_literal_source_stack_ratio", literalStack / denom);
        m.put("v4_high_quality_guard_ratio", highGuard / denom);
        m.put("v4_likely_vulnerable_ratio", likelyVuln / denom);
        m.put("v4_likely_safe_ratio", likelySafe / denom);

        m.put(
            "v4_fp_suppression_score",
            safeTotal + highGuard * 2.0 + literalStack * 2.0 + boundedStack
            - unboundedStackNoGuard * 2.0 - stackOverflow * 3.0
        );

        m.put(
            "v4_strict_sbo_risk_score",
            riskTotal + likelyVuln * 3.0 + stackOverflow * 4.0 + unboundedStackNoGuard * 2.0
        );

        return m;
    }




    // =========================
    // V6 context features
    // =========================

    private ArrayList<Object> analyzeAliasesV6(String c, ArrayList<Object> buffers) {
        ArrayList<Object> out = new ArrayList<Object>();
        HashSet<String> seen = new HashSet<String>();

        String[] lines = s(c).split("\\R");

        ArrayList<String> bufNames = new ArrayList<String>();
        for (Object o : buffers) {
            Map<?, ?> b = (Map<?, ?>) o;
            String nm = stringVal(b.get("name"));
            if (nm.length() > 0) bufNames.add(nm);
        }

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];

            for (String buf : bufNames) {
                Pattern p1 = cachedPattern(
                    "\\b([A-Za-z_]\\w*)\\s*=\\s*&?\\s*" + Pattern.quote(buf) + "\\b\\s*;",
                    Pattern.CASE_INSENSITIVE
                );

                Matcher m1 = p1.matcher(line);
                while (m1.find()) {
                    String alias = m1.group(1);
                    if (alias.equals(buf)) continue;

                    String key = alias + "->" + buf;
                    if (seen.contains(key)) continue;
                    seen.add(key);

                    LinkedHashMap<String, Object> a = new LinkedHashMap<String, Object>();
                    a.put("alias", alias);
                    a.put("target", buf);
                    a.put("line_index", i);
                    a.put("line", line.trim());
                    a.put("target_is_stack_buffer", bool(true));

                    Map<String, Object> targetBuf = findBufferByNameV6(buf, buffers);
                    a.put("target_size", targetBuf == null ? 0L : longVal(targetBuf.get("byte_size")));
                    a.put("target_stack_offset", targetBuf == null ? null : targetBuf.get("stack_offset"));

                    out.add(a);
                }

                Pattern p2 = cachedPattern(
                    "\\b(?:char|wchar_t|byte|undefined|void|int|uint|long|short)\\s*\\*+\\s*([A-Za-z_]\\w*)\\s*=\\s*&?\\s*" +
                    Pattern.quote(buf) + "\\b\\s*;",
                    Pattern.CASE_INSENSITIVE
                );

                Matcher m2 = p2.matcher(line);
                while (m2.find()) {
                    String alias = m2.group(1);
                    if (alias.equals(buf)) continue;

                    String key = alias + "->" + buf;
                    if (seen.contains(key)) continue;
                    seen.add(key);

                    LinkedHashMap<String, Object> a = new LinkedHashMap<String, Object>();
                    a.put("alias", alias);
                    a.put("target", buf);
                    a.put("line_index", i);
                    a.put("line", line.trim());
                    a.put("target_is_stack_buffer", bool(true));

                    Map<String, Object> targetBuf = findBufferByNameV6(buf, buffers);
                    a.put("target_size", targetBuf == null ? 0L : longVal(targetBuf.get("byte_size")));
                    a.put("target_stack_offset", targetBuf == null ? null : targetBuf.get("stack_offset"));

                    out.add(a);
                }
            }
        }

        return out;
    }

    private Map<String, Object> summarizeAliasesV6(ArrayList<Object> aliases) {
        LinkedHashMap<String, Object> m = new LinkedHashMap<String, Object>();

        int count = aliases.size();
        int stackAlias = 0;
        long maxTargetSize = 0;

        for (Object o : aliases) {
            Map<?, ?> a = (Map<?, ?>) o;

            if (truth(a.get("target_is_stack_buffer"))) stackAlias++;

            long sz = longVal(a.get("target_size"));
            if (sz > maxTargetSize) maxTargetSize = sz;
        }

        m.put("v6_alias_count", count);
        m.put("v6_stack_buffer_alias_count", stackAlias);
        m.put("v6_alias_target_size_max", maxTargetSize);

        return m;
    }

    private Map<String, Object> analyzeLoopsV6(String c, ArrayList<Object> buffers, ArrayList<String> params) {
        LinkedHashMap<String, Object> m = new LinkedHashMap<String, Object>();

        String[] lines = s(c).split("\\R");

        int loopCount = 0;
        int loopWritesStack = 0;
        int loopReadsExternal = 0;
        int loopBoundConst = 0;
        int loopBoundUnknown = 0;
        int loopHasIndexGuard = 0;
        int loopCopyRisk = 0;

        for (int i = 0; i < lines.length; i++) {
            String low = lines[i].toLowerCase();

            boolean isLoop = LOOP_PATTERN.matcher(low).find();

            if (!isLoop) continue;

            loopCount++;

            String window = windowTextV6(lines, i, Math.min(lines.length - 1, i + 10)).toLowerCase();

            boolean writesStack = containsStackBufferWriteV6(window, buffers);
            boolean readsExternal = hasInputSourceTextV6(window);
            boolean hasConst = intFromText(lines[i]) != null;
            boolean indexGuard =
                window.contains("<") || window.contains("<=") ||
                window.contains("len") || window.contains("size") ||
                window.contains("strlen") || window.contains("sizeof");

            if (writesStack) loopWritesStack++;
            if (readsExternal) loopReadsExternal++;
            if (hasConst) loopBoundConst++;
            else loopBoundUnknown++;
            if (indexGuard) loopHasIndexGuard++;

            if (writesStack && (readsExternal || !indexGuard || !hasConst)) {
                loopCopyRisk++;
            }
        }

        m.put("v6_loop_count", loopCount);
        m.put("v6_loop_writes_stack_count", loopWritesStack);
        m.put("v6_loop_reads_external_source_count", loopReadsExternal);
        m.put("v6_loop_bound_const_count", loopBoundConst);
        m.put("v6_loop_bound_unknown_count", loopBoundUnknown);
        m.put("v6_loop_has_index_guard_count", loopHasIndexGuard);
        m.put("v6_loop_copy_risk_count", loopCopyRisk);
        m.put("v6_loop_copy_risk_score", loopCopyRisk * 3.0 + loopWritesStack + loopReadsExternal);

        return m;
    }

    private Map<String, Object> functionRoleV6(Function func, String c, ArrayList<Object> sinks) {
        LinkedHashMap<String, Object> m = new LinkedHashMap<String, Object>();

        String name = normName(func.getName()).toLowerCase();
        String text = s(c).trim();
        String low = text.toLowerCase();

        boolean decompOk = text.length() > 0;
        boolean isExternal = false;
        boolean isThunk = false;

        try { isExternal = func.isExternal(); } catch (Throwable ignored) {}
        try { isThunk = func.isThunk(); } catch (Throwable ignored) {}

        int lineCount = text.length() == 0 ? 0 : text.split("\\R").length;

        int selfCallLike = 0;
        if (name.length() > 0 && low.contains(name + "(")) selfCallLike++;

        boolean libcWrapper =
            lineCount <= 12 &&
            sinks.size() > 0 &&
            selfCallLike > 0;

        boolean hasRealBody =
            decompOk &&
            !isExternal &&
            !isThunk &&
            !libcWrapper &&
            lineCount > 3;

        m.put("v6_decompile_success", bool(decompOk));
        m.put("v6_is_external", bool(isExternal));
        m.put("v6_is_thunk", bool(isThunk));
        m.put("v6_is_libc_wrapper_like", bool(libcWrapper));
        m.put("v6_has_real_body", bool(hasRealBody));
        m.put("v6_decompiled_line_count", lineCount);
        m.put("v6_function_sink_count", sinks.size());

        return m;
    }

    private void enrichSinksV6(
        String c,
        ArrayList<Object> buffers,
        ArrayList<String> params,
        ArrayList<Object> sinks,
        ArrayList<Object> aliases
    ) {
        String[] lines = s(c).split("\\R");

        for (Object o : sinks) {
            if (!(o instanceof Map)) continue;

            Map<String, Object> item = (Map<String, Object>) o;

            String api = normName(item.get("api")).toLowerCase();
            int idx = (int) longVal(item.get("line_index"));

            String dstExpr = stringVal(item.get("dst_arg"));
            String srcExpr = stringVal(item.get("src_arg"));
            String sizeExpr = stringVal(item.get("size_arg"));

            String dstVarRaw = cleanVar(dstExpr);
            String srcVarRaw = cleanVar(srcExpr);

            String dstVar = resolveAliasV6(dstVarRaw, aliases);
            String srcVar = resolveAliasV6(srcVarRaw, aliases);

            Map<String, Object> dstBuf = findBufferV6(dstExpr, buffers, aliases);
            Map<String, Object> srcBuf = findBufferV6(srcExpr, buffers, aliases);

            long dstSize = dstBuf == null ? longVal(item.get("dst_buffer_size")) : longVal(dstBuf.get("byte_size"));
            long srcSize = 0L;

            Long litLen = literalLen(srcExpr);
            if (litLen != null) srcSize = litLen.longValue();
            else if (srcBuf != null) srcSize = longVal(srcBuf.get("byte_size"));
            else srcSize = longVal(item.get("src_size_est"));

            Long sizeParsed = parseSizeExprSmart(sizeExpr, dstVar, dstSize);
            boolean sizeExprKnown2 = sizeParsed != null || truth(item.get("size_expr_known"));
            long sizeNumber = sizeParsed == null ? (sizeExprKnown2 ? longVal(item.get("size_value")) : 0L) : sizeParsed.longValue();

            boolean sizeofDst = exprUsesSizeofVarV6(sizeExpr, dstVarRaw) || exprUsesSizeofVarV6(sizeExpr, dstVar);
            if (sizeofDst && dstSize > 0 && !sizeExprKnown2) {
                sizeNumber = dstSize;
                sizeExprKnown2 = true;
            }

            boolean dstStack = dstBuf != null || truth(item.get("dst_is_local_buffer"));
            boolean srcStack = srcBuf != null || truth(item.get("src_is_local_buffer"));

            boolean dstSizeKnown = dstStack && dstSize > 0;
            boolean sizeKnown = sizeExprKnown2 || sizeofDst;

            boolean sizeGtDst = dstSizeKnown && sizeKnown && sizeNumber > dstSize;
            boolean sizeEqDst = dstSizeKnown && sizeKnown && sizeNumber == dstSize;
            boolean sizeLtDst = dstSizeKnown && sizeKnown && sizeNumber < dstSize;

            boolean literalGtDst = dstSizeKnown && litLen != null && litLen.longValue() > dstSize;
            boolean literalLeDst = dstSizeKnown && litLen != null && litLen.longValue() <= dstSize;

            String guardText = stringVal(item.get("guard_text"));
            String guardLow = guardText.toLowerCase();

            boolean hasGuard = truth(item.get("has_guard_before"));
            boolean highGuard = truth(item.get("v4_high_quality_guard"));

            boolean sizeGuard =
                hasGuard &&
                (
                    guardLow.contains("strlen") ||
                    guardLow.contains("wcslen") ||
                    guardLow.contains("strnlen") ||
                    guardLow.contains("sizeof") ||
                    guardLow.contains("len") ||
                    guardLow.contains("size") ||
                    guardLow.contains("count")
                ) &&
                (
                    guardLow.contains("<") ||
                    guardLow.contains(">") ||
                    guardLow.contains("<=") ||
                    guardLow.contains(">=") ||
                    guardLow.contains("==") ||
                    guardLow.contains("!=")
                );

            boolean strlenGuard =
                guardLow.contains("strlen") ||
                guardLow.contains("wcslen") ||
                guardLow.contains("strnlen") ||
                guardLow.contains("wcsnlen");

            boolean sizeofGuard = guardLow.contains("sizeof");

            boolean guardMentionsDst =
                truth(item.get("guard_mentions_dst")) ||
                truth(item.get("v4_guard_mentions_dst")) ||
                (dstVar.length() > 0 && guardLow.contains(dstVar.toLowerCase()));

            boolean guardMentionsSrc =
                truth(item.get("guard_mentions_src")) ||
                truth(item.get("v4_guard_mentions_src")) ||
                (srcVar.length() > 0 && guardLow.contains(srcVar.toLowerCase()));

            boolean strongGuard =
                highGuard ||
                (
                    sizeGuard &&
                    (guardMentionsDst || guardMentionsSrc || sizeofGuard || strlenGuard)
                );

            boolean weakGuard = hasGuard && !strongGuard;

            String before20 = windowTextV6(lines, Math.max(0, idx - 20), Math.max(0, idx - 1));
            String before8 = windowTextV6(lines, Math.max(0, idx - 8), Math.max(0, idx - 1));

            boolean sourceApiBefore = hasInputSourceTextV6(before20);

            String srcOrigin = stringVal(item.get("src_origin"));
            boolean srcExternal =
                "parameter".equals(srcOrigin) ||
                "input_like".equals(srcOrigin) ||
                "local_or_unknown".equals(srcOrigin) ||
                "unknown".equals(srcOrigin) ||
                sourceApiBefore;

            boolean sourceReachesSink =
                dstStack &&
                (
                    srcExternal ||
                    sourceApiBefore ||
                    sourceAssignedBeforeV6(before20, srcVarRaw) ||
                    sourceAssignedBeforeV6(before20, srcVar)
                );

            int sourceDist = minSourceDistanceBeforeV6(lines, idx);

            boolean chkApi = api.endsWith("_chk");

            boolean snprintfSafe =
                (api.equals("snprintf") || api.equals("vsnprintf") || api.equals("snprintf_chk") || api.equals("vsnprintf_chk")) &&
                dstStack &&
                (sizeLtDst || sizeEqDst || sizeofDst);

            boolean strncpySafe =
                (api.equals("strncpy") || api.equals("strncat") || api.equals("strncpy_chk") || api.equals("strncat_chk")) &&
                dstStack &&
                (sizeLtDst || sizeEqDst || sizeofDst);

            boolean memcpySafe =
                (api.equals("memcpy") || api.equals("memmove") || api.equals("memcpy_chk") || api.equals("memmove_chk")) &&
                dstStack &&
                (sizeLtDst || sizeEqDst || sizeofDst);

            boolean literalSafe = dstStack && literalLeDst;

            boolean safeProof =
                snprintfSafe ||
                strncpySafe ||
                memcpySafe ||
                literalSafe ||
                chkApi ||
                strongGuard;

            double risk = 0.0;
            double safe = 0.0;

            boolean dangerous = DANGEROUS.contains(api);
            boolean bounded = BOUNDED.contains(api);
            boolean unbounded = UNBOUNDED.contains(api);
            boolean inputApi = INPUT_APIS.contains(api);

            if (dstStack && dangerous) risk += 3.0;
            if (dstStack && unbounded) risk += 4.0;
            if (dstStack && inputApi) risk += 3.0;
            if (dstStack && srcExternal) risk += 2.0;
            if (dstStack && dangerous && !hasGuard) risk += 2.0;
            if (dstStack && unbounded && !strongGuard) risk += 2.5;
            if (dstStack && !sizeKnown && (bounded || dangerous)) risk += 1.5;
            if (sizeGtDst) risk += 5.0;
            if (literalGtDst) risk += 4.0;
            if (sourceReachesSink && !strongGuard) risk += 2.0;
            if (weakGuard && unbounded) risk += 1.0;

            if (safeProof) safe += 3.0;
            if (strongGuard) safe += 3.0;
            if (sizeLtDst || sizeEqDst) safe += 2.0;
            if (literalSafe) safe += 2.0;
            if (chkApi) safe += 2.0;
            if (bounded && dstStack && !sizeGtDst) safe += 1.0;
            if (!dstStack && dangerous) safe += 1.0;

            item.put("v6_dst_is_stack_buffer", bool(dstStack));
            item.put("v6_dst_stack_size_known", bool(dstSizeKnown));
            item.put("v6_dst_stack_size", dstSize);
            item.put("v6_dst_via_alias", bool(!dstVarRaw.equals(dstVar) && dstVar.length() > 0));
            item.put("v6_resolved_dst_var", dstVar);

            item.put("v6_src_is_stack_buffer", bool(srcStack));
            item.put("v6_src_is_literal", bool(litLen != null));
            item.put("v6_src_literal_len", litLen == null ? 0L : litLen.longValue());
            item.put("v6_src_external_like", bool(srcExternal));
            item.put("v6_src_via_alias", bool(!srcVarRaw.equals(srcVar) && srcVar.length() > 0));
            item.put("v6_resolved_src_var", srcVar);

            item.put("v6_size_arg_const", bool(sizeKnown && !sizeofDst));
            item.put("v6_size_expr_known", bool(sizeExprKnown2));
            item.put("v6_size_arg_sizeof_dst", bool(sizeofDst));
            item.put("v6_size_arg_unknown", bool(!sizeKnown));
            item.put("v6_size_value", sizeNumber);
            item.put("v6_size_gt_dst", bool(sizeGtDst));
            item.put("v6_size_eq_dst", bool(sizeEqDst));
            item.put("v6_size_lt_dst", bool(sizeLtDst));
            item.put("v6_size_to_dst_ratio", dstSize > 0 ? ((double) sizeNumber / (double) dstSize) : 0.0);

            item.put("v6_literal_len_gt_dst", bool(literalGtDst));
            item.put("v6_literal_len_le_dst", bool(literalLeDst));

            item.put("v6_guard_before_sink", bool(hasGuard));
            item.put("v6_size_guard_before_sink", bool(sizeGuard));
            item.put("v6_strlen_guard_before_sink", bool(strlenGuard));
            item.put("v6_sizeof_guard_before_sink", bool(sizeofGuard));
            item.put("v6_guard_mentions_dst_or_src", bool(guardMentionsDst || guardMentionsSrc));
            item.put("v6_strong_guard", bool(strongGuard));
            item.put("v6_weak_guard", bool(weakGuard));
            item.put("v6_sink_without_guard", bool(!hasGuard));

            item.put("v6_source_api_before_sink", bool(sourceApiBefore));
            item.put("v6_source_reaches_sink", bool(sourceReachesSink));
            item.put("v6_source_to_sink_line_distance", sourceDist);

            item.put("v6_snprintf_size_le_dst", bool(snprintfSafe));
            item.put("v6_strncpy_bound_le_dst", bool(strncpySafe));
            item.put("v6_memcpy_bound_le_dst", bool(memcpySafe));
            item.put("v6_literal_copy_safe", bool(literalSafe));
            item.put("v6_chk_api", bool(chkApi));
            item.put("v6_safe_proof", bool(safeProof));

            item.put("v6_callsite_risk_score", risk);
            item.put("v6_callsite_safe_score", safe);
            item.put("v6_callsite_risk_minus_safe", risk - safe);
            item.put("v6_likely_vulnerable_callsite", bool(risk >= 6.0 && risk > safe));
            item.put("v6_likely_safe_callsite", bool(safe >= 4.0 && safe >= risk));

            item.put("v6_context_before8", before8.length() > 500 ? before8.substring(before8.length() - 500) : before8);
        }
    }

    private Map<String, Object> summarizeV6Context(
        String c,
        ArrayList<Object> buffers,
        ArrayList<String> params,
        ArrayList<Object> sinks,
        ArrayList<Object> aliases
    ) {
        LinkedHashMap<String, Object> m = new LinkedHashMap<String, Object>();

        int sinkCount = sinks.size();

        int dstStack = 0;
        int dstSizeKnown = 0;
        int aliasDst = 0;

        int sizeConst = 0;
        int sizeUnknown = 0;
        int sizeGtDst = 0;
        int sizeEqDst = 0;
        int sizeLtDst = 0;

        int srcLiteral = 0;
        int srcExternal = 0;
        int sourceReaches = 0;
        int sourceReachesStack = 0;

        int guard = 0;
        int sizeGuard = 0;
        int strongGuard = 0;
        int weakGuard = 0;
        int noGuard = 0;

        int safeProof = 0;
        int risky = 0;
        int likelySafe = 0;

        int literalGtDst = 0;
        int literalLeDst = 0;

        double riskTotal = 0.0;
        double safeTotal = 0.0;
        double riskMinusSafeMax = -999999.0;

        long maxDstSize = 0;
        long maxSizeValue = 0;
        double maxRatio = 0.0;

        for (Object o : sinks) {
            if (!(o instanceof Map)) continue;

            Map<?, ?> s = (Map<?, ?>) o;

            if (truth(s.get("v6_dst_is_stack_buffer"))) dstStack++;
            if (truth(s.get("v6_dst_stack_size_known"))) dstSizeKnown++;
            if (truth(s.get("v6_dst_via_alias"))) aliasDst++;

            if (truth(s.get("v6_size_arg_const"))) sizeConst++;
            if (truth(s.get("v6_size_arg_unknown"))) sizeUnknown++;
            if (truth(s.get("v6_size_gt_dst"))) sizeGtDst++;
            if (truth(s.get("v6_size_eq_dst"))) sizeEqDst++;
            if (truth(s.get("v6_size_lt_dst"))) sizeLtDst++;

            if (truth(s.get("v6_src_is_literal"))) srcLiteral++;
            if (truth(s.get("v6_src_external_like"))) srcExternal++;
            if (truth(s.get("v6_source_reaches_sink"))) sourceReaches++;
            if (truth(s.get("v6_source_reaches_sink")) && truth(s.get("v6_dst_is_stack_buffer"))) sourceReachesStack++;

            if (truth(s.get("v6_guard_before_sink"))) guard++;
            if (truth(s.get("v6_size_guard_before_sink"))) sizeGuard++;
            if (truth(s.get("v6_strong_guard"))) strongGuard++;
            if (truth(s.get("v6_weak_guard"))) weakGuard++;
            if (truth(s.get("v6_sink_without_guard"))) noGuard++;

            if (truth(s.get("v6_safe_proof"))) safeProof++;
            if (truth(s.get("v6_likely_vulnerable_callsite"))) risky++;
            if (truth(s.get("v6_likely_safe_callsite"))) likelySafe++;

            if (truth(s.get("v6_literal_len_gt_dst"))) literalGtDst++;
            if (truth(s.get("v6_literal_len_le_dst"))) literalLeDst++;

            long ds = longVal(s.get("v6_dst_stack_size"));
            long sv = longVal(s.get("v6_size_value"));
            double ratio = doubleVal(s.get("v6_size_to_dst_ratio"));

            if (ds > maxDstSize) maxDstSize = ds;
            if (sv > maxSizeValue) maxSizeValue = sv;
            if (ratio > maxRatio) maxRatio = ratio;

            double r = doubleVal(s.get("v6_callsite_risk_score"));
            double sf = doubleVal(s.get("v6_callsite_safe_score"));
            double rms = doubleVal(s.get("v6_callsite_risk_minus_safe"));

            riskTotal += r;
            safeTotal += sf;
            if (rms > riskMinusSafeMax) riskMinusSafeMax = rms;
        }

        double denom = sinkCount + 1.0;

        m.put("v6_sink_count", sinkCount);

        m.put("v6_dst_stack_buffer_count", dstStack);
        m.put("v6_dst_stack_size_known_count", dstSizeKnown);
        m.put("v6_dst_alias_count", aliasDst);
        m.put("v6_dst_stack_size_max", maxDstSize);

        m.put("v6_size_arg_const_count", sizeConst);
        m.put("v6_size_arg_unknown_count", sizeUnknown);
        m.put("v6_size_gt_dst_count", sizeGtDst);
        m.put("v6_size_eq_dst_count", sizeEqDst);
        m.put("v6_size_lt_dst_count", sizeLtDst);
        m.put("v6_size_value_max", maxSizeValue);
        m.put("v6_size_to_dst_ratio_max", maxRatio);

        m.put("v6_src_literal_count", srcLiteral);
        m.put("v6_src_external_like_count", srcExternal);
        m.put("v6_source_reaches_sink_count", sourceReaches);
        m.put("v6_source_reaches_stack_sink_count", sourceReachesStack);

        m.put("v6_guard_before_sink_count", guard);
        m.put("v6_size_guard_before_sink_count", sizeGuard);
        m.put("v6_strong_guard_count", strongGuard);
        m.put("v6_weak_guard_count", weakGuard);
        m.put("v6_sink_without_guard_count", noGuard);

        m.put("v6_safe_proof_count", safeProof);
        m.put("v6_likely_vulnerable_callsite_count", risky);
        m.put("v6_likely_safe_callsite_count", likelySafe);

        m.put("v6_literal_len_gt_dst_count", literalGtDst);
        m.put("v6_literal_len_le_dst_count", literalLeDst);

        m.put("v6_risk_score_total", riskTotal);
        m.put("v6_safe_score_total", safeTotal);
        m.put("v6_risk_minus_safe_total", riskTotal - safeTotal);
        m.put("v6_risk_minus_safe_max", riskMinusSafeMax == -999999.0 ? 0.0 : riskMinusSafeMax);

        m.put("v6_dst_stack_sink_ratio", dstStack / denom);
        m.put("v6_source_reaches_stack_ratio", sourceReachesStack / denom);
        m.put("v6_strong_guard_ratio", strongGuard / denom);
        m.put("v6_safe_proof_ratio", safeProof / denom);
        m.put("v6_likely_vulnerable_ratio", risky / denom);
        m.put("v6_likely_safe_ratio", likelySafe / denom);

        m.put(
            "v6_strict_sbo_risk_score",
            riskTotal +
            risky * 3.0 +
            sizeGtDst * 4.0 +
            sourceReachesStack * 2.0 +
            noGuard * 1.5 -
            safeProof * 2.0 -
            strongGuard * 2.0
        );

        m.put(
            "v6_fp_suppression_score",
            safeTotal +
            safeProof * 3.0 +
            strongGuard * 2.0 +
            literalLeDst * 2.0 -
            sizeGtDst * 3.0 -
            noGuard * 1.0
        );

        return m;
    }

    private Map<String, Object> findBufferV6(String expr, ArrayList<Object> buffers, ArrayList<Object> aliases) {
        Map<String, Object> b = findBuffer(expr, buffers);
        if (b != null) return b;

        String v = cleanVar(expr);
        String resolved = resolveAliasV6(v, aliases);

        if (!resolved.equals(v)) {
            return findBufferByNameV6(resolved, buffers);
        }

        return null;
    }

    private Map<String, Object> findBufferByNameV6(String name, ArrayList<Object> buffers) {
        for (Object o : buffers) {
            Map<String, Object> b = (Map<String, Object>) o;
            if (name.equals(stringVal(b.get("name")))) return b;
        }

        return null;
    }

    private String resolveAliasV6(String var, ArrayList<Object> aliases) {
        String v = s(var).trim();

        for (Object o : aliases) {
            Map<?, ?> a = (Map<?, ?>) o;

            String alias = stringVal(a.get("alias"));
            String target = stringVal(a.get("target"));

            if (v.equals(alias) && target.length() > 0) return target;
        }

        return v;
    }

    private boolean exprUsesSizeofVarV6(String expr, String var) {
        String e = s(expr).toLowerCase();
        String v = s(var).toLowerCase();

        if (v.length() == 0) return false;

        return cachedPattern(
            "\\bsizeof\\s*\\(\\s*&?\\s*" + Pattern.quote(v) + "\\s*\\)",
            0
        ).matcher(e).find();
    }

    private boolean hasInputSourceTextV6(String text) {
        String t = s(text).toLowerCase();

        return INPUT_SOURCE_PATTERN.matcher(t).find();
    }

    private boolean sourceAssignedBeforeV6(String text, String var) {
        String t = s(text).toLowerCase();
        String v = s(var).toLowerCase();

        if (v.length() == 0) return false;

        Pattern p = cachedPattern(
            "\\b" + Pattern.quote(v) + "\\b\\s*=\\s*.*\\b(argv|envp|getenv|stdin|scanf|sscanf|fgets|gets|read|recv|recvfrom|getchar)\\b",
            Pattern.CASE_INSENSITIVE
        );

        return p.matcher(t).find();
    }

    private int minSourceDistanceBeforeV6(String[] lines, int idx) {
        int best = 999999;

        int start = Math.max(0, idx - 40);

        for (int i = start; i < idx && i < lines.length; i++) {
            if (hasInputSourceTextV6(lines[i])) {
                int d = idx - i;
                if (d < best) best = d;
            }
        }

        return best == 999999 ? 0 : best;
    }

    private String windowTextV6(String[] lines, int start, int end) {
        StringBuilder sb = new StringBuilder();

        if (lines == null || lines.length == 0) return "";

        int a = Math.max(0, start);
        int b = Math.min(lines.length - 1, end);

        for (int i = a; i <= b; i++) {
            sb.append(lines[i]).append("\n");
        }

        return sb.toString();
    }

    private boolean containsStackBufferWriteV6(String text, ArrayList<Object> buffers) {
        String t = s(text);

        for (Object o : buffers) {
            Map<?, ?> b = (Map<?, ?>) o;
            String name = stringVal(b.get("name"));

            if (name.length() == 0) continue;

            Pattern p = cachedPattern(
                "\\b" + Pattern.quote(name) + "\\s*\\[[^\\]]+\\]\\s*=",
                Pattern.CASE_INSENSITIVE
            );

            if (p.matcher(t).find()) return true;
        }

        return false;
    }




    // =========================
    // Safer size expression parsing
    // =========================
    //
    // Không dùng intFromText() trực tiếp cho size argument, vì nó có thể lấy nhầm
    // số trong tên biến như local_28, param_1, auStack_40.
    //
    // Hàm này chỉ trả về value khi expression đủ chắc:
    //   128
    //   0x80
    //   sizeof(dst)
    //   sizeof(dst) - 1
    //   sizeof(dst) + 0
    //
    // Nếu không chắc, trả về null để tránh tạo overflow_margin giả.
    private Long parseSizeExprSmart(String expr, String dstVar, long dstSize) {
        String e = s(expr).trim();

        if (e.length() == 0) return null;

        e = stripSizeExprCasts(e);
        e = e.trim();

        // Nếu là số thuần hoặc biểu thức số đơn giản: 32, 0x20, 32-1, 0x20+4
        Long pure = evalSimpleIntegerExpression(e);
        if (pure != null) return pure;

        // sizeof(dst), sizeof(dst)-1, sizeof(dst)+...
        if (dstVar != null && dstVar.length() > 0 && dstSize > 0) {
            String replaced = replaceSizeofDstWithValue(e, dstVar, dstSize);

            if (!replaced.equals(e)) {
                Long v = evalSimpleIntegerExpression(replaced);
                if (v != null) return v;
            }
        }

        // Nếu còn chữ cái thì không được cố lấy số.
        // Ví dụ local_28, param_1, n, len, strlen(src)+1.
        return null;
    }

    private String stripSizeExprCasts(String expr) {
        String e = s(expr).trim();

        boolean changed = true;

        while (changed) {
            String old = e;

            e = e.replaceAll(
                "^\\s*\\(\\s*(?:size_t|ssize_t|int|uint|uint32_t|uint64_t|long|ulong|unsigned\\s+int|unsigned\\s+long|longlong|ulonglong)\\s*\\)\\s*",
                ""
            );

            e = stripOuterParens(e.trim());

            changed = !old.equals(e);
        }

        return e.trim();
    }

    private String stripOuterParens(String expr) {
        String e = s(expr).trim();

        while (e.startsWith("(") && e.endsWith(")") && parensWrapWholeExpr(e)) {
            e = e.substring(1, e.length() - 1).trim();
        }

        return e;
    }

    private boolean parensWrapWholeExpr(String e) {
        int depth = 0;

        for (int i = 0; i < e.length(); i++) {
            char ch = e.charAt(i);

            if (ch == '(') depth++;
            else if (ch == ')') depth--;

            if (depth == 0 && i < e.length() - 1) return false;
            if (depth < 0) return false;
        }

        return depth == 0;
    }

    private String replaceSizeofDstWithValue(String expr, String dstVar, long dstSize) {
        String e = s(expr);
        String dst = cleanVar(dstVar);

        if (dst.length() == 0 || dstSize <= 0) return e;

        Pattern p = Pattern.compile(
            "\\bsizeof\\s*(?:\\(\\s*&?\\s*([A-Za-z_]\\w*)\\s*\\)|\\s+([A-Za-z_]\\w*))",
            Pattern.CASE_INSENSITIVE
        );

        Matcher m = p.matcher(e);
        StringBuffer sb = new StringBuffer();

        boolean changed = false;

        while (m.find()) {
            String v = m.group(1) != null ? m.group(1) : m.group(2);
            String cv = cleanVar(v);

            if (dst.equals(cv)) {
                m.appendReplacement(sb, String.valueOf(dstSize));
                changed = true;
            } else {
                m.appendReplacement(sb, Matcher.quoteReplacement(m.group(0)));
            }
        }

        m.appendTail(sb);

        return changed ? sb.toString() : e;
    }

    private Long evalSimpleIntegerExpression(String expr) {
        String e = s(expr).trim().replaceAll("\\s+", "");

        if (e.length() == 0) return null;

        // Chỉ cho phép số hex/dec và phép + -
        if (!e.matches("(?i)^[+-]?(?:0x[0-9a-f]+|\\d+)(?:[+-](?:0x[0-9a-f]+|\\d+))*$")) {
            return null;
        }

        Pattern p = Pattern.compile("([+-]?)(0x[0-9a-fA-F]+|\\d+)");
        Matcher m = p.matcher(e);

        long total = 0;
        int pos = 0;

        while (m.find()) {
            if (m.start() != pos) return null;

            String sign = m.group(1);
            String num = m.group(2);

            long v;
            try {
                if (num.toLowerCase().startsWith("0x")) {
                    v = Long.parseLong(num.substring(2), 16);
                } else {
                    v = Long.parseLong(num);
                }
            } catch (Throwable t) {
                return null;
            }

            if ("-".equals(sign)) total -= v;
            else total += v;

            pos = m.end();
        }

        if (pos != e.length()) return null;
        if (total < 0) return null;

        return Long.valueOf(total);
    }

    private int[] dstSrcSizeIndices(String api) {
        if (api.equals("strcpy") || api.equals("strcat") || api.equals("wcscpy") || api.equals("wcscat")) {
            return new int[] {0, 1, -1};
        }

        if (api.equals("memcpy") || api.equals("memmove") || api.equals("wmemcpy") || api.equals("wmemmove") ||
            api.equals("memcpy_chk") || api.equals("memmove_chk") ||
            api.equals("strncpy") || api.equals("strncat") || api.equals("wcsncpy") || api.equals("wcsncat") ||
            api.equals("strncpy_chk") || api.equals("strncat_chk")) {
            return new int[] {0, 1, 2};
        }

        if (api.equals("memset") || api.equals("wmemset")) return new int[] {0, -1, 2};
        if (api.equals("snprintf") || api.equals("vsnprintf") || api.equals("snprintf_chk") || api.equals("vsnprintf_chk")) return new int[] {0, -1, 1};
        if (api.equals("strcpy_chk") || api.equals("strcat_chk")) return new int[] {0, 1, 2};
        if (api.equals("sprintf_chk")) return new int[] {0, -1, 2};
        if (api.equals("sprintf") || api.equals("swprintf")) return new int[] {0, -1, -1};
        if (api.equals("fgets") || api.equals("fgetws")) return new int[] {0, -1, 1};
        if (api.equals("read") || api.equals("recv") || api.equals("recvfrom")) return new int[] {1, -1, 2};

        return new int[] {-1, -1, -1};
    }

    private String classifySource(String expr, ArrayList<Object> buffers, ArrayList<String> params) {
        String e = s(expr).trim();
        String v = cleanVar(e);
        String low = e.toLowerCase();

        if (literalLen(e) != null) return "literal";
        if (params.contains(v)) return "parameter";

        if (
            low.contains("argv") ||
            low.contains("envp") ||
            low.contains("getenv") ||
            low.contains("stdin") ||
            low.contains("read") ||
            low.contains("recv") ||
            low.contains("scanf") ||
            low.contains("fgets") ||
            low.contains("gets")
        ) {
            return "input_like";
        }

        for (Object o : buffers) {
            Map<?, ?> b = (Map<?, ?>) o;
            if (v.equals(stringVal(b.get("name")))) return "local_buffer";
        }

        if (v.matches("^[A-Z_][A-Z0-9_]*$")) return "macro_or_global";
        if (v.length() > 0) return "local_or_unknown";

        return "unknown";
    }

    private Map<String, Object> findBuffer(String expr, ArrayList<Object> buffers) {
        String v = cleanVar(expr);

        for (Object o : buffers) {
            Map<String, Object> b = (Map<String, Object>) o;
            if (v.equals(stringVal(b.get("name")))) return b;
        }

        return null;
    }

    private ArrayList<String> splitArgs(String s) {
        ArrayList<String> out = new ArrayList<String>();
        StringBuilder cur = new StringBuilder();

        int depth = 0;
        boolean inStr = false;
        char quote = 0;
        boolean esc = false;

        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);

            if (inStr) {
                cur.append(ch);
                if (esc) esc = false;
                else if (ch == '\\') esc = true;
                else if (ch == quote) inStr = false;
                continue;
            }

            if (ch == '"' || ch == '\'') {
                inStr = true;
                quote = ch;
                cur.append(ch);
                continue;
            }

            if (ch == '(') depth++;
            else if (ch == ')') depth--;
            else if (ch == ',' && depth == 0) {
                out.add(cur.toString().trim());
                cur.setLength(0);
                continue;
            }

            cur.append(ch);
        }

        if (cur.length() > 0) out.add(cur.toString().trim());
        return out;
    }

    private String cleanVar(String expr) {
        String x = s(expr).trim();
        x = x.replace("&", "").replace("*", "");
        x = x.replaceAll("\\[[^\\]]+\\]", "");
        int dot = x.indexOf(".");
        if (dot >= 0) x = x.substring(0, dot);
        int arr = x.indexOf("->");
        if (arr >= 0) x = x.substring(0, arr);

        Matcher m = CLEAN_VAR_PATTERN.matcher(x);
        return m.find() ? m.group(1) : "";
    }

    private Long literalLen(String expr) {
        Matcher m = STRING_LITERAL_PATTERN.matcher(s(expr));
        if (!m.find()) return null;
        return Long.valueOf(m.group(1).length());
    }

    private long typeSize(String typ) {
        String t = s(typ).toLowerCase();

        if (t.contains("wchar")) return 4;
        if (t.contains("char16")) return 2;
        if (t.contains("char32")) return 4;
        if (t.contains("char") || t.contains("byte") || t.contains("undefined")) return 1;
        if (t.contains("short")) return 2;
        if (t.contains("int64") || t.contains("long long") || t.contains("uint64")) return 8;
        if (t.contains("int") || t.contains("uint")) return 4;
        if (t.contains("long")) return 8;
        if (t.contains("float")) return 4;
        if (t.contains("double")) return 8;

        return 1;
    }

    private String operandsText(Instruction ins) {
        StringBuilder sb = new StringBuilder();

        try {
            int n = ins.getNumOperands();
            for (int i = 0; i < n; i++) {
                if (i > 0) sb.append(", ");
                sb.append(s(ins.getDefaultOperandRepresentation(i)));
            }
        } catch (Throwable ignored) {}

        return sb.toString();
    }

    private boolean containsStackRef(String text) {
        String t = s(text).toLowerCase();
        return t.contains("rbp") || t.contains("rsp") || t.contains("ebp") || t.contains("esp") ||
               t.contains("local_") || t.contains("stack_") || t.contains("austack") ||
               t.contains("acstack") || t.contains("aistack");
    }

    private Long parseStackOffset(String text) {
        String t = s(text).toLowerCase().replace(" ", "");

        Matcher m = RBP_OFFSET_PATTERN.matcher(t);
        if (m.find()) return intFromText(m.group(1));

        m = RSP_OFFSET_PATTERN.matcher(t);
        if (m.find()) return intFromText(m.group(1));

        m = STACK_NAME_OFFSET_PATTERN.matcher(t);
        if (m.find()) {
            try {
                return Long.valueOf(-Long.parseLong(m.group(1), 16));
            } catch (Throwable ignored) {}
        }

        return null;
    }

    private Long intFromText(String text) {
        String t = s(text).replace("ULL", "").replace("UL", "").replace("LL", "").replace("L", "");
        Matcher m = INT_TEXT_PATTERN.matcher(t);

        if (!m.find()) return null;

        try {
            return Long.decode(m.group(0));
        } catch (Throwable ignored) {
            try {
                return Long.valueOf(Long.parseLong(m.group(0)));
            } catch (Throwable ignored2) {
                return null;
            }
        }
    }

    private String normName(Object x) {
        String s = s(x).trim();
        s = s.replace("j_", "");
        s = s.replaceAll("^_+", "");
        int at = s.indexOf("@@");
        if (at >= 0) s = s.substring(0, at);
        at = s.indexOf("@");
        if (at >= 0) s = s.substring(0, at);
        return s;
    }

    private String addr(Address a) {
        if (a == null) return "";
        try {
            return "0x" + Long.toHexString(a.getOffset());
        } catch (Throwable e) {
            return s(a);
        }
    }

    private static void inc(Map<String, Integer> m, String k) {
        if (k == null || k.length() == 0) return;
        Integer v = m.get(k);
        m.put(k, v == null ? 1 : v + 1);
    }

    private static String s(Object x) {
        return x == null ? "" : String.valueOf(x);
    }

    private static Boolean bool(boolean b) {
        return Boolean.valueOf(b);
    }

    private static boolean truth(Object x) {
        if (x == null) return false;
        if (x instanceof Boolean) return ((Boolean) x).booleanValue();
        if (x instanceof Number) return ((Number) x).doubleValue() != 0.0;
        return "true".equalsIgnoreCase(s(x)) || "1".equals(s(x));
    }

    private static long longVal(Object x) {
        if (x == null) return 0L;
        if (x instanceof Number) return ((Number) x).longValue();
        try {
            return Long.parseLong(s(x));
        } catch (Throwable e) {
            return 0L;
        }
    }

    private static double doubleVal(Object x) {
        if (x == null) return 0.0;
        if (x instanceof Number) return ((Number) x).doubleValue();
        try {
            return Double.parseDouble(s(x));
        } catch (Throwable e) {
            return 0.0;
        }
    }

    private static String stringVal(Object x) {
        return s(x);
    }

    private static String quote(String s) {
        StringBuilder sb = new StringBuilder();
        sb.append('"');

        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);

            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 32) {
                        sb.append(String.format("\\u%04x", (int)c));
                    } else {
                        sb.append(c);
                    }
            }
        }

        sb.append('"');
        return sb.toString();
    }

    private static String toJson(Object obj) {
        if (obj == null) return "null";

        if (obj instanceof String) return quote((String)obj);
        if (obj instanceof Number || obj instanceof Boolean) return String.valueOf(obj);

        if (obj instanceof Map) {
            StringBuilder sb = new StringBuilder();
            sb.append("{");

            boolean first = true;
            for (Object eo : ((Map<?, ?>)obj).entrySet()) {
                Map.Entry<?, ?> e = (Map.Entry<?, ?>) eo;

                if (!first) sb.append(",");
                first = false;

                sb.append(quote(s(e.getKey())));
                sb.append(":");
                sb.append(toJson(e.getValue()));
            }

            sb.append("}");
            return sb.toString();
        }

        if (obj instanceof Iterable) {
            StringBuilder sb = new StringBuilder();
            sb.append("[");

            boolean first = true;
            for (Object x : (Iterable<?>)obj) {
                if (!first) sb.append(",");
                first = false;
                sb.append(toJson(x));
            }

            sb.append("]");
            return sb.toString();
        }

        return quote(s(obj));
    }
}
