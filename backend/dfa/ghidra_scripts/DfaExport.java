// Drone Firmware Analyzer - Ghidra post-script: export function-level facts as JSON.
// Usage (headless): -postScript DfaExport.java <output.json>
// Output is static-analysis data only; nothing here proves a vulnerability.
// @category DFA
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

import java.io.FileWriter;
import java.util.*;

public class DfaExport extends GhidraScript {
    private static final String[] RISKY = {"gets", "strcpy", "strcat", "sprintf", "vsprintf", "scanf", "sscanf",
        "fscanf", "system", "popen", "execl", "execlp", "execv", "execve", "execvp", "alloca", "strncpy", "strncat",
        "memcpy", "memmove", "snprintf", "realpath", "getwd", "mktemp", "tmpnam", "rand", "srand"};
    private static final int MAX_FUNCS = 4000;

    private static String esc(String s) {
        if (s == null) return "";
        StringBuilder b = new StringBuilder();
        for (char c : s.toCharArray()) {
            if (c == '"' || c == '\\') { b.append('\\').append(c); }
            else if (c < 0x20 || c > 0x7e) { b.append(String.format("\\u%04x", (int) c)); }
            else b.append(c);
        }
        return b.toString();
    }

    private static String normalize(String name) {
        String n = name;
        while (n.startsWith("_")) n = n.substring(1);
        if (n.startsWith("isoc99_")) n = n.substring(7);
        if (n.endsWith("_chk")) n = n.substring(0, n.length() - 4);
        int at = n.indexOf('@');
        if (at > 0) n = n.substring(0, at);
        return n;
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String out = args.length > 0 ? args[0] : "/tmp/dfa_ghidra.json";
        Set<String> risky = new HashSet<>(Arrays.asList(RISKY));
        List<Function> funcs = new ArrayList<>();
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        int thunks = 0, external = 0;
        long totalBody = 0;
        while (it.hasNext() && !monitor.isCancelled()) {
            Function f = it.next();
            if (f.isThunk()) thunks++;
            funcs.add(f);
            totalBody += f.getBody().getNumAddresses();
        }
        FunctionIterator ext = currentProgram.getFunctionManager().getExternalFunctions();
        List<Function> externals = new ArrayList<>();
        while (ext.hasNext()) { externals.add(ext.next()); external++; }

        // Call sites of risky functions (internal definitions, thunks and externals alike).
        Map<String, List<String[]>> riskyCalls = new TreeMap<>();
        List<Function> candidates = new ArrayList<>(funcs);
        candidates.addAll(externals);
        for (Function f : candidates) {
            String norm = normalize(f.getName());
            if (!risky.contains(norm)) continue;
            ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint());
            int n = 0;
            while (refs.hasNext()) {
                Reference r = refs.next();
                if (!r.getReferenceType().isCall()) continue;
                Function caller = getFunctionContaining(r.getFromAddress());
                if (caller != null && normalize(caller.getName()).equals(norm)) continue; // thunk to itself
                riskyCalls.computeIfAbsent(norm, k -> new ArrayList<>()).add(new String[]{
                    r.getFromAddress().toString(), caller == null ? "" : caller.getName()});
                if (++n > 500) break;
            }
        }

        // Largest functions and most-called functions (by incoming call references).
        funcs.sort((a, b) -> Long.compare(b.getBody().getNumAddresses(), a.getBody().getNumAddresses()));
        StringBuilder sb = new StringBuilder();
        sb.append("{\"ghidra_version\":\"").append(esc(getGhidraVersion())).append("\"");
        sb.append(",\"language\":\"").append(esc(currentProgram.getLanguageID().toString())).append("\"");
        sb.append(",\"compiler\":\"").append(esc(currentProgram.getCompilerSpec().getCompilerSpecID().toString())).append("\"");
        sb.append(",\"executable_format\":\"").append(esc(currentProgram.getExecutableFormat())).append("\"");
        sb.append(",\"image_base\":\"").append(currentProgram.getImageBase()).append("\"");
        sb.append(",\"min_address\":\"").append(currentProgram.getMinAddress()).append("\"");
        sb.append(",\"function_count\":").append(funcs.size());
        sb.append(",\"thunk_count\":").append(thunks);
        sb.append(",\"external_count\":").append(external);
        sb.append(",\"instruction_count\":").append(currentProgram.getListing().getNumInstructions());
        sb.append(",\"function_bytes\":").append(totalBody);
        sb.append(",\"memory_blocks\":[");
        boolean first = true;
        for (MemoryBlock blk : currentProgram.getMemory().getBlocks()) {
            if (!first) sb.append(","); first = false;
            sb.append("{\"name\":\"").append(esc(blk.getName())).append("\",\"start\":\"").append(blk.getStart())
              .append("\",\"size\":").append(blk.getSize()).append(",\"perms\":\"")
              .append(blk.isRead() ? "r" : "-").append(blk.isWrite() ? "w" : "-").append(blk.isExecute() ? "x" : "-").append("\"}");
        }
        sb.append("],\"risky_calls\":{");
        first = true;
        for (Map.Entry<String, List<String[]>> e : riskyCalls.entrySet()) {
            if (!first) sb.append(","); first = false;
            sb.append("\"").append(esc(e.getKey())).append("\":[");
            boolean f2 = true;
            for (String[] site : e.getValue()) {
                if (!f2) sb.append(","); f2 = false;
                sb.append("{\"address\":\"").append(esc(site[0])).append("\",\"function\":\"").append(esc(site[1])).append("\"}");
            }
            sb.append("]");
        }
        sb.append("},\"functions\":[");
        first = true;
        int count = 0;
        for (Function f : funcs) {
            if (count++ >= MAX_FUNCS || monitor.isCancelled()) break;
            if (!first) sb.append(","); first = false;
            int callers = f.getCallingFunctions(monitor).size();
            int callees = f.getCalledFunctions(monitor).size();
            sb.append("{\"name\":\"").append(esc(f.getName())).append("\",\"entry\":\"").append(f.getEntryPoint())
              .append("\",\"size\":").append(f.getBody().getNumAddresses())
              .append(",\"callers\":").append(callers).append(",\"callees\":").append(callees)
              .append(",\"thunk\":").append(f.isThunk()).append("}");
        }
        sb.append("]}");
        try (FileWriter w = new FileWriter(out)) { w.write(sb.toString()); }
        println("DFA: exported " + funcs.size() + " functions to " + out);
    }
}
