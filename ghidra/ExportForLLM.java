// Export every function of the analyzed binary as one JSON line: entry address,
// name, size, callers, callees, imported functions it calls, strings it
// references, and Ghidra's decompiled C. Consumed by fuzzer/reconstruct.py.
//
// Script arguments: <output.jsonl> [decompile timeout seconds] [max function size]
// @category CMSC614
import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.StringJoiner;
import java.util.TreeSet;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Reference;

public class ExportForLLM extends GhidraScript {

    private static String q(String s) {
        if (s == null) {
            return "null";
        }
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        b.append(String.format("\\u%04x", (int) c));
                    } else {
                        b.append(c);
                    }
            }
        }
        return b.append('"').toString();
    }

    private static String arr(Collection<String> xs) {
        StringJoiner j = new StringJoiner(",", "[", "]");
        for (String x : xs) {
            j.add(q(x));
        }
        return j.toString();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outPath = args[0];
        int timeout = args.length > 1 ? Integer.parseInt(args[1]) : 30;
        long maxSize = args.length > 2 ? Long.parseLong(args[2]) : 20000;

        Listing listing = currentProgram.getListing();
        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        int total = 0, decompiled = 0;
        try (PrintWriter out = new PrintWriter(new BufferedWriter(
                new OutputStreamWriter(new FileOutputStream(outPath), "UTF-8")))) {
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                if (monitor.isCancelled()) {
                    break;
                }
                if (f.isExternal() || f.isThunk()) {
                    continue;
                }
                Set<String> callees = new TreeSet<>();
                Set<String> imports = new TreeSet<>();
                for (Function c : f.getCalledFunctions(monitor)) {
                    Function t = c.isThunk() ? c.getThunkedFunction(true) : c;
                    if (t == null) {
                        continue;
                    }
                    if (t.isExternal()) {
                        imports.add(t.getName());
                    } else {
                        callees.add(t.getEntryPoint().toString());
                    }
                }
                Set<String> callers = new TreeSet<>();
                for (Function c : f.getCallingFunctions(monitor)) {
                    callers.add(c.getEntryPoint().toString());
                }
                Set<String> strings = new LinkedHashSet<>();
                for (Instruction ins : listing.getInstructions(f.getBody(), true)) {
                    for (Reference r : ins.getReferencesFrom()) {
                        Data d = listing.getDataAt(r.getToAddress());
                        if (d != null && d.hasStringValue() && d.getValue() != null) {
                            strings.add(d.getValue().toString());
                        }
                    }
                }
                long size = f.getBody().getNumAddresses();
                String code = null;
                String err = null;
                if (size <= maxSize) {
                    DecompileResults res = dec.decompileFunction(f, timeout, monitor);
                    if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                        code = res.getDecompiledFunction().getC();
                        decompiled++;
                    } else {
                        err = res == null ? "no result" : res.getErrorMessage();
                    }
                } else {
                    err = "too large";
                }
                total++;
                out.println("{\"entry\":" + q(f.getEntryPoint().toString())
                        + ",\"name\":" + q(f.getName())
                        + ",\"size\":" + size
                        + ",\"callees\":" + arr(callees)
                        + ",\"callers\":" + arr(callers)
                        + ",\"imports\":" + arr(imports)
                        + ",\"strings\":" + arr(strings)
                        + ",\"code\":" + q(code)
                        + ",\"error\":" + q(err) + "}");
            }
        } finally {
            dec.dispose();
        }
        println("ExportForLLM: " + decompiled + "/" + total + " functions decompiled -> " + outPath);
    }
}
