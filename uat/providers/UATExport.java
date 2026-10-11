// Export bounded native analysis evidence from Ghidra's headless analyzer.
// @category UltimateAndroidToolkit
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.AbstractStringDataType;
import com.google.gson.GsonBuilder;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class UATExport extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) throw new IllegalArgumentException("Output JSON path required");
        int limit = args.length > 1 ? Integer.parseInt(args[1]) : 500;
        Map<String, Object> report = new LinkedHashMap<>();
        report.put("provider", "ghidra");
        report.put("input", currentProgram.getExecutablePath());
        report.put("language", currentProgram.getLanguageID().toString());
        report.put("image_base", currentProgram.getImageBase().toString());
        report.put("functions_total", currentProgram.getFunctionManager().getFunctionCount());
        List<Object> functions = new ArrayList<>();
        DecompInterface decompiler = new DecompInterface();
        boolean available = decompiler.openProgram(currentProgram);
        report.put("decompiler_available", available);
        try {
            FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
            while (iterator.hasNext() && functions.size() < limit && !monitor.isCancelled()) {
                Function function = iterator.next();
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("name", function.getName(true));
                item.put("address", function.getEntryPoint().toString());
                item.put("size", function.getBody().getNumAddresses());
                List<Object> callers = new ArrayList<>();
                ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(function.getEntryPoint());
                while (refs.hasNext() && callers.size() < 1000) {
                    Reference reference = refs.next();
                    Map<String, Object> caller = new LinkedHashMap<>();
                    caller.put("address", reference.getFromAddress().toString());
                    caller.put("type", reference.getReferenceType().toString());
                    Function owner = currentProgram.getFunctionManager().getFunctionContaining(reference.getFromAddress());
                    caller.put("function", owner == null ? null : owner.getName(true));
                    callers.add(caller);
                }
                item.put("callers", callers);
                List<Object> assembly = new ArrayList<>();
                InstructionIterator instructions = currentProgram.getListing().getInstructions(function.getBody(), true);
                while (instructions.hasNext() && assembly.size() < 200) {
                    Instruction instruction = instructions.next();
                    Map<String, Object> line = new LinkedHashMap<>();
                    line.put("address", instruction.getAddress().toString());
                    line.put("text", instruction.toString());
                    assembly.add(line);
                }
                item.put("assembly", assembly);
                if (available && !function.isExternal()) {
                    DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
                    if (result.decompileCompleted() && result.getDecompiledFunction() != null)
                        item.put("pseudocode", result.getDecompiledFunction().getC());
                    else item.put("decompilation_error", result.getErrorMessage());
                }
                functions.add(item);
            }
        } finally {
            decompiler.dispose();
        }
        report.put("functions", functions);
        report.put("functions_truncated", currentProgram.getFunctionManager().getFunctionCount() > functions.size());
        List<Object> strings = new ArrayList<>();
        DataIterator data = currentProgram.getListing().getDefinedData(true);
        while (data.hasNext() && strings.size() < Math.min(50000, limit * 20)) {
            Data value = data.next();
            if (!(value.getDataType() instanceof AbstractStringDataType)) continue;
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("address", value.getAddress().toString());
            item.put("text", String.valueOf(value.getValue()));
            strings.add(item);
        }
        report.put("strings", strings);
        try (Writer output = new OutputStreamWriter(new FileOutputStream(args[0]), StandardCharsets.UTF_8)) {
            new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create().toJson(report, output);
        }
        println("UAT: exported " + functions.size() + " functions to " + args[0]);
    }
}
