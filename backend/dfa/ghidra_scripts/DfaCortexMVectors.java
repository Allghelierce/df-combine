// Drone Firmware Analyzer - Ghidra pre-script for raw ARM Cortex-M images.
// Raw flash dumps have no symbols or entry points; this seeds disassembly by creating functions
// at the reset/exception/IRQ handler addresses listed in the vector table at the image base.
// @category DFA
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;

public class DfaCortexMVectors extends GhidraScript {
    @Override
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        Address base = currentProgram.getMinAddress();  // raw imports report image base 0
        int created = 0;
        String[] names = {"initial_sp", "Reset_Handler", "NMI_Handler", "HardFault_Handler", "MemManage_Handler",
            "BusFault_Handler", "UsageFault_Handler", null, null, null, null, "SVC_Handler", "DebugMon_Handler", null,
            "PendSV_Handler", "SysTick_Handler"};
        for (int i = 1; i < 256; i++) {
            Address slot = base.add(4L * i);
            if (!mem.contains(slot)) break;
            long v = mem.getInt(slot) & 0xffffffffL;
            if (v == 0 || (v & 1) == 0) continue;            // empty or not a Thumb address
            Address target = base.getNewAddress(v & ~1L);
            if (!mem.contains(target)) continue;
            String name = (i < names.length && names[i] != null) ? names[i] : ("IRQ_" + (i - 16) + "_Handler");
            if (getFunctionAt(target) == null) {
                disassemble(target);
                if (createFunction(target, name) != null) created++;
            }
        }
        println("DFA: seeded " + created + " functions from the Cortex-M vector table");
    }
}
