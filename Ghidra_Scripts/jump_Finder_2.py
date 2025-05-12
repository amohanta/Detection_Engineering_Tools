#@author 
#@category Analysis
#@keybinding 
#@menupath 
#@toolbar 

from ghidra.program.model.listing import CodeUnit

# List of jump mnemonics to detect
jump_mnemonics = (
    "JMP", "JE", "JNE", "JG", "JGE", "JL", "JLE",
    "JA", "JAE", "JB", "JBE", "JO", "JNO", "JS", "JNS",
    "JCXZ", "JECXZ", "JRCXZ"
)

listing = currentProgram.getListing()
functions = listing.getFunctions(True)

print("=== Jump Instructions in Functions Starting with 'FUN_' ===")

for func in functions:
    func_name = func.getName()
    
    # Only process functions starting with 'FUN_'
    if not func_name.startswith("FUN_"):
        continue

    found_jump = False
    instructions = listing.getInstructions(func.getBody(), True)

    for instr in instructions:
        mnemonic = instr.getMnemonicString().upper()
        if mnemonic in jump_mnemonics:
            if not found_jump:
                print("\nFunction: {}".format(func_name))
                found_jump = True
            print("  {}: {}".format(instr.getAddress(), instr))

if not found_jump:
    print("No jump instructions found in 'FUN_' functions.")
