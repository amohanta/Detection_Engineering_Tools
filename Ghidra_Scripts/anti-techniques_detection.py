#author: abhijit mohanta abhijit.mohanta.15.08@gmail.com abhijit@intelliroot.com

from ghidra.program.model.listing import Listing
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import RefType
from ghidra.program.model.scalar import Scalar

# Dictionary of strings and instructions to check for references, with their categories
patterns = {
    "strings": {
        "vmware": "anti-vm => virtualbox Detection",
        "virtualbox": "anti-vm => virtualbox Detection",
        "vbox": "anti-vm => virtualbox Detection",
        "sandbox": "Sandbox Detection",
        "SbieSvc": "Tool Detection => Sandboxie Detection",
	"Sbiedrv": "Tool Detection =>Sandboxie Detection",
	"SandboxieRpcSs.exe":"Tool Detection => Sandboxie Detection",
        "procmon": "Tool Detection => Procmon Detection ",
        "eventvwr.exe": "binary used for possible UAC-bypass",
	"PROCEXPL": "Tool Detection => process Explorer process Detection",
	"ollydbg": "Ant-Debug => olly debugger process Detection ",
	"VBoxTray.exe": "Ant--VM => virutualbox Detection",
	"SUPERAntiSpyware.exe" : "Tool Detection",
	"EtherD.exe":"network sniffer Detection",
	"Sniffer.exe":"network sniffer Detection",
	"Wireshark":"network sniffer Detection",
	
	
    },
    "instructions": {
        "IN": "VMWare Detection instruction (CMP 564d5868)"
    }
}

# Get the current program
program = getCurrentProgram()
if program is None:
    print("No program is currently open.")
else:
    listing = program.getListing()
    function_manager = program.getFunctionManager()
    reference_manager = program.getReferenceManager()
    memory = program.getMemory()

    # Get all functions in the current program
    functions = function_manager.getFunctions(True)

    # Iterate over each function
    for function in functions:
        function_name = function.getName()
        function_entry = function.getEntryPoint()

        # Get the instructions within the function's body
        instructions = listing.getInstructions(function.getBody(), True)

        # Iterate over each instruction and print the address, mnemonic, and full instruction if it matches criteria
        for instruction in instructions:
            address = instruction.getAddress()
            mnemonic = instruction.getMnemonicString()
            full_instruction = "{} {}".format(mnemonic, instruction.getDefaultOperandRepresentation(0))

            # Check if the instruction matches any in the dictionary
            if mnemonic in patterns["instructions"]:
                print("\nFunction: {} at {}".format(function_name, function_entry))
                print("Address: {}, Instruction: {} (Category: {})".format(address, full_instruction, patterns["instructions"][mnemonic]))
                continue

            # Get the references from this instruction and check for specific strings
            references = reference_manager.getReferencesFrom(address)
            for ref in references:
                if ref.getReferenceType().isData():
                    ref_addr = ref.getToAddress()
                    if ref_addr is not None:
                        data = listing.getDataAt(ref_addr)
                        if data is not None and data.hasStringValue():
                            string_value = data.getValue().lower()  # Convert string value to lowercase
                            for keyword, category in patterns["strings"].items():
                                if keyword in string_value:
                                    print("\nFunction: {} at {}".format(function_name, function_entry))
                                    print("Address: {}, Instruction: {}".format(address, full_instruction))
                                    print("  References string: {} (Category: {})".format(string_value, category))
                                    break
                        else:
                            # Check if the referenced data is a scalar (e.g., an integer or pointer)
                            scalar = instruction.getScalar(0)
                            if scalar is not None:
                                value = scalar.getValue()
                                string_addr = program.getAddressFactory().getAddress(hex(value))
                                if string_addr is not None:
                                    data = listing.getDataAt(string_addr)
                                    if data is not None and data.hasStringValue():
                                        string_value = data.getValue().lower()  # Convert string value to lowercase
                                        for keyword, category in patterns["strings"].items():
                                            if keyword in string_value:
                                                print("\nFunction: {} at {}".format(function_name, function_entry))
                                                print("Address: {}, Instruction: {}".format(address, full_instruction))
                                                print("  References string: {} (Category: {})".format(string_value, category))
                                                break
