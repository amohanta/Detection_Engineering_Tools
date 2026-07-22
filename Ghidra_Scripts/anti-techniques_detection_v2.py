#author: abhijit mohanta abhijit.mohanta.15.08@gmail.com abhijit@intelliroot.com

# PyGhidra compatible version for Ghidra 12.x

from ghidra.program.model.scalar import Scalar

PATTERNS = {
    "strings": {
        "vmware": "anti-vm => VMware Detection",
        "virtualbox": "anti-vm => VirtualBox Detection",
        "vbox": "anti-vm => VirtualBox Detection",
        "sandbox": "Sandbox Detection",

        "sbiesvc": "Tool Detection => Sandboxie Detection",
        "sbiedrv": "Tool Detection => Sandboxie Detection",
        "sandboxierpcss.exe": "Tool Detection => Sandboxie Detection",

        "procmon": "Tool Detection => Process Monitor Detection",
        "eventvwr.exe": "Binary used for possible UAC bypass",

        "procexp": "Tool Detection => Process Explorer Detection",
        "ollydbg": "Anti-Debug => OllyDbg Detection",

        "vboxtray.exe": "Anti-VM => VirtualBox Detection",

        "superantispyware.exe": "Tool Detection",

        "etherd.exe": "Network Sniffer Detection",
        "sniffer.exe": "Network Sniffer Detection",
        "wireshark": "Network Sniffer Detection",
    },

    "instructions": {
        "IN": "VMWare Detection instruction (IN instruction)"
    }
}


def check_string_reference(program, listing, ref_manager, instruction,
                           function_name, function_entry):

    refs = ref_manager.getReferencesFrom(
        instruction.getAddress()
    )

    for ref in refs:

        if not ref.getReferenceType().isData():
            continue

        target_addr = ref.getToAddress()

        if target_addr is None:
            continue


        data = listing.getDataAt(target_addr)


        if data is None:
            continue


        if not data.hasStringValue():
            continue


        try:
            value = str(data.getValue()).lower()

        except Exception:
            continue


        for search_key, technique in PATTERNS["strings"].items():

            if search_key.lower() in value:

                print("")
                print("[+] Function : {} @ {}".format(
                    function_name,
                    function_entry
                ))

                print("[+] Address  : {}".format(
                    instruction.getAddress()
                ))

                print("[+] Instruction : {}".format(
                    instruction
                ))

                print("[+] String : {}".format(
                    value
                ))

                print("[+] Detection : {}".format(
                    technique
                ))

                print("-" * 60)

                return



def check_scalar_reference(program, listing, instruction,
                           function_name, function_entry):

    scalar = instruction.getScalar(0)

    if scalar is None:
        return


    value = scalar.getValue()


    try:
        address_space = (
            program
            .getAddressFactory()
            .getDefaultAddressSpace()
        )

        target_addr = address_space.getAddress(value)

    except Exception:
        return


    if target_addr is None:
        return


    data = listing.getDataAt(target_addr)


    if data is None:
        return


    if not data.hasStringValue():
        return


    try:
        value_string = str(data.getValue()).lower()

    except Exception:
        return


    for search_key, technique in PATTERNS["strings"].items():

        if search_key.lower() in value_string:

            print("")
            print("[+] Function : {} @ {}".format(
                function_name,
                function_entry
            ))

            print("[+] Address : {}".format(
                instruction.getAddress()
            ))

            print("[+] String : {}".format(
                value_string
            ))

            print("[+] Detection : {}".format(
                technique
            ))

            print("-" * 60)

            return



def main():

    program = currentProgram


    if program is None:

        print("[-] No program opened")

        return



    print("[+] Analyzing: {}".format(
        program.getName()
    ))


    listing = program.getListing()

    function_manager = (
        program
        .getFunctionManager()
    )

    reference_manager = (
        program
        .getReferenceManager()
    )


    functions = (
        function_manager
        .getFunctions(True)
    )


    count = 0


    for ghidra_function in functions:


        function_name = (
            ghidra_function
            .getName()
        )


        function_entry = (
            ghidra_function
            .getEntryPoint()
        )


        instructions = (
            listing
            .getInstructions(
                ghidra_function.getBody(),
                True
            )
        )


        for instr in instructions:


            mnemonic = (
                instr
                .getMnemonicString()
            )


            if mnemonic in PATTERNS["instructions"]:

                print("")
                print("[+] Function : {} @ {}".format(
                    function_name,
                    function_entry
                ))

                print("[+] Address : {}".format(
                    instr.getAddress()
                ))

                print("[+] Instruction : {}".format(
                    instr
                ))

                print("[+] Detection : {}".format(
                    PATTERNS["instructions"][mnemonic]
                ))

                print("-" * 60)

                count += 1


            check_string_reference(
                program,
                listing,
                reference_manager,
                instr,
                function_name,
                function_entry
            )


            check_scalar_reference(
                program,
                listing,
                instr,
                function_name,
                function_entry
            )


    print("")
    print("[+] Analysis completed")
    print("[+] Findings: {}".format(count))



main()