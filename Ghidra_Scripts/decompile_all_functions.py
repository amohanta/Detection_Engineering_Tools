#written by Abhijit mohanta and chatgpt

import os
import ghidra.app.decompiler.DecompInterface as DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

# Get the current program
currentProgram = getCurrentProgram()

# Create a decompiler object
decompInterface = DecompInterface()

# Set up the decompiler
if not decompInterface.openProgram(currentProgram):
	print("Failed to initialize the decompiler")
	quit()

# Get the listing of functions in the current program
functionManager = currentProgram.getFunctionManager()
functions = functionManager.getFunctions(True)

# Create a file to save the decompiled output
outputFile =  "C:\\test\\decompiled.txt"
f = open(outputFile, "w")

# Loop through each function, decompile it, and save the output to the file
for func in functions:
	result = decompInterface.decompileFunction(func, 0, ConsoleTaskMonitor())
	if result.decompileCompleted():
		f.write("Function: " + func.getName() + "\n")
		f.write(result.getDecompiledFunction().getC()) # Save the decompiled output
		f.write("\n\n")

# Close the file and clean up the decompiler
f.close()
decompInterface.dispose()
