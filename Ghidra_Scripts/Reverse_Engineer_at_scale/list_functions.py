# Import the necessary Ghidra modules
#from ghidra.app.script import GhidraScript
import os
logFile = 'D:\\Ghidra_test\\Logs\\func_list.txt'
if (os.path.exists(logFile) == False):
	f = open("file", "w")
	f.close()
else:
    print("File Exists")
	
def main():
		# Your script logic goes here
		# Access and manipulate the Ghidra API as needed
		binary_name = currentProgram.getExecutablePath()
		f = open( logFile, 'a')
		f.write("******************************\n")		
		f.write(str(binary_name) + "\n")
# Print the binary name
		print("Binary Name: " + binary_name)
		# Example: Print the names of all functions in the program
		for function in currentProgram.getFunctionManager().getFunctions(True):
			print function.getName()
			f.write(str(function.getName())+ "\n")
		f.close()

main()
