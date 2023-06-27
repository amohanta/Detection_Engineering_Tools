# Import the necessary Ghidra modules
from ghidra.app.script import GhidraScript

class MyHeadlessScript(GhidraScript):
	def run(self):
        # Your script logic goes here
        # Access and manipulate the Ghidra API as needed
        
        # Example: Print the names of all functions in the program
		for function in currentProgram.getFunctionManager().getFunctions(True):
			self.println(function.getName())

# Create an instance of your script and run it
headlessScript = MyHeadlessScript()
headlessScript.run()
