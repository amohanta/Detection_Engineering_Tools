import os
Ghidra_Home = "D:\\Ghidra_test\\Ghidra"
Headless_bat_path = Ghidra_Home + "\\support\\analyzeHeadless.bat" 

Project_Dir = "C:\\Users\\abhijit"
Project_name = "service"
SampleFile_list = ["Sample_6.1.exe","main.exe","RE-Sample-27-Anti-Vm.exe_","shellcode_injector.exe"]

SampleDir_path = "D:\\Ghidra_test\\binary\\"

ScriptDir = "D:\\Ghidra_test\\script"
ScriptName = "list_functions.py"




for SampleFile_Name in SampleFile_list:
	#SampleFile_Name = "Sample_6.1.exe"
	Sample_abs_path = SampleDir_path + SampleFile_Name
	command = Headless_bat_path + " " + Project_Dir + " " + Project_name + " -import " + Sample_abs_path + " -scriptPath " + ScriptDir + " -postScript " + ScriptName + " -overwrite"

	print command
	os.system(command)