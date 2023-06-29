# a log created for each file with name <filename>_scriptName_log.txt in  Logs Directory

import os
Ghidra_Home = "D:\\Ghidra_test\\Ghidra" #point to you Ghidra home folder
Headless_bat_path = Ghidra_Home + "\\support\\analyzeHeadless.bat" 

Project_Dir = "C:\\Users\\abhijit" #Ghidra project Directory
Project_name = "service" #Ghidra project Name

SampleDir_path = "D:\\Ghidra_test\\binary\\" #place all samples in this directory

ScriptDir = "D:\\Ghidra_test\\script" #directory containing script

if not os.path.exists("Logs"):
	os.makedirs("Logs")

SampleFile_list = os.listdir(SampleDir_path)
for SampleFile_Name in SampleFile_list:
	#SampleFile_Name = "Sample_6.1.exe"
	print "analysis_file => " + str(SampleFile_Name)
	ScriptName = "list_functions.py" #script name
	Sample_abs_path = SampleDir_path + str(SampleFile_Name)
	command = Headless_bat_path + " " + Project_Dir + " " + Project_name + " -import " + Sample_abs_path + " -scriptPath " + ScriptDir + " -postScript " + ScriptName + " -overwrite " + " >> " + "Logs\\" +str(SampleFile_Name) + "_" + ScriptName + "_log.txt"

	print command
	os.system(command)