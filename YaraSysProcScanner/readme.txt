YaraSysProcScanner can be used for used scanning all the processes in the system for presese of malware. YaraSysProcScanner is just a wrapper for yara and is based on the concept of memory scanning we discussed in our blog https://www.intelliroot.com/resource_library/tools/yaraedr.
The tool has both 32 and 64 bits. The tool is handy tool for malware analysts and Incident Responder.

  
The tool needs two parameters one the the yara binary which you can download from the yara repository https://github.com/VirusTotal/yara/releases. 
The second parameter is a yara rule file which you need to provide.
Suggest to keep all the files (yaraSysProcScanner, yara binary and yara rule file) in same directory and run the command:
YaraSysProcScnner <yara_binary> <yara_rule_file>.

