import sys
from cx_Freeze import setup, Executable

# Dependencies are automatically detected, but it might need fine tuning.
build_exe_options = {
	"packages": ["os"], 
	"excludes": ["tkinter"],
	"include_files": [
		("C:\\Program Files\\Microsoft Visual Studio 9.0\\VC\\redist\\x86\\Microsoft.VC90.CRT\\", "."), 
		"config.json",
		"firefly-blacklist.txt",
		"firefly-blacklist.meta.json",
		"firefly-hosts.txt",
		"firefly-hosts.meta.json",
		"firefly-hosts-disabled.txt",
		"custom-blacklist.txt",
		"custom-whitelist.txt",
        "meek-relays.txt",
		"cacert.pem",
		"README.md",
		"LICENSE",
		("webui\\static", "webui\\static"),
		("webui\\templates", "webui\\templates"),
		("tools\\", "tools"),
	],
}

# GUI applications require a different base on Windows (the default is for a
# console application).
base = None
if sys.platform == "win32":
	base = "Win32GUI"


exe = Executable(
	# what to build
	script = "main.py", # the name of your main python script goes here 
	initScript = None,
	base = base, # if creating a GUI instead of a console app, type "Win32GUI"
	targetName = "firefly.exe", # this is the name of the executable file
	copyDependentFiles = True,
	compress = True,
	appendScriptToExe = True,
	appendScriptToLibrary = True,
	icon = "firefly.ico" # if you want to use an icon file, specify the file name here
)

setup(
	name = "firefly",
	version = "0.2.0",
	description = "an Internet censorship circumvention tool",
	options = {"build_exe": build_exe_options},
	executables = [exe]
)
