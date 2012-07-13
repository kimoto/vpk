vpk
===
VPK File Format Parser (extract and archive)

What is VPK
===
VPK is "Valve Pak". 
https://developer.valvesoftware.com/wiki/VPK

Usage
===
extract from your vpk file
 require 'vpk'
 VPK::VPKFile.new("./path_to.vpk").extract_to("./")

archive from your directory
 require 'vpk'
 VPK::VPKFile.archive("./path_to_dir").write_to("./archive.vpk")

