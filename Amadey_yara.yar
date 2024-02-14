import "pe"

rule amadey_CTI {
	
	meta:
		Author = "CTI_MNEMO"
		Date = "2024-02-13"
		FileType = "Win32 EXE"
		sha1 = "64BD92B0A8CD71D8A795F481BE30763F2139EA76"

	strings:
		$a1 = "Wkgdvkiecv" fullword
		$a2 = "AesEncryption" fullword
		$a3 = ".edom SOD ni nur eb tonnac margorp sihT!" fullword
		
		$h1 = {00 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 47 00 7A 00 63 00 75 00 65 00 6F 00 61 00 72 00 75 00 65 00 2E 00 65 00 78 00 65 00} // OriginalFilename

	condition:
		uint16(0) == 0x5A4D
		and pe.version_info["OriginalFilename"] contains "Gzcueoarue.exe"
		//and pe.imports["ICryptoTransform"; "MutexRights"; "RandomNumberGenerator"; "MemoryStream"]
		and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744"
		and all of ($a*) and $h1
		

}