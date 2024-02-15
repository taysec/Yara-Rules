import "pe"

rule NjRAT_detection {
	meta:
		Description = "Regla para identificar muestra activa de NjRAT"
		Author = "Mnemo_CTI"
		Date = "2024-02-15"
		sha1 = "F0CD78B2E7D47C673DED49819D06AAB70991014D"
		
	strings:
		// strings
		$s1 = "GetWindowThreadProcessId" fullword
		$s2 = "cmd.exe /c ping 0 -n 2 & del" wide ascii
		
		// location
		$l1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide ascii
		
		// web address
		$w1 = "spykronic.duckdns.org" wide
		
	condition:
		uint16(0) == 0x5A4D
		and pe.version_info["OriginalFilename"] contains "Server.exe"
		and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744"
		and all of ($s*, $l1, $w1)
}
