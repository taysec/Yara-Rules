import "pe"
import "dotnet"

rule Asyncrat {
	meta:
		Description = "Regla para identificar muestra de AsyncRat"
		Autor = "CTI_Mnemo" 
		Date = "2024-02-15"
		Hash= "sha256,0E948E3D83E22DF165AFAC4DA052B45297F719A33F86C4C194958F59DAD75A28"
		
	strings:
		
		$Entrypoint = {7E 0A 00 00 04 20 E8 03 00 00 D8 28 1F 00 00 0A 7E}
		
		$s1= "shutdown.exe /f /s /t 0" fullword wide
		$s2= "shutdown.exe -L" fullword wide
		$s3= "Select * from AntivirusProduct" fullword wide
		$s4= "IAsyncResult" fullword 
		$s5= "XWorm V3.0" fullword wide
		
	condition:
		uint16(0) == 0x5A4D
		and pe.version_info["OriginalFilename"] contains "XClient.exe"
		and pe.imphash()== "f34d5f2d4577ed6d9ceec516c1f5a744"
		and dotnet.version == "v4.0.30319"
		and all of ($s*) 
		and $Entrypoint
}
