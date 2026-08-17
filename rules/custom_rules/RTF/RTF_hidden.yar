   
rule hidden_objects{   
    meta:
        authour     = "Hurkins"
        date        = "30-06-2026"
        description = "checks for hidden objects in rtf"
        severity    = "High"
    strings:
        $RTF_magic    = { 7B 5C 72 74 66 }
        $objocx       = "\\objocx"
        $objw         = "\\objw"
        $objh         = "\\objh"
    condition:
        $RTF_magic at 0 
        and  any of ($objocx,$objw = /\\objw[0-9]{1,2}[^0-9]/, $objh = /\\objh[0-9]{1,2}[^0-9]/)

}

rule UNC_paths{
    meta:
        authour     = "Hurkins"
        date        = "30-06-2026"
        description = "checks for UNC path"
        severity    = "High"
    strings:
        $RTF_magic    = { 7B 5C 72 74 66 }
        $objdata      = "\\objdata"
        $UNC_utf_16le = { 5C 00 5C 00 }
        $UNC_hex      = "5c005c00" nocase
    condition:
        $RTF_magic at 0
        and ($objdata or any of ($UNC_*))
}


rule olemagic{
    meta:
        authour     = "Hurkins"
        date        = "30-06-2026"
        description = "checks for OLE"
        severity    = "High"
    strings:
        $RTF_magic  = { 7B 5C 72 74 66 }
        $objocx     = "\\objocx"
        $ole_magic  = "d0cf11e0a1b11ae1" nocase
    condition:
    $RTF_magic at 0
    and ($objocx or $ole_magic)
    
}



