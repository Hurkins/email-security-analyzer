rule malicious_pdf{
    meta:
        authour     = "Hurkins Palichina"
        date        = "24-06-2026"
        description = "Detecting pdf files with malicious embedded JavaScript"
        severity    = "high"
    
    strings: 
        $pdf_header = {25 50 44 46}
        $js_1       = "/JavaScript" nocase
        $js_2       = "/JS" nocase
        $launch     = "/Launch" nocase
        $embed      = "/EmbeddedFile" nocase
        $execute     = "/OpenAction" nocase
    condition:
        $pdf_header at 0
        and filesize < 5MB
        and (
            any of ($js_1, $js_2, $launch)
            or $embed
            or $execute
        )
}