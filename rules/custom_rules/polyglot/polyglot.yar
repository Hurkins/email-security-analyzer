rule pdf_zip_polyglot{
    meta:
        authour     = "Hurkins"
        date        = "30-06-2026"
        description = "checks for pdf-zip polyglot"
        severity    = "High"
    strings:
        $pdf_header = { 25 50 44 46 }
        $pdf_footer = { 25 25 45 4F 46 }
        $zip_local  = { 50 4B 03 04 }
        $zip_cd     = { 50 4B 01 02 }
        $zip_eocd   = { 50 4B 05 06 }
    condition:
        $pdf_header at 0
        and @pdf_footer < @zip_local
        and all of ($zip_*)
}

rule exe_zip_polyglot {
    meta:
        authour     = "Hurkins"
        date        = "30-06-2026"
        description = "checks for pdf-zip polyglot"
        severity    = "High"
    strings:
        $mz        = { 4D 5A }
        $pe        = { 50 45 00 00 }
        $zip_local = { 50 4B 03 04 }
        $zip_cd    = { 50 4B 01 02 }
        $zip_eocd  = { 50 4B 05 06 }
    condition:
        $mz at 0
        and $pe in (0..1024)
        and all of ($zip_*)
}

rule jpeg_zip_polyglot {
    meta:
        authour     = "Hurkins"
        date        = "30-06-2026"
        description = "checks for pdf-zip polyglot"
        severity    = "High"
    strings:
        $jpeg_start = { FF D8 FF }
        $jpeg_end   = { FF D9 }
        $zip_local  = { 50 4B 03 04 }
        $zip_cd     = { 50 4B 01 02 }
        $zip_eocd   = { 50 4B 05 06 }
    condition:
        $jpeg_start at 0
        and @jpeg_end < @zip_local
        and all of ($zip_*)
}

rule gif_zip_polyglot {
    meta:
        authour     = "Hurkins"
        date        = "30-06-2026"
        description = "checks for pdf-zip polyglot"
        severity    = "High"
    strings:
        $gif_header  = { 47 49 46 38 }
        $gif_footer  = { 3B }
        $zip_local  = { 50 4B 03 04 }
        $zip_cd     = { 50 4B 01 02 }
        $zip_eocd   = { 50 4B 05 06 }
    condition:
        $gif_header at 0
        and @gif_footer < @zip_local
        and all of ($zip_*)
}

rule png_zip_polyglot {
    meta:
        authour     = "Hurkins"
        date        = "30-06-2026"
        description = "checks for pdf-zip polyglot"
        severity    = "High"
    strings:
        $png_header = { 89 50 4E 47 0D 0A 1A 0A }
        $png_footer = { 49 45 4E 44 AE 42 60 82 }
        $zip_local  = { 50 4B 03 04 }
        $zip_cd     = { 50 4B 01 02 }
        $zip_eocd   = { 50 4B 05 06 }
    condition:
        $png_header at 0
        and @png_footer < @zip_local
        and all of ($zip_*)

}