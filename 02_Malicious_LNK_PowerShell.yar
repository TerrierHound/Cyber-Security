rule Malicious_LNK_PowerShell_Delivery
{
    meta:
        author = "ChatGPT for user"
        date = "2025-11-03"
        description = "Detect LNK-delivered obfuscated PowerShell that extracts tar and drops loader (heuristic)."
        source = "SecurityAffairs / Arctic Wolf summary"

    strings:
        $s_lnk_marker        = ".lnk"                         nocase
        $s_powershell        = "powershell"                   nocase
        $s_iEX               = "IEX "                         nocase
        $s_from_b64          = "FromBase64String"             nocase
        $s_tar_cmd           = "tar -x"                       nocase
        $s_extract_tmp       = "%AppData%\\Local\\Temp"       nocase
        $s_rjnlzlkfe         = "rjnlzlkfe.ta"                 nocase
        $s_eu_decoy          = "EU meeting agenda"            nocase
        $s_invoked_command   = "Start-Process"                nocase
        $s_obfuscation_char  = "-EncodedCommand"              nocase

    condition:
        not pe and (
            (any of ($s_powershell, $s_iEX, $s_from_b64, $s_obfuscation_char) and any of ($s_tar_cmd, $s_extract_tmp, $s_rjnlzlkfe))
            or
            (any of ($s_lnk_marker) and any of ($s_powershell, $s_from_b64, $s_tar_cmd))
        )
}
