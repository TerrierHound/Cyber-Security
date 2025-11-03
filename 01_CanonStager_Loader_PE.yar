rule CanonStager_Loader_PE
{
    meta:
        author = "ChatGPT for user"
        date = "2025-11-03"
        description = "Detects CanonStager-like loader/PE artifacts (strings from SecurityAffairs summary)."
        source = "SecurityAffairs / Arctic Wolf summary"
        reference = "https://securityaffairs.com/184083/apt/china-linked-unc6384-exploits-windows-zero-day-to-spy-on-european-diplomats.html"

    strings:
        $s_cnmpaui      = "cnmpaui"            nocase
        $s_cnmpaui_dll  = "cnmpaui.dll"        nocase
        $s_cnmpaui_exe  = "cnmpaui.exe"        nocase
        $s_cnmplog      = "cnmplog.dat"        nocase
        $s_tarname      = "rjnlzlkfe.ta"       nocase
        $s_appdata_tmp  = "%AppData%\\Local\\Temp" nocase
        $s_eu_decoy     = "EU meeting agenda"  nocase
        $s_rc4_hint     = "RC4"                nocase

    condition:
        pe and ( any of ($s_cnmpaui*, $s_cnmplog, $s_tarname, $s_appdata_tmp, $s_eu_decoy) )
}
