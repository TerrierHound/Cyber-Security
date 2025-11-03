rule UNC6384_C2_Domains
{
    meta:
        author = "ChatGPT for user"
        date = "2025-11-03"
        description = "Detect references to known domains reported in the SecurityAffairs article."
        source = "SecurityAffairs / Arctic Wolf summary"

    strings:
        $d1 = "racineupci.org"        nocase
        $d2 = "dorareco.net"          nocase
        $d3 = "naturadeco.net"        nocase
        $d4 = "cloudfront"            nocase

        $http_prefix = "http://"       nocase
        $https_prefix = "https://"     nocase

    condition:
        (any of ($d1, $d2, $d3) and (any of ($http_prefix, $https_prefix) or filesize < 2000000))
        or
        (any of ($d1, $d2, $d3) and not pe)
}
