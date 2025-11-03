UNC6384_YARA_Rules
======================

Dosya listesi (zip içinde):
- 01_CanonStager_Loader_PE.yar      : YARA kuralı - CanonStager / loader / PE artifact'leri için
- 02_Malicious_LNK_PowerShell.yar   : YARA kuralı - .LNK -> obfuscated PowerShell -> tar/droplog tespiti (heuristic)
- 03_UNC6384_C2_Domains.yar         : YARA kuralı - makalede belirtilen C2 domain referanslarını arar
- README.md                         : Bu dosya

Kaynak / referans:
- SecurityAffairs makalesi (Arctic Wolf raporu özetlenmiş): https://securityaffairs.com/184083/apt/china-linked-unc6384-exploits-windows-zero-day-to-spy-on-european-diplomats.html

Kullanım notları:
- Bu kurallar makalede geçen IoC'ler ve özet bilgiler temel alınarak oluşturuldu. Üretime almadan önce test edip false-positive/negative oranını değerlendir.
- Fileless veya bellek içi varyantlar diske yazılmazsa YARA ile tespit zorlaşır. Bellek taraması (YARA-for-volatility vb.) veya network tespit kuralları da kullanın.
- Daha kesin tespit için dosya hash'leri (SHA256/MD5) veya ek domain/IP listeleri ile kuralları güncelleyin.
