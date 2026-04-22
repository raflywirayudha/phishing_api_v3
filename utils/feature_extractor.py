import re
import math
import tldextract
from urllib.parse import urlparse

# Extractor khusus fitur (tanpa private domains agar cocok dengan dataset)
feature_extractor = tldextract.TLDExtract(include_psl_private_domains=False)

def extract_features(url_string):

    # Pra-pemrosesan string
    url_string = str(url_string).strip()
    normalized_url = url_string.rstrip('/')
    parsed = urlparse(url_string)

    host = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    # 1. Panjang keseluruhan URL
    url_len = len(normalized_url)

    # Ekstraksi domain menggunakan tldextract
    ext = feature_extractor(url_string)
    registered_domain = ext.top_domain_under_public_suffix or ""

    # 2. Panjang domain utama (Registered Domain)
    dom_len = len(registered_domain)

    # 3. Status IP Address (1 jika IP, 0 jika Nama Host)
    is_ip = 1 if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", host) else 0
    
    # 4. Panjang TLD (Top Level Domain)
    tld_len = len(ext.suffix)

    # 5. Jumlah subdomain 
    subdom_cnt = len(ext.subdomain.split('.')) if ext.subdomain else 0

    # Inisialisasi penghitung karakter (Fitur 6, 7, 8, 9, 10, 11, 12, 13, 14, 19)
    letter_cnt = 0
    digit_cnt = 0
    special_cnt = 0
    char_counts = {c: 0 for c in "=?&.-_/"} 
    char_freqs = {} 

    for char in normalized_url:
        char_freqs[char] = char_freqs.get(char, 0) + 1
        if char in char_counts:
            char_counts[char] += 1
        if char.isalpha():
            letter_cnt += 1         # 6. Jumlah huruf
        elif char.isdigit():
            digit_cnt += 1          # 7. Jumlah angka
        else:
            special_cnt += 1        # 8. Jumlah karakter spesial


    # 15, 16, 17. Perhitungan Rasio
    l_ratio = letter_cnt / url_len if url_len > 0 else 0
    d_ratio = digit_cnt / url_len if url_len > 0 else 0
    s_ratio = special_cnt / url_len if url_len > 0 else 0

    # 20. Perhitungan Entropy (Tingkat keacakan URL)
    entropy = 0
    if url_len > 0:
        for count in char_freqs.values():
            p = count / url_len
            entropy -= p * math.log2(p)

    features = [
        url_len,                                    # 1. Panjang keseluruhan URL
        dom_len,                                    # 2. Panjang domain utama (Registered Domain)
        is_ip,                                      # 3. Status IP Address (1 jika IP, 0 jika Nama Host)
        tld_len,                                    # 4. Panjang TLD (Top Level Domain) cth: '.com' atau '.ac.id'
        subdom_cnt,                                 # 5. Jumlah subdomain yang ditemukan
        letter_cnt,                                 # 6. Jumlah karakter alfabet (a-z)
        digit_cnt,                                  # 7. Jumlah karakter angka (0-9)
        special_cnt,                                # 8. Jumlah karakter spesial (selain huruf dan angka)
        char_counts['='],                           # 9. Frekuensi karakter '='
        char_counts['?'],                           # 10. Frekuensi karakter '?' (tanda tanya)
        char_counts['&'],                           # 11. Frekuensi karakter '&' (ampersand)
        char_counts['.'],                           # 12. Frekuensi karakter '.' (titik)
        char_counts['-'],                           # 13. Frekuensi karakter '-' (tanda hubung)
        char_counts['_'],                           # 14. Frekuensi karakter '_' (garis bawah)
        l_ratio,                                    # 15. Rasio huruf terhadap panjang URL
        d_ratio,                                    # 16. Rasio angka terhadap panjang URL
        s_ratio,                                    # 17. Rasio karakter spesial terhadap panjang URL
        1 if url_string.startswith('https') else 0, # 18. Penggunaan Protokol HTTPS (1 jika Ya, 0 jika Tidak)
        char_counts['/'],                           # 19. Frekuensi karakter '/' (garis miring)
        entropy,                                    # 20. Skor Entropy (mengukur kerumitan/keacakan string URL)
        len(path),                                  # 21. Panjang bagian Path pada URL
        len(query)                                  # 22. Panjang bagian Query String pada URL
    ]
    
    return features