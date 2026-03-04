import re
import math
from urllib.parse import urlparse

def extract_features(url_string):
    url_string = str(url_string).strip()
    normalized_url = url_string.rstrip('/')
    parsed = urlparse(url_string)
    host = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    url_len = len(normalized_url)
    dom_len = len(host)
    is_ip = 1 if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", host) else 0
    
    parts = host.split('.')
    tld_len = len(parts[-1]) if len(parts) > 0 else 0
    subdom_cnt = len(parts) - 2 if len(parts) > 2 else 0

    # --- START SINGLE PASS OPTIMIZATION ---
    # Inisialisasi semua penghitung
    letter_cnt = 0
    digit_cnt = 0
    special_cnt = 0
    char_counts = {c: 0 for c in "=?&.-_/"} # Karakter spesifik fitur 9-14 & 19
    char_freqs = {} # Untuk perhitungan Entropy fitur 20

    for char in normalized_url:
        # 1. Update frekuensi karakter (untuk Entropy)
        char_freqs[char] = char_freqs.get(char, 0) + 1
        
        # 2. Update hitungan karakter spesifik
        if char in char_counts:
            char_counts[char] += 1
            
        # 3. Klasifikasi Leksikal (Fitur 6, 7, 8)
        if char.isalpha():
            letter_cnt += 1
        elif char.isdigit():
            digit_cnt += 1
        else:
            special_cnt += 1
    # --- END SINGLE PASS OPTIMIZATION ---

    # Rasio (Fitur 15, 16, 17)
    l_ratio = letter_cnt / url_len if url_len > 0 else 0
    d_ratio = digit_cnt / url_len if url_len > 0 else 0
    s_ratio = special_cnt / url_len if url_len > 0 else 0

    # Perhitungan Entropy (Fitur 20) menggunakan data dari Single Pass
    entropy = 0
    if url_len > 0:
        for count in char_freqs.values():
            p = count / url_len
            entropy -= p * math.log2(p)

    # Susun 22 Fitur sesuai urutan model XGBoost
    features = [
        url_len,               # 1
        dom_len,               # 2
        is_ip,                 # 3
        tld_len,               # 4
        subdom_cnt,            # 5
        letter_cnt,            # 6
        digit_cnt,             # 7
        special_cnt,           # 8
        char_counts['='],      # 9
        char_counts['?'],      # 10
        char_counts['&'],      # 11
        char_counts['.'],      # 12
        char_counts['-'],      # 13
        char_counts['_'],      # 14
        l_ratio,               # 15
        d_ratio,               # 16
        s_ratio,               # 17
        1 if url_string.startswith('https') else 0, # 18
        char_counts['/'],      # 19
        entropy,               # 20
        len(path),             # 21
        len(query)             # 22
    ]
    
    return features