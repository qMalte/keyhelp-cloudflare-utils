import re

def is_valid_ipv4(ip: str) -> bool:
    """
    Überprüft, ob eine IPv4-Adresse gültig ist.
    
    Prüft folgende Kriterien:
    - Exakt 4 Oktette, getrennt durch Punkte
    - Jedes Oktett muss eine Zahl zwischen 0 und 255 sein
    - Keine führenden Nulllen (wie '01' statt '1')
    
    Args:
        ip: String mit der zu prüfenden IP-Adresse
        
    Returns:
        bool: True wenn gültig, False wenn ungültig
        
    Examples:
        >>> is_valid_ipv4("192.168.1.1")
        True
        >>> is_valid_ipv4("256.1.2.3")
        False
        >>> is_valid_ipv4("1.2.3.4.5")
        False
        >>> is_valid_ipv4("192.168.01.1")
        False
    """
    
    # IPv4 Regex Pattern
    # Erklärt:
    # ^                    Start des Strings
    # (?:                  Nicht-erfassende Gruppe
    #   25[0-5]           Matches 250-255
    #   |                 ODER
    #   2[0-4][0-9]      Matches 200-249
    #   |                 ODER
    #   [1]?[0-9][0-9]?  Matches 0-199
    # )                   Ende der Gruppe
    # \.                  Literal dot
    # {4}                 Exakt 4 mal die vorherige Gruppe
    # $                   Ende des Strings
    
    pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[1]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[1]?[0-9][0-9]?)$'
    
    return bool(re.match(pattern, ip))

def is_valid_ipv6(ip: str) -> bool:
    """
    Überprüft, ob eine IPv6-Adresse gültig ist.
    
    Prüft folgende Kriterien:
    - 8 Gruppen von je 1-4 Hexadezimalziffern
    - Gruppen getrennt durch Doppelpunkte
    - Erlaubt eine einzelne Gruppe von doppelten Doppelpunkten für komprimierte Nullen
    - Case-insensitive Hexadezimalziffern
    
    Args:
        ip: String mit der zu prüfenden IP-Adresse
        
    Returns:
        bool: True wenn gültig, False wenn ungültig
        
    Examples:
        >>> is_valid_ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        True
        >>> is_valid_ipv6("2001:db8::2:1")
        True
        >>> is_valid_ipv6("2001:db8::25de::cade")
        False
        >>> is_valid_ipv6("2001:db8:85a3:0000:0000:8a2e:0370:7334:extra")
        False
    """
    
    # IPv6 Regex Pattern
    # Erklärt:
    # ^                Start des Strings
    # (?:              Nicht-erfassende Gruppe
    #   [0-9a-fA-F]{1,4} 1-4 Hexadezimalziffern
    #   :              Doppelpunkt
    # ){6}             6 solche Gruppen
    # [0-9a-fA-F]{1,4} Eine weitere Gruppe
    # $                Ende des Strings
    # ODER
    # ::              Doppelte Doppelpunkte (für Kompression)
    # (?:             Rest der Adresse
    #   [0-9a-fA-F]{1,4}:
    # ){0,6}          0-6 Gruppen
    # [0-9a-fA-F]{1,4}
    
    pattern = (
        r'^(?:'
        r'(?:[0-9a-fA-F]{1,4}:){6}'
        r'[0-9a-fA-F]{1,4}'
        r'|'
        r'::(?:[0-9a-fA-F]{1,4}:){0,5}'
        r'[0-9a-fA-F]{1,4}'
        r'|'
        r'(?:[0-9a-fA-F]{1,4}:){1}:(?:[0-9a-fA-F]{1,4}:){0,4}'
        r'[0-9a-fA-F]{1,4}'
        r'|'
        r'(?:[0-9a-fA-F]{1,4}:){2}:(?:[0-9a-fA-F]{1,4}:){0,3}'
        r'[0-9a-fA-F]{1,4}'
        r'|'
        r'(?:[0-9a-fA-F]{1,4}:){3}:(?:[0-9a-fA-F]{1,4}:){0,2}'
        r'[0-9a-fA-F]{1,4}'
        r'|'
        r'(?:[0-9a-fA-F]{1,4}:){4}:(?:[0-9a-fA-F]{1,4}:)?'
        r'[0-9a-fA-F]{1,4}'
        r'|'
        r'(?:[0-9a-fA-F]{1,4}:){5}:'
        r'[0-9a-fA-F]{1,4}'
        r'|'
        r'(?:[0-9a-fA-F]{1,4}:){7}'
        r'[0-9a-fA-F]{1,4}'
        r')$'
    )
    
    return bool(re.match(pattern, ip))

def generate_spf_record(ip_addresses: list) -> str:
    """
    Generiert einen SPF TXT Record aus einer gemischten Liste von IP-Adressen.
    Erkennt automatisch IPv4 und IPv6 Adressen und validiert diese.
    
    Args:
        ip_addresses: Liste von IP-Adressen (IPv4 oder IPv6) als Strings
    
    Returns:
        String mit dem kompletten SPF Record
    
    Example:
        ips = ["192.168.1.1", "2001:db8::1", "10.0.0.1", "2001:db8::2"]
        record = generate_spf_record(ips)
    """
    
    # Listen für sortierte und validierte IPs
    ipv4_addresses = []
    ipv6_addresses = []
    invalid_ips = []
    
    # Sortiere und validiere die IPs
    for ip in ip_addresses:
        try:
            if (is_valid_ipv4(ip)):
                ipv4_addresses.append(ip)
            elif (is_valid_ipv6(ip)):
                ipv6_addresses.append(ip)
        except ValueError:
            invalid_ips.append(ip)
    
    # Wenn ungültige IPs gefunden wurden, gib eine Warnung aus
    if invalid_ips:
        print(f"Warnung: Folgende IP-Adressen sind ungültig und werden übersprungen: {invalid_ips}")
    
    # Start mit dem SPF Version Identifier
    spf_parts = ["v=spf1"]
    
    # IPv4 Adressen hinzufügen
    for ip in ipv4_addresses:
        spf_parts.append(f"ip4:{ip}")
    
    # IPv6 Adressen hinzufügen
    for ip in ipv6_addresses:
        spf_parts.append(f"ip6:{ip}")
    
    # All mechanism hinzufügen
    spf_parts.append("-all")
    
    # Zusammenfügen mit Leerzeichen
    return " ".join(spf_parts)