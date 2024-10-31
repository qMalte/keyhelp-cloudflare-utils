import streamlit as st
import spf_helper as spf
from cloudflare import CloudflareAPI
from keyhelp import KeyHelpAPI

@st.cache_data(ttl=300)
def fetch_cloudflare_zones(_cloudflare: CloudflareAPI):
    return _cloudflare.get_zones()

@st.cache_data(ttl=300)
def fetch_keyhelp_domains(_keyhelp: KeyHelpAPI):
    return _keyhelp.list_domains()

@st.cache_data(ttl=300)
def fetch_server_info(_keyhelp: KeyHelpAPI):
    return _keyhelp.get_server_info()

@st.cache_data
def filter_ip_addresses(system):
    excluded_prefixes = ['192.168', '127.0', '172.1', '172.18', '10']
    return [ip for ip in system['meta']['ip_addresses'] 
            if not any(ip.startswith(prefix) for prefix in excluded_prefixes)]

@st.cache_data
def get_valid_domain_names(domains, zones):
    return [domain['domain'] for domain in domains 
            if next((z for z in zones['result'] if z['name'] == domain['domain']), None)]

def update_mx_record(cloudflare: CloudflareAPI, domain_name, expected_mx_record):
    # Get domain info
    zones = fetch_cloudflare_zones(cloudflare)

    zone = next((z for z in zones['result'] if z['name'] == domain_name), None)
    if not zone:
        st.error(f"Zone '{domain_name}' nicht gefunden.")
        return

    st.info(f"Zone '{domain_name}' gefunden.")

    # Get MX record
    with st.spinner("Lade DNS-Einträge..."):
        dns_records = cloudflare.get_dns_records(zone['id'])
    mx_records = [record for record in dns_records['result'] if record['type'] == 'MX']

    if len(mx_records) == 0:
        st.warning(f"Keine MX-Einträge für '{domain_name}' gefunden.")

    if len(mx_records) > 1:
        st.warning(f"Mehr als ein MX-Eintrag für '{domain_name}' gefunden.")
        for record in mx_records:
            with st.spinner(f"Lösche MX-Eintrag {record['id']}..."):
                cloudflare.delete_dns_record(zone['id'], record['id'])

    if len(mx_records) == 1:
        st.info(f"MX-Eintrag für '{domain_name}' gefunden.")
        
        if mx_records[0]['content'] == expected_mx_record and mx_records[0]['name'] == domain_name and mx_records[0]['priority'] == 10:
            st.success(f"MX-Eintrag für '{domain_name}' ist korrekt.")
            return

        with st.spinner(f"Lösche MX-Eintrag für '{domain_name}'..."):
            cloudflare.delete_dns_record(zone['id'], mx_records[0]['id'])

    with st.spinner(f"Erstelle MX-Eintrag für '{domain_name}'..."):
        cloudflare.add_dns_record(zone['id'], 'MX', domain_name, expected_mx_record)
    
def update_spf_record(cloudflare: CloudflareAPI, domain_name, ip_addresses):
    # Get domain info
    zones = fetch_cloudflare_zones(cloudflare)

    zone = next((z for z in zones['result'] if z['name'] == domain_name), None)
    if not zone:
        return

    # Check SPF (TXT) Record
    with st.spinner("Lade DNS-Einträge..."):
        dns_records = cloudflare.get_dns_records(zone['id'])
    spfRecords = [record for record in dns_records['result'] if record['type'] == 'TXT' and record['name'] == domain_name and 'v=spf1' in record['content']]

    spfRecord = spf.generate_spf_record(ip_addresses)

    if len(spfRecords) == 0:
        st.warning(f"Kein SPF-Eintrag für '{domain_name}' gefunden.")

    if len(spfRecords) > 1:
        st.warning(f"Mehr als ein SPF-Eintrag für '{domain_name}' gefunden.")
        for record in spfRecords:
            with st.spinner(f"Lösche SPF-Eintrag {record['id']}..."):
                cloudflare.delete_dns_record(zone['id'], record['id'])

    if len(spfRecords) == 1:
        st.info(f"SPF-Eintrag für '{domain_name}' gefunden.")
        
        if spfRecords[0]['content'] == spfRecord and spfRecords[0]['name'] == domain_name:
            st.success(f"SPF-Eintrag für '{domain_name}' ist korrekt.")
            return

        with st.spinner(f"Lösche SPF-Eintrag für '{domain_name}'..."):
            for record in spfRecords:
                cloudflare.delete_dns_record(zone['id'], record['id'])

    with st.spinner(f"Erstelle SPF-Eintrag für '{domain_name}'..."):
        cloudflare.add_dns_record(zone['id'], 'TXT', domain_name, spfRecord)

def update_dkim_record(cloudflare: CloudflareAPI, keyhelp: KeyHelpAPI, domain_name: str):
    # Get domain info
    zones = fetch_cloudflare_zones(cloudflare)
    domains = fetch_keyhelp_domains(keyhelp)

    domain = next((d for d in domains if d['domain'] == domain_name), None)
    if not domain:
        st.error(f"Domain '{domain_name}' nicht gefunden.")
        return

    zone = next((z for z in zones['result'] if z['name'] == domain_name), None)
    if not zone:
        return

    expected_dkim_record = domain['dkim_txt_record'];

    dkim_record_arr = expected_dkim_record.split(' IN TXT ( ')

    if len(dkim_record_arr) != 2:
        st.error(f"DKIM Record für '{domain_name}' ist ungültig.")
        return

    dkim_name = dkim_record_arr[0]
    dkim_content = dkim_record_arr[1][:-2]

    # Check DKIM (TXT) Record
    with st.spinner("Lade DNS-Einträge..."):
        dns_records = cloudflare.get_dns_records(zone['id'])
    dkimRecords = [record for record in dns_records['result'] if record['type'] == 'TXT' and record['name'] == f"{dkim_name}.{domain_name}" and 'v=DKIM1' in record['content']]

    if len(dkimRecords) == 0:
        st.warning(f"Kein DKIM-Eintrag für '{domain_name}' gefunden.")

    if len(dkimRecords) > 1:
        st.warning(f"Mehr als ein DKIM-Eintrag für '{domain_name}' gefunden.")
        for record in dkimRecords:
            with st.spinner(f"Lösche DKIM-Eintrag {record['id']}..."):
                cloudflare.delete_dns_record(zone['id'], record['id'])

    if len(dkimRecords) == 1:
        st.info(f"DKIM-Eintrag für '{domain_name}' gefunden.")
        
        if dkimRecords[0]['content'] == dkim_content and dkimRecords[0]['name'] == f"{dkim_name}.{domain_name}":
            st.success(f"DKIM-Eintrag für '{domain_name}' ist korrekt.")
            return

        with st.spinner(f"Lösche DKIM-Eintrag für '{domain_name}'..."):
            for record in dkimRecords:
                cloudflare.delete_dns_record(zone['id'], record['id'])

    with st.spinner(f"Erstelle DKIM-Eintrag für '{domain_name}'..."):
        cloudflare.add_dns_record(zone['id'], 'TXT', dkim_name, dkim_content)
        st.success(f"DKIM-Eintrag für '{domain_name}' erstellt.")

def update_dmarc_record(cloudflare: CloudflareAPI, domain_name: str, email: str):
    default_dmarc = f"v=DMARC1; p=quarantine; rua=mailto:{email}; ruf=mailto:{email}; fo=1;"

    # Get domain info
    zones = fetch_cloudflare_zones(cloudflare)

    zone = next((z for z in zones['result'] if domain_name in z['name']), None)
    if not zone:
        return

    # Check DMARC (TXT) Record
    with st.spinner("Lade DNS-Einträge..."):
        dns_records = cloudflare.get_dns_records(zone['id'])
    dmarcRecords = [record for record in dns_records['result'] if record['type'] == 'TXT' and '_dmarc' in record['name']]

    if len(dmarcRecords) == 0:
        st.warning(f"Kein DMARC-Eintrag für '{domain_name}' gefunden.")

    if len(dmarcRecords) > 1:
        st.warning(f"Mehr als ein DMARC-Eintrag für '{domain_name}' gefunden.")
        for record in dmarcRecords:
            with st.spinner(f"Lösche DMARC-Eintrag {record['id']}..."):
                cloudflare.delete_dns_record(zone['id'], record['id'])

    if len(dmarcRecords) == 1:
        st.info(f"DMARC-Eintrag für '{domain_name}' gefunden.")
        
        if dmarcRecords[0]['content'] == default_dmarc and dmarcRecords[0]['name'] == f"_dmarc.{domain_name}":
            st.success(f"DMARC-Eintrag für '{domain_name}' ist korrekt.")
            return

        with st.spinner(f"Lösche DMARC-Eintrag für '{domain_name}'..."):
            for record in dmarcRecords:
                cloudflare.delete_dns_record(zone['id'], record['id'])

    with st.spinner(f"Erstelle DMARC-Eintrag für '{domain_name}'..."):
        cloudflare.add_dns_record(zone['id'], 'TXT', "_dmarc", default_dmarc)
        st.success(f"DMARC-Eintrag für '{domain_name}' erstellt.")

def update_web_records(cloudflare: CloudflareAPI, keyhelp: KeyHelpAPI, domain_name: str, ip_addresses: list):
    """
    Aktualisiert DNS-Einträge für eine Domain und ihre Subdomains in Cloudflare basierend auf KeyHelp-Daten.
    
    Args:
        cloudflare: CloudflareAPI Instanz
        keyhelp: KeyHelpAPI Instanz
        domain_name: Name der Hauptdomain
        ip_addresses: Liste der zu prüfenden IP-Adressen
    """
    # Get domain info
    try:
        zones = fetch_cloudflare_zones(cloudflare)
        domains = fetch_keyhelp_domains(keyhelp)
    except Exception as e:
        st.error(f"Fehler beim Abrufen der Domain-Informationen: {str(e)}")
        return

    # Get Domains and Subdomains
    domain_list = []
    for domain in domains:
        if domain_name in domain['domain']:
            domain_list.append(domain)
            
    if not domain_list:
        st.warning(f"Keine Domains gefunden für {domain_name}")
        return
        
    # Zone ID finden
    zone = next((z for z in zones['result'] if z['name'] == domain_name), None)
    if not zone:
        st.error(f"Keine Zone gefunden für {domain_name}")
        return

    # DNS Records für jede Domain/Subdomain aktualisieren
    for domain_entry in domain_list:
        current_domain = domain_entry['domain']
        
        # DNS Records abrufen
        with st.spinner(f"Lade DNS-Einträge für {current_domain}..."):
            try:
                dns_records = cloudflare.get_dns_records(zone['id'])
                all_records = dns_records.get('result', [])
                
                # Separate A und AAAA Records für aktuelle Domain/Subdomain
                domain_records = [r for r in all_records if r['name'] == current_domain]
                a_records = [r for r in domain_records if r['type'] == 'A']
                aaaa_records = [r for r in domain_records if r['type'] == 'AAAA']
                
            except Exception as e:
                st.error(f"Fehler beim Abrufen der DNS-Einträge für {current_domain}: {str(e)}")
                continue

        # Dictionary für Status der IP-Adressen für diese Domain
        ip_status = {ip: False for ip in ip_addresses}
        
        # A-Records prüfen
        for record in a_records:
            for ip in ip_addresses:
                if spf.is_valid_ipv4(ip) and record['content'] == ip:
                    ip_status[ip] = True
                    st.success(f"A-Eintrag für '{current_domain}' ist korrekt.")

        # AAAA-Records prüfen
        for record in aaaa_records:
            for ip in ip_addresses:
                if spf.is_valid_ipv6(ip) and record['content'] == ip:
                    ip_status[ip] = True
                    st.success(f"AAAA-Eintrag für '{current_domain}' ist korrekt.")

        # Falsche Records für aktuelle Domain/Subdomain löschen
        incorrect_records = [
            record for record in domain_records 
            if record['type'] in ['A', 'AAAA'] 
            and not any(record['content'] == ip for ip in ip_addresses)
        ]
        
        for record in incorrect_records:
            try:
                with st.spinner(f"Lösche {record['type']}-Eintrag für {current_domain}..."):
                    cloudflare.delete_dns_record(zone['id'], record['id'])
                    st.warning(f"{record['type']}-Eintrag für '{current_domain}' gelöscht.")
            except Exception as e:
                st.error(f"Fehler beim Löschen des DNS-Eintrags für {current_domain}: {str(e)}")

        # Neue Records nur für fehlende IPs erstellen
        for ip in ip_addresses:
            try:
                if not ip_status[ip]:  # Nur erstellen wenn IP noch nicht korrekt zugewiesen
                    if spf.is_valid_ipv4(ip):
                        with st.spinner(f"Erstelle A-Eintrag für '{current_domain}'..."):
                            cloudflare.add_dns_record(zone['id'], 'A', current_domain, ip)
                            st.success(f"A-Eintrag für '{current_domain}' erstellt.")
                    elif spf.is_valid_ipv6(ip):
                        with st.spinner(f"Erstelle AAAA-Eintrag für '{current_domain}'..."):
                            cloudflare.add_dns_record(zone['id'], 'AAAA', current_domain, ip)
                            st.success(f"AAAA-Eintrag für '{current_domain}' erstellt.")
            except Exception as e:
                st.error(f"Fehler beim Erstellen des DNS-Eintrags für {current_domain}: {str(e)}")