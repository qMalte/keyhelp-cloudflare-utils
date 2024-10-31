import streamlit as st
import pandas as pd
import numpy as np
from cloudflare import CloudflareAPI
from keyhelp import KeyHelpAPI
import time
from misc import *

params = st.query_params

with st.form("parameter_form"):
    keyhelp_host_param = params.get("keyhelp_host", "https://demo.keyhelp.eu")
    keyhelp_api_key_param = params.get("keyhelp_api_key", "")
    cloudflare_api_key_param = params.get("cloudflare_api_key", "")
    dmarc_email_param = params.get("dmarc_email", "postmaster@example.com")

st.title('KeyHelp / Cloudflare - Bridge')

# Input-Field for KeyHelp API Key
keyhelpHost = st.text_input('KeyHelp Host', keyhelp_host_param)
keyhelp_api_key = st.text_input('KeyHelp API Key', keyhelp_api_key_param)
cloudflare_api_key = st.text_input('Cloudflare API Key', cloudflare_api_key_param)
dmarc_email = st.text_input('Postmaster E-Mail (DMARC-Reports)', dmarc_email_param)

if st.button('Übernahme der Parameter in die URL'):
    st.query_params["keyhelp_host"] = keyhelpHost
    st.query_params["keyhelp_api_key"] = keyhelp_api_key
    st.query_params["cloudflare_api_key"] = cloudflare_api_key
    st.query_params["dmarc_email"] = dmarc_email
    st.rerun()

# Initialize CloudflareAPI
cloudflare = CloudflareAPI(cloudflare_api_key)

# Initialize KeyHelpAPI
keyhelp = KeyHelpAPI(keyhelpHost, keyhelp_api_key)

# Action Buttons
# with st.spinner('Operation in progress...'):

def main():

    zones = fetch_cloudflare_zones(cloudflare)
    domains = fetch_keyhelp_domains(keyhelp)
    system = fetch_server_info(keyhelp)

    # System properties
    hostname = system['meta']['hostname']
    ipAdresses = filter_ip_addresses(system)

    domain_names = [];

    for domain in domains:
        # Check if domain is already in Cloudflare
        domain_name = domain['domain']
        zone = next((z for z in zones['result'] if z['name'] == domain_name), None)
        if not zone:
            continue

        domain_names.append(domain_name)

    selected_domains = st.multiselect('Wähle eine Domain', domain_names)

    if st.button('Update der DNS-Einträge (E-Mail)'):
        if (len(selected_domains) == 0):
            st.error('Bitte wähle mindestens eine Domain aus.')
        for domain_name in selected_domains:
            update_mx_record(cloudflare, domain_name, hostname)
            update_spf_record(cloudflare, domain_name, ipAdresses)
            update_dkim_record(cloudflare, keyhelp, domain_name)
            update_dmarc_record(cloudflare, domain_name, dmarc_email)

    if st.button('Update der DNS-Einträge (WebSpace)'):
        if (len(selected_domains) == 0):
            st.error('Bitte wähle mindestens eine Domain aus.')
        for domain_name in selected_domains:
            update_web_records(cloudflare, keyhelp, domain_name, ipAdresses)


# Run the main function
if __name__ == "__main__":
    if (keyhelp_api_key == "" or cloudflare_api_key == "" or keyhelpHost == ""):
        st.warning('Bitte fülle die Felder aus.')
    else:
        main()