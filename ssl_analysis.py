import streamlit as st
import ssl
import socket
from datetime import datetime

def ssl_analysis(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                # Extract relevant certificate information
                issuer = dict(x[0] for x in cert['issuer'])
                subject = dict(x[0] for x in cert['subject'])
                valid_from = datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z")
                valid_until = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                days_left = (valid_until - datetime.now()).days

                return {
                    'valid': True,
                    'issuer': issuer['organizationName'],
                    'subject': subject['commonName'],
                    'valid_from': valid_from.strftime('%Y-%m-%d'),
                    'valid_until': valid_until.strftime('%Y-%m-%d'),
                    'days_left': days_left
                }
    except Exception as e:
        return {
            'valid': False,
            'error': str(e)
        }

def ssl_analysis_ui():
    st.header("SSL/TLS Certificate Analysis")

    # Input field for domain name
    domain_name = st.text_input("Enter Domain Name for SSL/TLS Analysis", "")

    if st.button("Analyze SSL/TLS Certificate"):
        if domain_name:
            result = ssl_analysis(domain_name)
            if result['valid']:
                st.success(f"SSL/TLS Certificate for {domain_name} is valid.")
                st.write(f"Issuer: {result['issuer']}")
                st.write(f"Subject: {result['subject']}")
                st.write(f"Valid from: {result['valid_from']}")
                st.write(f"Expires on: {result['valid_until']} (in {result['days_left']} days)")
            else:
                st.error(f"Error analyzing SSL/TLS certificate: {result['error']}")
        else:
            st.error("Please enter a domain name to analyze.")

# Call the function to render the UI
ssl_analysis_ui()
