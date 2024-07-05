import streamlit as st
import requests
import base64
from dotenv import load_dotenv
import os
load_dotenv()

# Function to check if a URL is a phishing URL using VirusTotal API
def check_phishing_url(url):
    try:
       
        api_key=os.getenv('API_KEY')

        # Encode the URL in base64 format
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        # Submit the URL for scanning
        submit_url = 'https://www.virustotal.com/api/v3/urls'
        headers = {'x-apikey': api_key}
        data = {'url': url}
        response = requests.post(submit_url, headers=headers, data=data)
        response.raise_for_status()

        # Get the scan ID from the response
        scan_id = response.json()['data']['id']

        # Fetch the analysis report
        report_url = f'https://www.virustotal.com/api/v3/analyses/{scan_id}'
        report_response = requests.get(report_url, headers=headers)
        report_response.raise_for_status()
        report_data = report_response.json()

        # Check if the response is in JSON format and contains analysis stats
        if 'data' in report_data and 'attributes' in report_data['data']:
            attributes = report_data['data']['attributes']
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            if last_analysis_stats.get('malicious', 0) > 0:
                return "Phishing Detected"
            else:
                return "No Phishing Detected"
        else:
            st.error("Error: Unexpected response format.")
            return "Unknown"
    except requests.exceptions.RequestException as e:
        st.error(f"Error checking URL: {e}")
        return "Unknown"

def phishing_detection_ui():
    st.header("Phishing Detection")

    # Input field for URL to check
    url_to_check = st.text_input("Enter URL to Check for Phishing", "")

    if st.button("Check URL"):
        if url_to_check:
            status = check_phishing_url(url_to_check)
            st.write(f"URL Status: {status}")
        else:
            st.error("Please enter a valid URL.")







# Call the function to render the UI
phishing_detection_ui()
