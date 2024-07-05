import streamlit as st
from ransomware_analysis import ransomware_analysis_ui
from phishing_detection import phishing_detection_ui
from ssl_analysis import ssl_analysis_ui

# Main UI
st.title("Cybersecurity Tools")

# Sidebar for navigation
st.sidebar.title("Navigation")
option = st.sidebar.radio("Go to", ["Ransomware Analysis","SSL Analysis", "Phishing Detection"])

if option == "Ransomware Analysis":
    ransomware_analysis_ui()
elif option == "SSL Analysis":
    ssl_analysis_ui()
elif option == "Phishing Detection":
    phishing_detection_ui()


# Mitigation steps
st.markdown("""
## Mitigation Steps:
1. **Backup Your Data**: Regularly backup your important data to an external hard drive or a cloud service.
2. **Keep Software Updated**: Ensure your operating system and software applications are up-to-date with the latest security patches.
3. **Use Antivirus Software**: Install and maintain antivirus software to detect and remove malicious software.
4. **Avoid Suspicious Links and Attachments**: Be cautious of emails and messages from unknown sources, especially those with attachments or links.
5. **Enable Ransomware Protection**: Some antivirus software offers specific ransomware protection features.
6. **Educate Yourself and Others**: Stay informed about the latest cybersecurity threats and educate others to recognize and avoid them.
""")
