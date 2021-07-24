# malicious_page_checker
This tool checks for malicious external URLs that are present on a website specified by the user. It accesses the website's static and dynamic HTML code, scans it for links, and retrieves information from VirusTotal about whether these links are potentially harmful. 

Usage Instructions:
1. Clone this repo.
2. Run the command "pip install -r requirements.txt".
3. Make a VirusTotal account if you don't already have one at virustotal.com, and add your API key in the API_KEY variable in website_checker.py.
4. Run the command "python3 website_checker.py [website-of-your-choice]".
Example: python3 website_checker.py https://www.freestuff.com/ 