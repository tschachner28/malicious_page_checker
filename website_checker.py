import argparse
from selenium import webdriver
import sys, os
import vt

def check_for_malicious_links(input_url):
    sys.path.append(os.path.abspath('/chromedriver.exe'))

    # Find all the links (both those that are statically loaded and those that are dynamically loaded) to external pages
    external_links = []
    driver = webdriver.Chrome(executable_path=sys.path[0] + "/chromedriver")
    driver.get(input_url)
    driver.implicitly_wait(10)
    source = driver.execute_script("return document.body.innerHTML;")
    driver.quit()
    while source.find('href') != -1:
        link_ind = source.find('href')+6
        truncated_source = source[link_ind:]
        close_quote_ind = link_ind + truncated_source.find('"')
        if source[link_ind:link_ind+4] != 'http': #exclude internal links
            source = source[close_quote_ind+1:]
            continue
        else: # external link
            current_link = source[link_ind:close_quote_ind]
            external_links.append(current_link)
            source = source[close_quote_ind+1:]

    # Include the potentially malicious links and information about them, found using VirusTotal, in an output file
    output_file = open('potentially_malicious_urls.txt', "w")

    # Query the URLS on VirusTotal
    API_KEY = '' # TODO: add your API key here
    client = vt.Client(API_KEY)
    output_file.write("Input URL: " + input_url + "\n")
    urls_not_found = 0
    no_malicious_urls = True

    for link in external_links:
        try:
            url_id = vt.url_id(link)
            url = client.get_object("/urls/{}", url_id)
        except:
            urls_not_found += 1
            continue

        threats = {threat: url.last_analysis_results[threat] for threat in url.last_analysis_results.keys() if url.last_analysis_results[threat]['category'] not in ['harmless', 'undetected']} # key: threat name (string), value: category (string)

        if len(threats) > 0 or url.total_votes['malicious'] > url.total_votes['harmless'] or len(url.threat_names) > 0: # include in potentially harmful sites output file
            no_malicious_urls = False
            output_file.write("External URL: " + link + "\n")

            if len(threats) > 0:
                output_file.write("Threats:\n")
                for threat in threats.keys():
                    output_file.write(threat + ": " + threats[threat] + "\n")
            else:
                output_file.write("Threats: None\n")

            output_file.write("Malicious Votes: " + str(url.total_votes['malicious']) + ", " + "Harmless Votes: " + str(url.total_votes['harmless']) + "\n")

            if len(url.threat_names) > 0:
                output_file.write("Threat Names: " + url.threat_names + "\n")
            else:
                output_file.write("Threat Names: None\n")

            output_file.write("\n")

    if no_malicious_urls:
        output_file.write("No malicious links found.\n")
    output_file.write("Links not found in VirusTotal: " + str(urls_not_found) + "\n")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('url', type=str,
                        help='URL that will be checked for malicious external links')

    args = parser.parse_args()
    
    check_for_malicious_links(args.url)
