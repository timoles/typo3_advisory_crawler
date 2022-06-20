import requests
import re
from bs4 import BeautifulSoup
import json
from pkg_resources import parse_version
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


ctx = {
    'base_url': 'https://typo3.org',
    'extensions_advisories_page': '/help/security-advisories/typo3-extensions/',
    'core_advisories_page': '/help/security-advisories/typo3-cms',
    'proxies': {},
    'verify': False
}


def get_next_page_link_from_advisory(soup):
    '''
    This function will get a link to the next advisory page
        soup: The soup object from which the link is extracted
        returns: The relative link to the next page
    '''
    # Get the "li.next.page-item" element from response text and extract URL
    for next_item_list in soup.find_all('li', {"class": "next page-item"}):
        next_page_link = next_item_list.find_all('a')
        next_page_link_href = next_page_link[0].get('href')

        return next_page_link_href

def extract_advisory_links(soup, result_list):
    '''
    This function extracts all relative links to advisories from the given soup object
        soup: The soup object from which the links are extracted
        result_list: The list to which the links are added
        modified result_list: The list of relative links to advisories
    '''
    # All links to advisories are within buttons. Get all buttons and extract href
    advisory_links = soup.find_all('a', {"class": "btn"})
    for advisory_link in advisory_links:
        advisory_link_href = advisory_link.get('href')
        # Check if the link points to a security advisory
        if advisory_link_href:
            if advisory_link_href.startswith('/security/advisory/'):
                result_list.append(advisory_link_href)
    
def request_to_soup(ctx, relative_path):
    '''
    This function will request the given URL and return the soup object
        relative_path: The relative path to request
        returns: The soup object
    '''
    request_url = ctx['base_url'] + relative_path
    print("Requesting: " + request_url)
    response = requests.get(request_url, timeout=6, proxies=ctx['proxies'], verify=ctx['verify'])
    soup = BeautifulSoup(response.text, 'html.parser')
    return soup
    
def crawl_advisory_page(ctx, path, result_list):
    '''
    This function will crawl the advisory page and extract all relative links to advisories
        ctx: The context object
        returns: The list of relative links to advisories
    '''
    current_page = 1
    while path :
        print('Requesting page: ' + str(current_page))
        soup = request_to_soup(ctx, path)
        extract_advisory_links(soup, result_list)

        path = get_next_page_link_from_advisory(soup)
        current_page += 1

def get_core_advisories(ctx):
    '''
    Starts the crawl for core advisories
        ctx: The context object
        returns: A list of parsed advisories. Each advisory is a dictionary with metadata
    '''
    print('Starting crawl for core advisories')
    core_advisory_links = []
    path = ctx['core_advisories_page']
    crawl_advisory_page(ctx, path, core_advisory_links)
    return get_parsed_advisories(ctx, core_advisory_links)

def get_extension_advisories(ctx):
    '''
    Starts the crawl for extension advisories
        ctx: The context object
        returns: A list of parsed advisories. Each advisory is a dictionary with metadata
    '''
    print('Starting crawl for extension advisories')
    extension_advisory_links = []
    path = ctx['extensions_advisories_page']
    crawl_advisory_page(ctx, path, extension_advisory_links)
    return get_parsed_advisories(ctx, extension_advisory_links)

def parse_advisory(ctx, soup, relative_link):
    '''
    Does the actual advisory parsing and returns a dictionary with metadata
        ctx: The context object
        soup: The soup object from which the metadata is extracted
        relative_link: The relative link to the advisory
    '''


    advisory_data = {}

    # For new versions of the advisory:
    # Advisory metadata is stored within unordered list 'alert-warning'
    # The ul contains li elements with the different metadata key-value pairs
    # Get all elments and pass them to the dict
    for metadata_list in soup.find_all('ul', {"class": "alert-warning"}):
        for list_element in metadata_list.find_all('li'):
            split_string = list_element.text.split(':', maxsplit=1)
            advisory_data[split_string[0].strip()] = split_string[1].strip()
    
    # We got an old advisory which requires different parsing
    if advisory_data == {}:
        for div_element in soup.find_all('div', {"class": "news-text-wrap"}):
            for metadata_value in div_element:
                metadata_soup = BeautifulSoup(str(metadata_value), 'html.parser')
                metadata_key = metadata_soup.find_all('strong')
                if metadata_key:
                    key = metadata_key[0].text.strip().strip(':')
                    value = metadata_soup.text.replace(key, '').replace(':', '', 1).strip()

                    advisory_data[key] = value
    
    # Add advisory link and title to metadata (extracted from URl)
    advisory_data['Advisory URL'] = ctx['base_url'] + relative_link
    advisory_data['Title'] = relative_link.split('/')[-1].upper()
    try:
        advisory_data['Affected Versions'] = parse_vulnerable_versions(advisory_data['Affected Versions'])
    except KeyError: 
        advisory_data['Affected Versions'] = []
    return advisory_data

def get_parsed_advisories(ctx, relative_links_to_advisories):
    '''
    Goes through list of relative links to advisories and parses each one
        ctx: The context object
        relative_links_to_advisories: The list of relative links to advisories
        returns: A list of parsed advisories. Each advisory is a dictionary with metadata
    '''
    advisories_metadata = []
    for relative_link in relative_links_to_advisories:
        soup = request_to_soup(ctx, relative_link)
        advisories_metadata.append(parse_advisory(ctx, soup, relative_link))
    return advisories_metadata

def parse_vulnerable_versions(version_in):
    '''
    Parses the vulnerable versions string and returns a list of versions that are vulnerable
        version_in: The string to parse
        returns: A list of versions
        The return list contains dictionaries with the following keys:
            'low': The minimum vulnerable version
            'high': The maximum vulnerable version
    '''
    affected_version_metadata = []
    affected_version_in = version_in.lower()
    affected_version_in = affected_version_in.replace("and below", " - 0.0.0")
    affected_version_in = affected_version_in.replace("below of", " - 0.0.0")
    affected_version_in = affected_version_in.replace("and all versions below", " - 0.0.0")
    affected_version_in = affected_version_in.replace("to", "-")
    affected_version_in = affected_version_in.replace("up", "")
    affected_version_in = affected_version_in.replace(".x", ".9")
    affected_version_in = affected_version_in.replace("development releases of the", "")
    affected_version_in = affected_version_in.replace("branch", "")
    affected_version_in = affected_version_in.replace("\xa0", "")
    affected_version_in = affected_version_in.replace("versions from", "")
    affected_version_in = affected_version_in.replace("versions", "")
    affected_version_in = affected_version_in.replace("version", "")
    affected_version_in = affected_version_in.replace("all", "")
    affected_version_in = affected_version_in.replace("powermail", "")
    affected_version_in = affected_version_in.replace("yag", "")
    affected_version_in = affected_version_in.replace("pt_extbase", "")
    affected_version_in = affected_version_in.replace("elts", "")
    affected_version_in = affected_version_in.replace(":", "")
    affected_version_in = affected_version_in.replace(" ", "")
    affected_version_in = affected_version_in.replace(";", ",")
    affected_version_in = affected_version_in.replace('and', ',')
    if re.match('^(?![0-9]|-|,)', affected_version_in):
        print('Unexpected characters in version, please check')

    for version in affected_version_in.split(','):
        version_low = parse_version('0')
        version_high = parse_version('99')
        version_split = version.split('-')
        if len(version_split) == 1:
            version_high = parse_version(version_split[0])
        elif len(version_split) ==  2:
            version_low = parse_version(version.split('-')[0].strip())
            version_high = parse_version(version.split('-')[1].strip())
        else:
            print('Got wierd version response, please check.')
        if version_low < version_high:
            # we transform the version back to a string, as otherwise we need to modify the json serialization.
            # TODO fix this 
            affected_version_metadata.append({'low': str(version_low), 'high': str(version_high)}) # Carefull we cast back to string!! TODO don't do this
        else:
            affected_version_metadata.append({'low': str(version_high), 'high': str(version_low)}) # Carefull we cast back to string!! TODO don't do this
    return affected_version_metadata


x = get_core_advisories(ctx)
with open('core_advisories.json', 'w', encoding ='utf8') as json_file:
    json.dump(x, json_file)
y = get_extension_advisories(ctx)
with open('ext_advisories.json', 'w', encoding ='utf8') as json_file:
    json.dump(y, json_file)

print('done')
#
#database = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'typo3scan.db')
#conn = sqlite3.connect(database)
#c = conn.cursor()
#                # Add vulnerability details to database
#                for ext_vuln in vulnerabilities:
#                    c.execute('SELECT * FROM extension_vulns WHERE advisory=? AND extensionkey=? AND vulnerability=? AND affected_version_max=? AND affected_version_min=?', (ext_vuln[0], ext_vuln[1], ext_vuln[2], ext_vuln[3], ext_vuln[4],))
#                    data = c.fetchall()
#                    if not data:
#                        update_counter+=1
#                        c.execute('INSERT INTO extension_vulns VALUES (?,?,?,?,?)', (ext_vuln[0], ext_vuln[1], ext_vuln[2], ext_vuln[3], ext_vuln[4]))
#                        conn.commit()
#                    else:
#                        if update_counter == 0:
#                            print('[!] Already up-to-date.\n')
#                        else:
#                            print(' \u2514 Done. Added {} new advisories to database.\n'.format(update_counter))
#                        return True
