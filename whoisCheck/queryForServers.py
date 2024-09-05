import socket
import re
from codecs import encode
import csv

EXCEPTIONS = {
    ".ac.uk": "whois.ja.net",
    ".ps": "whois.pnina.ps",
    ".buzz": "whois.nic.buzz",
    ".moe": "whois.nic.moe",
    "example.com": "whois.verisign-grs.com"
}


def whois_query(domain, server="", previous=None, rfc3490=True, never_cut=False, with_server_list=False,
                server_list=None):
    previous = previous or []
    server_list = server_list or []

    if rfc3490:
        domain = encode(domain, "idna").decode("ascii")

    if len(previous) == 0 and server == "":
        is_exception = False
        for exception, exc_serv in EXCEPTIONS.items():
            if domain.endswith(exception):
                is_exception = True
                target_server = exc_serv
                break
        if not is_exception:
            target_server = get_root_server(domain)
    else:
        target_server = server

    if target_server == "whois.jprs.jp":
        request_domain = f"{domain}/e"
    elif domain.endswith(".de") and (target_server == "whois.denic.de" or target_server == "de.whois-servers.net"):
        request_domain = f"-T dn,ace {domain}"
    elif target_server == "whois.verisign-grs.com":
        request_domain = f"={domain}"
    else:
        request_domain = domain

    response = whois_request(request_domain, target_server)

    if never_cut:
        new_list = [response] + previous

    if target_server == "whois.verisign-grs.com":
        for record in response.split("\n\n"):
            if re.search(f"Domain Name: {domain.upper()}\n", record):
                response = record
                break

    if not never_cut:
        new_list = [response] + previous

    server_list.append(target_server)

    for line in [x.strip() for x in response.splitlines()]:
        match = re.match("(refer|whois server|referral url|whois server|registrar whois):\s*([^\s]+\.[^\s]+)", line,
                         re.IGNORECASE)
        if match is not None:
            referral_server = match.group(2)
            if referral_server != server and "://" not in referral_server:
                return whois_query(domain, referral_server, new_list, server_list=server_list,
                                   with_server_list=with_server_list)

    if with_server_list:
        return (new_list, server_list)
    else:
        return new_list


def get_root_server(domain):
    data = whois_request(domain, "whois.iana.org")
    for line in [x.strip() for x in data.splitlines()]:
        match = re.match("refer:\s*([^\s]+)", line)
        if match is None:
            continue
        return match.group(1)
    raise Exception("No root WHOIS server found for domain.")


def whois_request(domain, server, port=43):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((server, port))
    sock.send((f"{domain}\r\n").encode("utf-8"))
    buff = b""
    while True:
        data = sock.recv(1024)
        if len(data) == 0:
            break
        buff += data
    sock.close()
    return buff.decode("utf-8")


def parse_whois_response(response):
    data = {}
    patterns = {
        "Domain Name": re.compile(r"Domain Name:\s?(.+)"),
        "Registry Domain ID": re.compile(r"Registry Domain ID:\s?(.+)"),
        "Registrar WHOIS Server": re.compile(r"Registrar WHOIS Server:\s?(.+)"),
        "Updated Date": re.compile(r"Updated Date:\s?(.+)"),
        "Creation Date": re.compile(r"Creation Date:\s?(.+)"),
        "Registry Expiry Date": re.compile(r"Registry Expiry Date:\s?(.+)"),
        "Registrar": re.compile(r"Registrar:\s?(.+)"),
        "Registrar IANA ID": re.compile(r"Registrar IANA ID:\s?(.+)"),
        "Domain Status": re.compile(r"Domain Status:\s?(.+)"),
        "Name Server": re.compile(r"Name Server:\s?(.+)"),
        "DNSSEC": re.compile(r"DNSSEC:\s?(.+)")
    }

    for key, pattern in patterns.items():
        matches = pattern.findall(response)
        if matches:
            data[key] = matches if key == "Name Server" else matches[0]

    return data


def save_to_csv(domain_info, filename="whois_data.csv"):
    with open(filename, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        headers = [
            "Domain", "WHOIS Server", "Domain Name", "Registry Domain ID", "Registrar WHOIS Server",
            "Updated Date", "Creation Date", "Registry Expiry Date", "Registrar", "Registrar IANA ID",
            "Domain Status", "DNSSEC",
            "Name Server 1", "Name Server 2", "Name Server 3", "Name Server 4", "Name Server 5"
        ]
        writer.writerow(headers)

        for info in domain_info:
            domain = info['domain']
            for response, server in zip(info['data'], info['servers']):
                parsed_data = parse_whois_response(response)
                name_servers = parsed_data.get("Name Server", [])
                name_servers = name_servers if isinstance(name_servers, list) else [name_servers]
                row = [
                    domain,
                    server,
                    parsed_data.get("Domain Name", ""),
                    parsed_data.get("Registry Domain ID", ""),
                    parsed_data.get("Registrar WHOIS Server", ""),
                    parsed_data.get("Updated Date", ""),
                    parsed_data.get("Creation Date", ""),
                    parsed_data.get("Registry Expiry Date", ""),
                    parsed_data.get("Registrar", ""),
                    parsed_data.get("Registrar IANA ID", ""),
                    parsed_data.get("Domain Status", ""),
                    parsed_data.get("DNSSEC", "")
                ] + name_servers[:5] + [""] * (5 - len(name_servers[:5]))
                writer.writerow(row)


def get_whois_for_domains(domains):
    domain_info = []
    for domain in domains:
        whois_data = whois_query(domain, with_server_list=True)
        domain_info.append({
            'domain': domain,
            'data': whois_data[0],
            'servers': whois_data[1]
        })
    return domain_info


# run it
domains = [
    "example.com",
    "google.com",
    "openai.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "facebook.com",
    "netflix.com",
    "twitter.com",
    "linkedin.com",
    "github.com",
    "stackoverflow.com",
    "wikipedia.org",
    "yahoo.com",
    "bing.com",
    "reddit.com",
    "medium.com",
    "spotify.com",
    "zoom.us",
    "adobe.com"
]
domain_info = get_whois_for_domains(domains)
save_to_csv(domain_info)
