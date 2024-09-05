import mysql.connector
import requests
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from concurrent.futures import ThreadPoolExecutor
import time
import socket
import re
from codecs import encode
import logging
from colorlog import ColoredFormatter

logger = logging.getLogger('DomainLogger')
logger.setLevel(logging.DEBUG)


formatter = ColoredFormatter(
    "%(log_color)s%(levelname)s: %(message)s",
    log_colors={
        'DEBUG': 'white',
        'INFO': 'green',
        'WARNING': 'yellow',
        'ERROR': 'red',
        'CRITICAL': 'bold_red',
    }
)
handler = logging.StreamHandler()
handler.setFormatter(formatter)
logger.addHandler(handler)

EXCEPTIONS = {
    ".ac.uk": "whois.ja.net",
    ".ps": "whois.pnina.ps",
    ".buzz": "whois.nic.buzz",
    ".moe": "whois.nic.moe",
    ".com.tr": "whois.nic.tr",
    "example.com": "whois.verisign-grs.com"
}

def connect_to_database(host, user, password, database):
    print("Connecting to database...")
    conn = mysql.connector.connect(
        host=host,
        user=user,
        password=password,
        database=database
    )
    print("Database connection is successful.")
    return conn

def create_or_verify_domain_status_table(cursor):
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS domain_status (
        id INT AUTO_INCREMENT PRIMARY KEY,
        domain VARCHAR(255) NOT NULL UNIQUE,
        protokol VARCHAR(10) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

def fetch_domain_with_null_status(cursor, limit=10):
    cursor.execute("SELECT id, domain FROM auction_2024 WHERE status IS NULL LIMIT %s", (limit,))
    return cursor.fetchall()

def check_domain_alive(session, domain):
    protocols = ['http', 'https']
    alive_protocols = []

    for protocol in protocols:
        url = f"{protocol}://{domain}"
        try:
            response = session.get(url, timeout=5)
            if response.status_code == 200:
                logger.info(f"{protocol.upper()} check is successful: {domain}")
                alive_protocols.append(protocol)
                break
            else:
                logger.warning(f"{protocol.upper()} check is not successful: {domain}, Status Code: {response.status_code}")
        except requests.exceptions.RequestException as e:
            logger.error(f"{protocol.upper()} check is not successful: {domain}, Error: {e}")

    return alive_protocols

def update_domain_status(cursor, domain_id, status):
    cursor.execute("UPDATE auction_2024 SET status = %s WHERE id = %s", (status, domain_id))

def insert_alive_domain(cursor, domain, protocols):
    cursor.executemany(
        "INSERT INTO domain_status (domain, protokol) VALUES (%s, %s) ON DUPLICATE KEY UPDATE protokol = VALUES(protokol)",
        [(domain, protocol) for protocol in protocols]
    )

def send_email(inactive_sites, email_address, email_password, email_to):
    if inactive_sites:
        message = MIMEMultipart()
        message['From'] = email_address
        message['To'] = email_to
        message['Subject'] = "Pasif Siteler Bildirimi"

        body = "Aşağıdaki siteler pasif durumda:\n\n" + "\n".join(inactive_sites)
        message.attach(MIMEText(body, 'plain'))

        try:
            with smtplib.SMTP_SSL('smtp.yandex.com.tr', 465) as server:
                server.login(email_address, email_password)
                server.sendmail(email_address, email_to, message.as_string())
            logger.info("Inactive sites are sent by mail.")
        except Exception as e:
            logger.error(f"There is an error sending mail: {e}")
    else:
        logger.info("All sites are active, no email sent.")

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

    response = whois_request(domain, target_server)

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

def process_domain(domain_record, cursor, session):
    domain_id, domain = domain_record
    logger.info(f"Domain {domain} is chosen.")

    alive_protocols = check_domain_alive(session, domain)

    if alive_protocols:
        insert_alive_domain(cursor, domain, alive_protocols)
        update_domain_status(cursor, domain_id, 2)
    else:
        whois_data = whois_query(domain, with_server_list=False)
        logger.warning(f"Domain {domain} is not alive. WHOIS info: {whois_data[0]}")
        update_domain_status(cursor, domain_id, 0)
        return domain

def process_domains():
    host = ''
    user = ''
    password = ''
    database = ''
    email_address = ""
    email_password = ""
    email_to = ""

    conn = connect_to_database(host, user, password, database)
    cursor = conn.cursor()

    create_or_verify_domain_status_table(cursor)

    inactive_sites = []

    with requests.Session() as session:
        while True:
            domain_records = fetch_domain_with_null_status(cursor)

            if not domain_records:
                logger.info("All domains are checked.")
                break

            with ThreadPoolExecutor(max_workers=5) as executor:
                results = executor.map(lambda record: process_domain(record, cursor, session), domain_records)

            inactive_sites.extend(filter(None, results))

            conn.commit()
            time.sleep(1)

    if inactive_sites:
        send_email(inactive_sites, email_address, email_password, email_to)

    cursor.close()
    conn.close()

process_domains()
