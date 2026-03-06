import re
import socket
import json
import ipaddress
import threading
import time
from urllib.request import urlopen
from urllib.parse import urlparse
from xml.sax.saxutils import escape
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipwhois import IPWhois
from tqdm import tqdm

INPUT_FILE = "urls.txt"
OUTPUT_KML = "geolocations.kml"
FAILURE_LOG = "failures.log"

MAX_WORKERS = 30
DNS_RATE_LIMIT = 40
API_RATE_LIMIT = 40

dns_last_call = 0
api_last_call = 0

dns_lock = threading.Lock()
api_lock = threading.Lock()

dns_cache = {}
geo_cache = {}

kml_results = []
failures = []

seen_ips = set()

ipv4_re = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

# ----------------------------
# Rate limiters
# ----------------------------

def throttle_dns():
    global dns_last_call
    with dns_lock:
        delay = 1.0 / DNS_RATE_LIMIT
        now = time.time()
        elapsed = now - dns_last_call
        if elapsed < delay:
            time.sleep(delay - elapsed)
        dns_last_call = time.time()


def throttle_api():
    global api_last_call
    with api_lock:
        delay = 1.0 / API_RATE_LIMIT
        now = time.time()
        elapsed = now - api_last_call
        if elapsed < delay:
            time.sleep(delay - elapsed)
        api_last_call = time.time()


# ----------------------------
# URL parsing
# ----------------------------

def extract_host(url):

    try:

        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        parsed = urlparse(url)

        return parsed.hostname

    except:
        return None


# ----------------------------
# Detect type
# ----------------------------

def detect_type(host):

    try:
        if ipv4_re.match(host):
            return "ipv4"

        ipaddress.IPv6Address(host)

        return "ipv6"

    except:
        return "domain"


# ----------------------------
# DNS resolver
# ----------------------------

def resolve_domain(domain):

    if domain in dns_cache:
        return dns_cache[domain], None

    try:

        throttle_dns()

        infos = socket.getaddrinfo(domain, None)

        ips = list({info[4][0] for info in infos})

        dns_cache[domain] = ips

        return ips, None

    except Exception as e:

        return [], str(e)


# ----------------------------
# Geolocation
# ----------------------------

def geolocate_ip(ip):

    if ip in geo_cache:
        return geo_cache[ip]

    lat = None
    lon = None
    asn = "Unknown"

    # Try RDAP first
    try:

        obj = IPWhois(ip)

        res = obj.lookup_rdap()

        asn = res.get("asn_description", "Unknown")

    except:
        pass

    # Fallback to ip-api for coordinates

    try:

        throttle_api()

        with urlopen(f"http://ip-api.com/json/{ip}") as u:

            data = json.loads(u.read().decode())

            if data.get("status") == "success":

                lat = data.get("lat")
                lon = data.get("lon")

                if "as" in data:
                    asn = data["as"]

    except:
        pass

    if lat and lon:

        geo_cache[ip] = (lat, lon, asn)

        return lat, lon, asn

    return None


# ----------------------------
# Normalize XML
# ----------------------------

def safe(text):

    if not text:
        return ""

    return escape(str(text))


# ----------------------------
# KML writer
# ----------------------------

def write_kml():

    with open(OUTPUT_KML, "w", encoding="utf-8") as kml:

        kml.write('<?xml version="1.0" encoding="UTF-8"?>\n')

        kml.write('<kml xmlns="http://www.opengis.net/kml/2.2">\n')

        kml.write("<Document>\n")

        for ip, url, lat, lon, asn in kml_results:

            ip_s = safe(ip)

            url_s = safe(url)

            asn_s = safe(asn)

            kml.write("  <Placemark>\n")

            kml.write(f"    <name>{ip_s}</name>\n")

            kml.write(
                f"    <description><![CDATA[URL: {url_s} | ASN: {asn_s}]]></description>\n"
            )

            kml.write("    <Point>\n")

            kml.write(f"      <coordinates>{lon},{lat},0</coordinates>\n")

            kml.write("    </Point>\n")

            kml.write("  </Placemark>\n")

        kml.write("</Document>\n")

        kml.write("</kml>\n")


# ----------------------------
# Processing function
# ----------------------------

def process_line(line):

    host = extract_host(line)

    if not host:

        failures.append(("PARSE_FAIL", line))

        return

    host_type = detect_type(host)

    if host_type in ("ipv4", "ipv6"):

        ips = [host]

    else:

        ips, err = resolve_domain(host)

        if err:

            failures.append(("DNS_FAIL", host))

            return

    for ip in ips:

        if ip in seen_ips:
            continue

        seen_ips.add(ip)

        geo = geolocate_ip(ip)

        if geo:

            lat, lon, asn = geo

            kml_results.append((ip, line, lat, lon, asn))

        else:

            failures.append(("GEO_FAIL", ip))


# ----------------------------
# Main
# ----------------------------

def main():

    with open(INPUT_FILE, "r", encoding="utf-8", errors="ignore") as f:

        lines = [line.strip() for line in f if line.strip()]

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:

        futures = [executor.submit(process_line, line) for line in lines]

        for _ in tqdm(as_completed(futures), total=len(futures), desc="Processing"):

            pass

    write_kml()

    with open(FAILURE_LOG, "w") as flog:

        for f in failures:

            flog.write(f"{f}\n")

    print(
        f"\nFinished: {len(kml_results)} mapped | {len(failures)} failures"
    )


if __name__ == "__main__":

    main()