"""Sanity evaluation on SYNTHETIC data (no real DGA feed available offline). Not a substitute for DGArchive/Tranco."""
import random
import string
import hashlib
import base64
import sys

sys.path.insert(0, ".")
from sentinel_dga.detector import DGADetector  # noqa: E402

BENIGN = """google youtube facebook amazon twitter instagram linkedin microsoft netflix spotify wikipedia reddit github
stackoverflow cloudflare dropbox salesforce paypal alibaba flipkart hotstar whatsapp telegram discord microsoftonline
office365 outlook stackexchange wordpress shopify squarespace godaddy namecheap nytimes theguardian washingtonpost
timesofindia hindustantimes ndtv indiatoday economictimes moneycontrol zerodha upstox phonepe bhimupi irctc uidai
digilocker incometax sbionline hdfcbank icicibank axisbank kotak paytm zomato swiggy bigbasket myntra ajio nykaa
makemytrip goibibo cleartrip redbus ola uber airbnb booking tripadvisor expedia skyscanner coursera udemy edx khanacademy
duolingo medium quora pinterest tumblr twitch tiktok snapchat weibo baidu tencent alibabacloud aliexpress ebay walmart
target bestbuy homedepot ikea lenovo samsung huawei xiaomi oneplus mozilla ubuntu debian fedora archlinux kernel python
nodejs golang rust-lang postgresql mongodb elastic kubernetes docker jenkins gitlab bitbucket atlassian jetbrains
mathworks nvidia amd intel qualcomm broadcom cisco juniper paloaltonetworks fortinet crowdstrike okta twilio sendgrid
mailchimp hubspot zendesk intercom notion figma canva adobe autodesk unity unrealengine steampowered epicgames riotgames
supercell rovio spotifycdn bbc cnn aljazeera reuters bloomberg forbes techcrunch theverge wired arstechnica engadget
""".split()


def rand_letters(rng):
    return "".join(rng.choices(string.ascii_lowercase, k=rng.randint(10, 20)))


def rand_alnum(rng):
    return "".join(rng.choices(string.ascii_lowercase + string.digits, k=rng.randint(10, 18)))


def md5_hex(rng):
    return hashlib.md5(str(rng.random()).encode()).hexdigest()[: rng.choice([12, 16, 20, 32])]


def b32(rng):
    return base64.b32encode(rng.randbytes(rng.randint(7, 10))).decode().lower().rstrip("=")


def consonant_heavy(rng):
    return "".join(rng.choices("bcdfghjklmnpqrstvwxz", weights=[1] * 20, k=rng.randint(9, 15)) +
                   rng.choices("aeiou", k=rng.randint(0, 2)))


GENS = {"random letters": rand_letters, "random alnum": rand_alnum, "md5 hex": md5_hex, "base32": b32,
        "consonant heavy": consonant_heavy}


def run(det_factory, n=400, seed=7):
    rng = random.Random(seed)
    for name, gen in GENS.items():
        det = det_factory()
        hits = sum(bool(det.process_dns({"domain": gen(rng) + ".com", "src_ip": f"10.{i // 250}.{i % 250}.1"})) for i in range(n))
        print(f"  {name:<16} single-name detection (1 query/host): {hits / n:6.1%}")
    fp = sum(bool(det_factory().process_dns({"domain": w + rng.choice([".com", ".net", ".in", ".org"]), "src_ip": "10.0.0.5"}))
             for w in BENIGN)
    print(f"  benign brand names flagged: {fp}/{len(BENIGN)} = {fp / len(BENIGN):.1%}")
    det = det_factory(); alerts = []
    for i in range(12):
        a = det.process_dns({"domain": rand_letters(rng) + ".net", "src_ip": "10.0.0.99"})
        if a: alerts.append(a)
    print(f"  one infected host, 12 DGA queries: {len(alerts)} alerts, "
          f"severities {[a['severity'] for a in alerts]}")


if __name__ == "__main__":
    print("heuristic detector, synthetic data:")
    run(DGADetector)
