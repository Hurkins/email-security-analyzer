from email.utils import parseaddr
from email import policy
from email.parser import BytesParser
from publicsuffix2 import get_sld
import re
from collections import  defaultdict
import argparse





class HeaderAnalysis:
    def __init__(self,email):
        self.email = email
        self.From = self.header_parser('From')
        self.reply_to = self.header_parser('Reply-To')
        self.return_path = self.header_parser('Return-Path')

    def header_parser(self, header_name):
        raw_value = self.email.get(header_name)
        if not raw_value:
            return None
        name, email_addr = parseaddr(raw_value)

        if '@' not in email_addr:
            return{
                "Header": header_name,
                "Name": name,
                "email": None,
                "local": None,
                "domain":None
            }
        local, domain = email_addr.split("@",1)
        return{
                "Header": header_name,
                "Name":name,
                "email":email_addr,
                "local":local,
                "domain":domain.lower()
                        }



    def normalizer(self,domain):
        if not domain:
            return None
        return get_sld(domain).lower() # type: ignore

    # compare the normalized domains only
    def check(self,a, b):
        a_dom = self.normalizer(a)
        b_dom = self.normalizer(b)

        if not a_dom or not b_dom:
            return None
        if a_dom == b_dom:
            return 'match'
        return 'no_match'

    def domain_relationship(self,a, b):
        if a is None or b is None:
            return None

        if a.endswith('.' + b):
            return "SUBDOMAIN"
        elif b.endswith('.' + a):
            return "PARENT_DOMAIN"
        return "UNRELATED"

    def check_sender_consistency(self):
        if self.reply_to and self.From:
            raw_a = self.reply_to['domain']
            raw_b = self.From['domain']
            # RAW domain
            if raw_a == raw_b:
                # print("RAW_MATCH → EXACT_MATCH")
                pass
            else:
            # Normalized domains
                normalized = self.check(raw_a, raw_b)

                if normalized == 'no_match':
                    # print(" Domain relationship: HARD_MISMATCH → !MISMATCH domains")
                    pass
                elif normalized == 'match':
                    # domain relationship check
                    related = self.domain_relationship(raw_a, raw_b)
                    # print(f"RELATED_DOMAINS → {related}")


    def parse_spf(self):

        #  Try Authentication-Results

        ar = self.email.get("Authentication-Results", "")
        if ar:
            spf_match = re.search(r'spf=(pass|fail|softfail|neutral|none)', ar, re.I)
            domain_match = re.search(r'smtp\.mailfrom="?([^"\s;]+@[^"\s;]+)"?', ar, re.I)

            if spf_match:
                spf_result = spf_match.group(1).lower()
                spf_domain = None

                if domain_match:
                    spf_domain = domain_match.group(1).split("@")[-1]

                return { "SPF":{
                    "spf_pass": spf_result == "pass",
                    "spf_result": spf_result,
                    "spf_domain": spf_domain,
                    "source": "Authentication-Results"
                    }
                }

        # Fallback: Received-SPF

        rs = self.email.get("Received-SPF") or ""
        if rs:
            spf_match = re.search(r'^(pass|fail|softfail|neutral|none)', rs, re.I)
            domain_match = re.search(r'domain of ([^"\s;]+@[^"\s;]+)', rs, re.I)

            if spf_match:
                spf_result = spf_match.group(1).lower()
                spf_domain = None

                if domain_match:
                    spf_domain = domain_match.group(1).split("@")[-1]

                return { "SPF":{
                    "spf_pass": spf_result == "pass",
                    "spf_result": spf_result,
                    "spf_domain": spf_domain,
                    "source": "Received-SPF"
                }
                }


        #  Nothing found

        return {"SPF":{
            "spf_pass": None,
            "spf_result": None,
            "spf_domain": None,
            "source": None
        }
        }



    # DMARC
    def dmarc(self):
        ar = self.email.get('Authentication-Results') or ""
        if not ar:
            return{
                "dmarc_pass":None,
                "policy":None,
                "from_domain":None,
                "alignment": None,
                "risk": "UNKNOWN"
            }
        results_match = re.search(r'dmarc=(pass|fail)',ar, re.I)
        if not results_match:
            return{
                "dmarc_pass":None,
                "policy": None,
                "from_domain": None,
                "alignment": None,
                "risk": "UNKNOWN"
            }
        dmarc_result = results_match.group(1).lower()

        policy_match = re.search(r'p=(none|quarantine|reject)',ar,re.I)
        policy = policy_match.group(1).lower() if policy_match else "none"

        from_match = re.search(r'header\.from=([\w.-]+)',ar, re.I)
        from_domain = from_match.group(1) if from_match else None

        alignment = "aligned" if dmarc_result == "pass" else "misaligned"

        if dmarc_result == "pass":
            risk = "LOW"
        elif policy == "reject":
            risk = "HIGH"
        elif policy == "quarantine":
            risk = "MEDIUM"
        else:
            risk = "MEDIUM"

        return{ "DMARC":{
            "dmarc_pass": dmarc_result == "pass",
            "policy": policy,
            "from_domain": from_domain,
            "alignment": alignment,
            "risk": risk
        }
        }


    def dkim_result (self):
        ar = self.email.get("Authentication-Results")
        if not ar:
            return {
                "DKIM":[]
            }

        results = {
            "DKIM":[]
        }

        for match in re.finditer(r'dkim=(pass|fail|neutral).*?header\.i=(@?[^"\s;]+)',ar,re.I):
            dkim_result = match.group(1).lower()
            dkim_domain = match.group(2).lstrip("@")

            results["DKIM"].append({
                "state": dkim_result,
                "domain": dkim_domain
            })
        return results

    #"i" counter

    def parse_kv(self, header_value):
        pairs = {}
        for part in re.split(r';\s*', header_value):
            if '=' in part:
                k, v = part.split('=', 1)
                pairs[k.strip()] = v.strip()
        return pairs
    #ARC_DKIM
    def parse_dkim_results_ARC(self, arr_value):
        dkims = []
        patterns = r'dkim=(pass|fail).*?(?:header\.i|header\.d|dkdomain)=@?([^;"\s\)]+)'

        for match in re.finditer(patterns,arr_value,re.I):
            dkims.append({
                "state": match.group(1).lower(),
                "domain": match.group(2),
            })

        return dkims
    # ARC
    def parse_arc(self):
        arc_sets = defaultdict(dict)

        aar_headers = self.email.get_all('ARC-Authentication-Results') or []
        ams_headers = self.email.get_all('ARC-Message-Signature') or []
        seal_headers= self.email.get_all('ARC-Seal') or []

        if not (aar_headers or ams_headers or seal_headers):
            return{
                "arc_present": False,
                "sets": [],
                "chain_valid": False,
                "trust_level": "NONE"
            }
        for aar in aar_headers:
            i_match = re.search(r'i=(\d+)',aar)
            if not i_match:
                continue
            i = int(i_match.group(1))

            arc_sets[i]['aar'] ={
                "spf":re.search(r'spf=(pass|fail|none)',aar,re.I).group(1).lower() if re.search(r'spf=',aar,re.I) else None, #type: ignore
                "smtp_mailfrom":re.search(r'smtp\.mailfrom\s*=\s*"?([^"\s;]+)"?',aar, re.I).group(1) if re.search(r'smtp\.mailfrom=',aar,re.I) else None, #type: ignore
                "dkim":self.parse_dkim_results_ARC(aar),
                "dmarc":re.search(r'dmarc=(pass|fail|none)', aar, re.I).group(1).lower() if re.search(r'dmarc=',aar,re.I) else None, #type: ignore
                "header_from":re.search(r'(?:header\.from|fromdomain)="?([^"\s;]+)"?', aar, re.I).group(1) if re.search(r'(header\.from|fromdomain)=', aar, re.I) else None #type: ignore
            }

        for ams in ams_headers:
            kv = self.parse_kv(ams)
            i  = int(kv.get("i", -1))
            if i < 0:
                continue

            arc_sets[i]["ams"] = {
                "domain":kv.get("d"),
                "selector": kv.get("s"),
                "algorithm": kv.get("a"),
                "signed_headers": kv.get("h", "").split(':'),
            }

        for seal in seal_headers:
            kv = self.parse_kv(seal)
            i = int(kv.get("i", -1))
            if i < 0:
                continue

            arc_sets[i]["seal"] = {
                "domain": kv.get("d"),
                "selector": kv.get("s"),
                "cv": kv.get("cv"),
            }
        sets =[]
        expected_i = 1
        chain_valid = True

        for i in sorted(arc_sets.keys()):
            s = arc_sets[i]
            if i != expected_i:
                chain_valid = False
            if not all(k in s for k in ("aar", "ams", "seal")):
                chain_valid = False
            sets.append({
                "i" : i,
                "aar": s.get("aar"),
                "ams": s.get("ams"),
                "seal": s.get("seal")
            })
            expected_i += 1

        if not chain_valid:
            trust = "LOW"
        else:
            last_seal = sets[-1]["seal"]
            trust = "HIGH" if last_seal and last_seal.get("cv") == "pass" else "MEDIUM"

        return{
            "arc_present": True,
            "sets": sets,
            "chain_valid": chain_valid,
            "trust_level": trust
        }

    def run(self):
        self.check_sender_consistency()
        results = {
            "checks": {
                "SPF": self.parse_spf()["SPF"],
                "DKIM": self.dkim_result()["DKIM"],
                "ARC": self.parse_arc(),
                "DMARC": self.dmarc()["DMARC"]
            }
        }
        return results
def  analyse_email():
    parser = argparse.ArgumentParser(
            description="Analyze email authentication headers (SPF, DKIM, DMARC, ARC)"
        )
    parser.add_argument("file", help="path to the .eml file to analyze, example: ./header_checker file.eml"
            )
    args = parser.parse_args()

    email_file = args.file
    emailName, extension = email_file.split(".", 1)

    if extension != "eml":
        print("Make sure you upload a .eml file!")
    else:
        with open(email_file,"rb") as rp:
            email = BytesParser(policy=policy.default).parse(rp)
        analyzer = HeaderAnalysis(email)
        return analyzer.run()
def analyse_raw_Headers(raw_headers: bytes) -> dict:
    email = BytesParser(policy=policy.default).parsebytes(raw_headers)
    analyzer = HeaderAnalysis(email)
    return analyzer.run()

if __name__ == "__main__":
    import json
    analysis_output = analyse_email()
    print(json.dumps(analysis_output, indent=2))