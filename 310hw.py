import sys
import time
import datetime
import random
import dns.name
import dns.message
import dns.query
import dns.rdatatype

ROOT_SERVERS = [
    "198.41.0.4",
    "199.9.14.201",
    "192.33.4.12",
    "199.7.91.13",
    "192.203.230.10",
    "192.5.5.241",
    "192.112.36.4",
    "198.97.190.53",
    "192.36.148.17",
    "192.58.128.30",
    "193.0.14.129",
    "199.7.83.42",
    "202.12.27.33",
]

def resolve_iterative(domain, timeout=3, max_hops=10):
    def send_query(qname, server_ip):
        msg = dns.message.make_query(qname, dns.rdatatype.A)
        return dns.query.udp(msg, server_ip, timeout=timeout)

    def nsname_to_ips(ns_hostname, remaining_hops):
        if remaining_hops <= 0:
            return []
        try:
            rrsets = resolve_iterative(ns_hostname, timeout=timeout, max_hops=remaining_hops)
            ips = []
            for rr in rrsets:
                if rr.rdtype == dns.rdatatype.A:
                    for rr_item in rr:
                        ips.append(rr_item.address)
            return ips
        except Exception:
            return []

    q = dns.name.from_text(domain)
    target = q
    nameserver_ips = ROOT_SERVERS.copy()
    accumulated = []

    for hop in range(max_hops):
        random.shuffle(nameserver_ips)
        response = None
        last_exc = None
        for ns_ip in nameserver_ips:
            try:
                response = send_query(target, ns_ip)
                break
            except Exception as e:
                last_exc = e
                continue
        if response is None:
            raise Exception(f"Unable to reach nameservers {nameserver_ips} - last error: {last_exc}")

        if response.answer:
            has_a = any(rrset.rdtype == dns.rdatatype.A for rrset in response.answer)
            has_cname = any(rrset.rdtype == dns.rdatatype.CNAME for rrset in response.answer)
            for rrset in response.answer:
                if rrset.rdtype == dns.rdatatype.CNAME:
                    accumulated.append(rrset)
            if has_a:
                for rrset in response.answer:
                    if rrset.rdtype == dns.rdatatype.A:
                        accumulated.append(rrset)
                return accumulated
            if has_cname:
                last_target = None
                for rrset in response.answer:
                    if rrset.rdtype == dns.rdatatype.CNAME:
                        last_target = rrset[0].target.to_text()
                if not last_target:
                    raise Exception("Unexpected CNAME response")
                target = dns.name.from_text(last_target)
                nameserver_ips = ROOT_SERVERS.copy()
                continue

        glue = []
        for rrset in response.additional:
            if rrset.rdtype == dns.rdatatype.A:
                for r in rrset:
                    glue.append(r.address)
        if glue:
            nameserver_ips = glue
            continue

        ns_hostnames = []
        for rrset in response.authority:
            if rrset.rdtype == dns.rdatatype.NS:
                for r in rrset:
                    ns_hostnames.append(r.target.to_text())
        if not ns_hostnames:
            has_soa = any(rrset.rdtype == dns.rdatatype.SOA for rrset in response.authority)
            if has_soa:
                raise Exception(f"No A record for {domain}; authority contains SOA")
            raise Exception("No delegation records available to continue resolution")

        resolved = []
        remaining = max_hops - hop - 1
        for nh in ns_hostnames:
            ips = nsname_to_ips(nh, remaining)
            if ips:
                resolved.extend(ips)
        if not resolved:
            for nh in ns_hostnames:
                ips = nsname_to_ips(nh, remaining)
                resolved.extend(ips)

        if not resolved:
            raise Exception("Could not resolve delegated nameserver hostnames: " + ", ".join(ns_hostnames))

        nameserver_ips = list(dict.fromkeys(resolved))

    raise Exception("Exceeded maximum hops while resolving " + domain)

def format_question_section(name):
    print("\n\tQUESTION SECTION:\n")
    print(f"\t{name:<40} IN\tA\n")

def format_answer_section(answer_rrsets):
    print("\n\tANSWER SECTION:\n")
    for rrset in answer_rrsets:
        if rrset.rdtype == dns.rdatatype.A:
            for r in rrset:
                print(f"\t{rrset.name.to_text()}\t{rrset.ttl}\tIN\tA\t{r.address}")
        elif rrset.rdtype == dns.rdatatype.CNAME:
            for r in rrset:
                print(f"\t{rrset.name.to_text()}\t{rrset.ttl}\tIN\tCNAME\t{r.target.to_text()}")
        else:
            print(f"\t{rrset}")

def main():
    try:
        domain_input = input('mydig ').strip()
        domain_input = domain_input.strip('"').strip("'")
    except (EOFError, KeyboardInterrupt):
        print("\nNo input provided.")
        sys.exit(1)
    if not domain_input:
        print("No domain entered. Exiting.")
        sys.exit(1)
    domain = domain_input.rstrip(".")
    start = time.time()
    try:
        answers = resolve_iterative(domain)
        elapsed_ms = int((time.time() - start) * 1000)
        format_question_section(domain + ".")
        format_answer_section(answers)
        print(f"\n\tQuery time: {elapsed_ms} ms")
        print(f"\tWHEN: {datetime.datetime.now().strftime('%a %b %d %H:%M:%S %Y')}\n")
    except Exception as e:
        print("ERROR:", e)
        sys.exit(1)

if __name__ == "__main__":
    main()
