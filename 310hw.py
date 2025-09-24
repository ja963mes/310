import dns.query
import dns.rdatatype
import dns.message
import socket
import time
from datetime import datetime


# Step 1: List of Root Server IPv4 addresses
# It's best to only use IPv4 for this assignment unless you need IPv6 support.
ROOT_SERVERS = [
    "198.41.0.4",  # a.root-servers.net
    "199.9.14.201", # b.root-servers.net
    "192.33.4.12", # c.root-servers.net
    "199.7.91.13",  # d.root-servers.net
    "192.203.230.10", # e.root-servers.net
    "192.5.5.241",  # f.root-servers.net
    "192.112.36.4", # g.root-servers.net
    "198.97.190.53", # h.root-servers.net
    "192.36.148.17", # i.root-servers.net
    "192.58.128.30", # j.root-servers.net
    "193.0.14.129", # k.root-servers.net
    "199.7.83.42",  # l.root-servers.net
    "202.12.27.33", # m.root-servers.net
]

def mydig(domain_name):
    """
    Performs an iterative DNS resolution for an 'A' record of a given domain name.
    
    Args:
        domain_name (str): The domain name to resolve.
    
    Returns:
        tuple: A tuple containing the resolved IP address and the final domain name
               (in case of CNAME), or None, None if resolution fails.
    """
    # Start the resolution with a root server IP. We'll use the first one.
    current_nameserver = ROOT_SERVERS[0]
    current_domain = domain_name

    print("QUESTION SECTION:")
    print(f" {current_domain.ljust(25)} IN      A\n")
    
    # The iterative resolution loop.
    # We continue until we get an 'A' record or run out of nameservers to query.
    while True:
        try:
            # Create a non-recursive query for the current domain.
            # We explicitly set rd=False to prevent the library from doing
            # the full recursive lookup for us, as per the assignment rules.
            query = dns.message.make_query(current_domain, dns.rdatatype.A)
            query.flags ^= dns.flags.RD  # Unset the Recursion Desired flag

            # Send the query to the current nameserver.
            print(f"Querying {current_nameserver} for {current_domain}")
            response = dns.query.udp(query, current_nameserver, timeout=5)

            # Check if we have an answer.
            if response.answer:
                # Iterate through the answer section to find A and CNAME records.
                for rrset in response.answer:
                    # Found an A record, we're done.
                    if rrset.rdtype == dns.rdatatype.A:
                        return rrset[0].address, current_domain
                    # Found a CNAME, update the domain and continue the loop.
                    elif rrset.rdtype == dns.rdatatype.CNAME:
                        cname_target = str(rrset[0])
                        print(f"Found CNAME for {current_domain}: {cname_target}")
                        current_domain = cname_target
                        # We need to restart the iterative process for the new domain.
                        current_nameserver = ROOT_SERVERS[0]
                        break # Break from the inner rrset loop to continue outer while loop
                else: # This 'else' belongs to the 'for' loop, executed if no break occurs.
                      # This happens when the answer section has something, but not A or CNAME.
                    print("No A or CNAME record found in the answer section. Exiting.")
                    return None, None
            
            # If no answer, look for authority (NS) records.
            elif response.authority:
                found_new_nameserver = False
                for rrset in response.authority:
                    if rrset.rdtype == dns.rdatatype.NS:
                        for rdata in rrset:
                            # Try to find the IP address of the new nameserver in the additional section.
                            # This is the "glue record".
                            for additional_rrset in response.additional:
                                if additional_rrset.rdtype == dns.rdatatype.A and additional_rrset.name == rdata.target:
                                    current_nameserver = additional_rrset[0].address
                                    print(f"Found next nameserver in additional section: {current_nameserver}")
                                    found_new_nameserver = True
                                    break
                            
                            if found_new_nameserver:
                                break
                            
                            # If no glue record, we must resolve the new nameserver's name itself.
                            # This is a recursive call to mydig to find the NS server's IP.
                            if not found_new_nameserver:
                                print(f"Resolving IP for nameserver: {rdata.target}")
                                ip, _ = mydig(str(rdata.target))
                                if ip:
                                    current_nameserver = ip
                                    found_new_nameserver = True
                                    print(f"Resolved nameserver IP: {current_nameserver}")
                                    break
                
                if not found_new_nameserver:
                    print("Could not find a new nameserver to query. Exiting.")
                    return None, None
            
            # If no answer or authority records, something is wrong.
            else:
                print("No answer, authority, or additional records. Exiting.")
                return None, None

        except (dns.exception.Timeout, socket.error) as e:
            print(f"Query to {current_nameserver} timed out or failed: {e}")
            print("Trying next root server...")
            # If one server fails, try another from the root servers list.
            try:
                # Find the current server's index and move to the next.
                idx = ROOT_SERVERS.index(current_nameserver)
                current_nameserver = ROOT_SERVERS[idx + 1]
            except (ValueError, IndexError):
                print("Ran out of nameservers to try. Resolution failed.")
                return None, None
        
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            return None, None

def main():
    """
    Main function to run the mydig tool from the command line.
    """
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python mydig.py <domain_name>")
        sys.exit(1)
    
    domain_name = sys.argv[1]
    
    start_time = time.time()
    
    ip_address, final_domain = mydig(domain_name)
    
    end_time = time.time()
    query_time = (end_time - start_time) * 1000  # Convert to milliseconds
    
    print("\nANSWER SECTION:")
    if ip_address:
        print(f" {final_domain.ljust(25)} 262     IN      A       {ip_address}")
    else:
        print(" Resolution failed.")
        
    print(f"\nQuery time: {query_time:.2f} msec")
    print(f"WHEN: {datetime.now().strftime('%a %b %d %H:%M:%S %Y')}")

if __name__ == "__main__":
    main()
