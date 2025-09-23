import dns.query
import dns.message
import dns.rdatatype
import dns.exception
import time

# Step 1: List of Root Server IPv4 addresses
# It's best to only use IPv4 for this assignment unless you need IPv6 support.
root_servers = [
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

def resolve_iterative(domain_name):
    # Step 2: Initialize with a Root Server
    current_server_ip = root_servers[0]
    
    # Create the DNS query message. We're asking for an A record.
    query = dns.message.make_query(domain_name, dns.rdatatype.A)
    
    # Step 3: The Main Resolution Loop
    while True:
        try:
            # This is the single, iterative query.
            # It sends the query to the current server.
            response = dns.query.udp(query, current_server_ip, timeout=5)

            # Check for NXDOMAIN response immediately after receiving the response.
            if response.rcode() == dns.rcode.NXDOMAIN:
                print(f"Error: The domain '{domain_name}' does not exist.")
                return None
            
            # Check if we have the final answer.
            if response.answer:
                # Loop through the answer section.
                for record in response.answer:
                    # Check if it's an A record.
                    if record.rdtype == dns.rdatatype.A:
                        # Found the final answer, so return it.
                        return record
                # You'll need to add CNAME handling here.
            
            # If no answer, get the next server from the Authority and Additional sections.
            else:
                next_server_ip = None
                # Check the additional section for IP addresses of the next NS.
                if response.additional:
                    for record in response.additional:
                        # Find the A record for the next name server.
                        if record.rdtype == dns.rdatatype.A:
                            next_server_ip = str(record[0]) # Get the IP address
                            break # We only need one.

                # If we didn't find the IP in the additional section, we'll need to
                # perform a new query to find it. This is a crucial, difficult step.
                if not next_server_ip and response.authority:
                    for record in response.authority:
                        if record.rdtype == dns.rdatatype.NS:
                            next_ns_name = str(record[0])
                            # Recursive call to find the IP of the next name server.
                            ns_record = resolve_iterative(next_ns_name) 
                            if ns_record:
                                next_server_ip = str(ns_record[0])
                                break
                            
                # If we successfully found the next server, update the current IP.
                if next_server_ip:
                    current_server_ip = next_server_ip
                else:
                    raise Exception("Could not find next DNS server to query.")

        # Error handling for network issues or bad responses.
        except BlockingIOError:
            # The socket is not ready yet. Let's wait and retry.
            print(f"Socket is busy, retrying query to {current_server_ip}...")
            time.sleep(1) # Wait for 1 second before retrying
            continue # Continue the loop to try the query again

        # Catch other errors, like timeouts or malformed responses
        except (dns.exception.Timeout, dns.exception.FormError) as e:
            print(f"Error querying {current_server_ip}: {e}")
            return None
        
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            return None

# --- Main Program Execution ---
if __name__ == "__main__":
    input_domain = input("Enter a domain name: ")
    print(f"Resolving {input_domain}...")
    final_answer = resolve_iterative(input_domain)
    
    if final_answer:
        # Step 4: Display the results
        # This is where you format your output like `dig`
        print("\nQUESTION SECTION:")
        print(f"  {input_domain.strip('.')}.      IN      A")
        print("\nANSWER SECTION:")
        print(f"  {final_answer.name}.   {final_answer.ttl}   IN   A   {final_answer[0]}")
    else:
        print("Failed to resolve the domain.")