import dns.resolver
from dns import reversename
from tqdm import tqdm
import time

def dns_record_lookup(target_domain, file_name):
    record_types = ["A", "AAAA", "CNAME", "MX", "TXT", "SOA"]
    resolver = dns.resolver.Resolver()

    with open(file_name, "w") as file:
        for record_type in tqdm(record_types, desc="Hunting for Information..."):
            time.sleep(1)  
            try:
                items = resolver.resolve(target_domain, record_type)
                if record_type == "A":
                    file.write(f"\nIPv4 records for {target_domain}:\n")
                elif record_type == "AAAA":
                    file.write(f"\nIPv6 records for {target_domain}:\n")
                elif record_type == "MX":
                    file.write(f"\nMail Exchange records for {target_domain}:\n")
                elif record_type == "TXT":
                    file.write(f"\n{record_type} records for {target_domain}:\n")
                elif record_type == "SOA":
                    file.write(f"\nStart of Authority (SOA) records for {target_domain}:\n")
                for item in items:
                    file.write(f"{item}\n")

            except dns.resolver.NoAnswer:
                file.write(f"\nNo {record_type} records found for {target_domain}.\n")
            except dns.resolver.NXDOMAIN:
                file.write(f"\nDomain {target_domain} does not exist.\n")
                break
            except dns.resolver.Timeout:
                file.write(f"\nTimeout while querying {record_type} records for {target_domain}.\n")
            except Exception as e:
                file.write(f"\nAn error occurred while querying {record_type} records: {e}\n")
    print(f"DNS record Hunting completed. Results saved to {file_name}.")

def reverse_dns_lookup(file_name):
    resolver = dns.resolver.Resolver()
    ip_address = input("Enter an IP address for Reverse DNS Hunting: ")

    with tqdm(total=1, desc="Performing Reverse DNS Hunting...") as pbar:
        time.sleep(1)
        try:
            reversed_name = reversename.from_address(ip_address)
            resolved_name = resolver.resolve(reversed_name, "PTR")
            print(f"Reverse DNS for {ip_address}: {resolved_name[0]}")
            with open(file_name, "a") as file:
                file.write(f"\nReverse DNS for {ip_address}:\n{resolved_name[0]}\n")
        except dns.resolver.NXDOMAIN:
            print(f"No reverse DNS found for {ip_address}.")
            with open(file_name, "a") as file:
                file.write(f"\nNo reverse DNS found for {ip_address}.\n")
        except Exception as e:
            print(f"An error occurred during reverse DNS Hunting: {e}")
            with open(file_name, "a") as file:
                file.write(f"\nAn error occurred during reverse DNS Hunting: {e}\n")
        finally:
            pbar.update(1)

def main():
    while True:
        print("Welcome to the DNS Hunting Tool!")
        print("1. Hunt The DNS Records")
        print("2. Perform Reverse DNS Hunt")
        choice = input("Choose an option (1 or 2), QUIT for exiting: ")

        if choice == "1":
            target_domain = input("Enter the target domain: ")
            file_name = input("Enter the file name to save results: ")
            dns_record_lookup(target_domain, file_name)
        elif choice == "2":
            file_name = input("Enter the file name to save results: ")
            reverse_dns_lookup(file_name)
        elif choice.upper() == "QUIT":
            print("Exiting the program. Goodbye Fellow Hunter!")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()



