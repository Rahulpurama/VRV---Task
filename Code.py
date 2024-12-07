# import re
# from collections import Counter

# # Parses the log file and extracts all IP addresses.
# def parse_log_file(file_path):
#     ip_addresses = []
#     with open(file_path, 'r') as file:
#         for line in file:
#             # Extract IP addresses using a regular expression
#             ip_match = re.search(r'^\d+\.\d+\.\d+\.\d+', line)
#             if ip_match:
#                 ip_addresses.append(ip_match.group())
#     return ip_addresses

# # Counts the number of requests made by each IP address
# # and returns a sorted list of tuples (IP, count).
# def count_requests_per_ip(ip_addresses):
#     ip_counts = Counter(ip_addresses)
#     return sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)

# # Displays the IP address and request count in a formatted way.
# def display_results(ip_data):
#     print(f"{'IP Address':<20} {'Request Count':<15}")
#     print("-" * 35)
#     for ip, count in ip_data:
#         print(f"{ip:<20} {count:<15}")

# def main():
#     log_file = 'sample.log'  # Replace with your log file path

#     # Parse log file to extract IP addresses
#     ip_addresses = parse_log_file(log_file)

#     # Count requests per IP
#     ip_data = count_requests_per_ip(ip_addresses)

#     # Display results
#     display_results(ip_data)

# if __name__ == "__main__":
#     main()
    
# import re
# from collections import Counter

# def extract_endpoints(file_path):
#     """
#     Parses the log file and extracts all endpoints (URLs or resource paths).
#     """
#     endpoints = []
#     with open(file_path, 'r') as file:
#         for line in file:
#             # Extract endpoint using a regular expression
#             endpoint_match = re.search(r'"(?:GET|POST|PUT|DELETE) (.*?) HTTP/', line)
#             if endpoint_match:
#                 endpoints.append(endpoint_match.group(1))
#     return endpoints

# def find_most_frequent_endpoint(endpoints):
#     """
#     Identifies the most frequently accessed endpoint and its count.
#     """
#     endpoint_counts = Counter(endpoints)
#     most_frequent = max(endpoint_counts.items(), key=lambda x: x[1])
#     return most_frequent

# def display_most_frequent_endpoint(endpoint, count):
#     """
#     Displays the most frequently accessed endpoint in a formatted way.
#     """
#     print("Most Frequently Accessed Endpoint:")
#     print(f"{endpoint} (Accessed {count} times)")

# def main():
#     log_file = 'sample.log'  # Replace with your log file path

#     # Extract endpoints from the log file
#     endpoints = extract_endpoints(log_file)

#     # Find the most frequently accessed endpoint
#     endpoint, count = find_most_frequent_endpoint(endpoints)

#     # Display the result
#     display_most_frequent_endpoint(endpoint, count)

# if __name__ == "__main__":
#     main()


import re
from collections import defaultdict, Counter
import csv

# Configurable threshold for suspicious activity detection
FAILED_LOGIN_THRESHOLD = 10

def parse_log_file(file_path):
    """
    Parses the log file and extracts relevant information.
    Returns lists of IP addresses, endpoints, and failed login attempts.
    """
    ip_addresses = []
    endpoints = []
    failed_logins = defaultdict(int)

    with open(file_path, 'r') as file:
        for line in file:
            # Extract IP addresses
            ip_match = re.search(r'^\d+\.\d+\.\d+\.\d+', line)
            if ip_match:
                ip = ip_match.group()
                ip_addresses.append(ip)

            # Extract endpoints
            endpoint_match = re.search(r'"[A-Z]+\s(\/\S*)', line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoints.append(endpoint)

            # Detect failed logins
            if "401" in line or "Invalid credentials" in line:
                if ip_match:
                    failed_logins[ip] += 1

    return ip_addresses, endpoints, failed_logins

def count_requests_per_ip(ip_addresses):
    """
    Counts the number of requests made by each IP address.
    Returns a sorted list of tuples (IP, count).
    """
    ip_counts = Counter(ip_addresses)
    return sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)

def find_most_frequent_endpoint(endpoints):
    """
    Identifies the most frequently accessed endpoint.
    Returns the endpoint and its access count.
    """
    endpoint_counts = Counter(endpoints)
    return endpoint_counts.most_common(1)[0]

def detect_suspicious_activity(failed_logins):
    """
    Flags IP addresses with failed login attempts exceeding the threshold.
    Returns a list of tuples (IP, count).
    """
    return [(ip, count) for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD]

def save_to_csv(ip_data, endpoint_data, suspicious_data, output_file):
    """
    Saves the results to a CSV file.
    """
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        # Write Requests per IP
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(ip_data)
        writer.writerow([])
        
        # Write Most Accessed Endpoint
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow(endpoint_data)
        writer.writerow([])
        
        # Write Suspicious Activity
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        writer.writerows(suspicious_data)

def main():
    log_file = 'C:/Users/Rahul/Desktop/VRV/sample.log.txt'  # Replace with your log file path
    output_file = 'log_analysis_results.csv'

    # Parse log file
    ip_addresses, endpoints, failed_logins = parse_log_file(log_file)

    # Count requests per IP
    ip_data = count_requests_per_ip(ip_addresses)
    
    # Find most accessed endpoint
    endpoint_data = find_most_frequent_endpoint(endpoints)
    
    # Detect suspicious activity
    suspicious_data = detect_suspicious_activity(failed_logins)

    # Display results
    print("Requests per IP Address:")
    for ip, count in ip_data:
        print(f"{ip:<20} {count}")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{endpoint_data[0]} (Accessed {endpoint_data[1]} times)")
    
    print("\nSuspicious Activity Detected:")
    for ip, count in suspicious_data:
        print(f"{ip:<20} {count}")
    
    # Save results to CSV
    save_to_csv(ip_data, endpoint_data, suspicious_data, output_file)
    print(f"\nResults saved to {output_file}")

if __name__ == "__main__":
    main()
