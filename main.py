import re
from collections import defaultdict
import csv
from typing import List, Dict

class PyLog:
    def __init__(self, log_file_path: str, failed_login_threshold: int = 10):
        """
        Initialize the PyLog class with the log file path and failed login threshold.        
        """
        self.log_file_path = log_file_path
        self.failed_login_threshold = failed_login_threshold
        self.log_entries = self._read_log_file()

    def _read_log_file(self) -> List[str]:
        
        # Read the log file and return a list of log entries.
        
        try:
            with open(self.log_file_path, 'r') as file:
                return file.readlines()
        except FileNotFoundError:
            print(f"Error: Log file {self.log_file_path} not found.")
            return []

    def count_requests_per_ip(self) -> Dict[str, int]:
        
        # Count the number of requests made by each IP address.
        
        ip_requests = defaultdict(int)
        for entry in self.log_entries:
            match = re.match(r'^(\d+\.\d+\.\d+\.\d+)', entry)
            if match:
                ip_requests[match.group(1)] += 1
        
        return dict(sorted(ip_requests.items(), key=lambda x: x[1], reverse=True))

    def find_most_accessed_endpoint(self) -> Dict[str, int]:
        
        #Find the most frequently accessed endpoint.        
        
        endpoint_counts = defaultdict(int)
        for entry in self.log_entries:
            match = re.search(r'"[A-Z]+ (/\w+)', entry)
            if match:
                endpoint_counts[match.group(1)] += 1
        
        if not endpoint_counts:
            return {}
        
        most_accessed = max(endpoint_counts.items(), key=lambda x: x[1])
        return {most_accessed[0]: most_accessed[1]}

    def detect_suspicious_activity(self) -> Dict[str, int]:
        
        # Detect potential brute force login attempts. 
        
        
        failed_logins = defaultdict(int)
        for entry in self.log_entries:
            # Specifically look for failed login attempts
            failed_login_match = re.match(r'^(\d+\.\d+\.\d+\.\d+).*"POST /login.*" (401|"Invalid credentials")', entry)
            if failed_login_match:
                ip = failed_login_match.group(1)
                failed_logins[ip] += 1
        
        # Filter IPs with failed attempts exceeding the threshold
        suspicious_ips = {
            ip: count for ip, count in failed_logins.items() 
            if count > self.failed_login_threshold
        }
        
        return dict(sorted(suspicious_ips.items(), key=lambda x: x[1], reverse=True))

    def save_results_to_csv(self, results: dict, filename: str = 'log_analysis_results.csv'):
        
        # Save analysis results to a CSV file.
        try:
            with open(filename, 'w', newline='') as csvfile:
                # Write results for requests per IP
                csvfile.write("Requests per IP\n")
                writer = csv.writer(csvfile)
                writer.writerow(["IP Address", "Request Count"])
                for ip, count in results['requests_per_ip'].items():
                    writer.writerow([ip, count])
                
                # Write results for most accessed endpoint
                csvfile.write("\nMost Accessed Endpoint\n")
                writer.writerow(["Endpoint", "Access Count"])
                endpoint, count = list(results['most_accessed_endpoint'].items())[0]
                writer.writerow([endpoint, count])
                
                # Write results for suspicious activity
                csvfile.write("\nSuspicious Activity\n")
                writer.writerow(["IP Address", "Failed Login Attempts"])
                for ip, count in results['suspicious_activity'].items():
                    writer.writerow([ip, count])
            
            print(f"Results saved to {filename}")
        except Exception as e:
            print(f"Error saving results to CSV: {e}")

    def display_results(self):
        
        # Analyze log file
        requests_per_ip = self.count_requests_per_ip()
        most_accessed_endpoint = self.find_most_accessed_endpoint()
        suspicious_activity = self.detect_suspicious_activity()

        # Prepare results dictionary
        results = {
            'requests_per_ip': requests_per_ip,
            'most_accessed_endpoint': most_accessed_endpoint,
            'suspicious_activity': suspicious_activity
        }

        # Display requests per IP
        print("\n--- Requests per IP Address ---")
        print(f"{'IP Address':<20}{'Request Count':<15}")
        print("-" * 35)
        for ip, count in requests_per_ip.items():
            print(f"{ip:<20}{count:<15}")

        # Display most accessed endpoint
        print("\n--- Most Frequently Accessed Endpoint ---")
        if most_accessed_endpoint:
            endpoint, count = list(most_accessed_endpoint.items())[0]
            print(f"{endpoint} (Accessed {count} times)")

        # Display suspicious activity with exact format
        print("\nSuspicious Activity Detected:")
        if suspicious_activity:
            print(f"{'IP Address':<20}{'Failed Login Attempts':<15}")
            print("-" * 35)
            for ip, count in suspicious_activity.items():
                print(f"{ip:<20}{count:<15}")
        else:
            print("No suspicious activity detected.")

        # Save results to CSV
        self.save_results_to_csv(results)

def main():
    log_file_path = 'sample.log'
    analyzer = PyLog(log_file_path)
    analyzer.display_results()

if __name__ == "__main__":
    main()