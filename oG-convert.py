import argparse
import re

def parse_nmap_grepable(input_file, output_file):
    output_lines = []
    
    with open(input_file, 'r') as file:
        for line in file:
            if line.startswith('Host:'):
                # Extract IP
                ip_match = re.search(r'Host: ([\d\.]+)', line)
                ip = ip_match.group(1) if ip_match else ''
                
                # Extract Hostname
                hostname_match = re.search(r'\((.*?)\)', line)
                hostname = hostname_match.group(1) if hostname_match else ''
                
                # Extract Ports
                ports_match = re.search(r'Ports: (.+?)\s+(Ignored State|Seq Index|$)', line)
                ports = ports_match.group(1) if ports_match else ''
                
                # Extract just the port numbers
                port_numbers = []
                if ports:
                    for port in ports.split(','):
                        port_details = port.split('/')
                        if len(port_details) > 1 and port_details[1] == 'open':
                            port_numbers.append(port_details[0])
                
                # Skip the line if no open ports are found
                if not port_numbers:
                    continue
                
                # Format as <IP>,hostname,80/443/5060
                formatted_line = f"{ip},{hostname},{'/'.join(port_numbers)}"
                output_lines.append(formatted_line)

    # Write to output file
    with open(output_file, 'w') as file:
        for line in output_lines:
            file.write(line + '\n')
    print(f"Output written to {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parse nmap -oG output and reformat it.")
    parser.add_argument('-i', '--input', required=True, help="Input file (nmap -oG format)")
    parser.add_argument('-o', '--output', required=True, help="Output file (CSV or text format)")
    
    args = parser.parse_args()
    
    parse_nmap_grepable(args.input, args.output)
