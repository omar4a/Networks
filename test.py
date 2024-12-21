def get_domain_name():
    try:
        with open('/etc/resolv.conf', 'r') as f:
            for line in f:
                if line.startswith('search') or line.startswith('domain'):
                    return line.split()[1]
    except Exception as e:
        print(f"Error fetching domain name: {e}")
    return "example.com"  # Default value if unable to fetch dynamically

name = get_domain_name()

print(name)