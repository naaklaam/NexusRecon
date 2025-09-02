# NexusRecon
Cara Instalasi:

# Install dependencies
pip3 install requests beautifulsoup4 dnspython python-whois

# Download the tool
wget -O nexusrecon.py https://raw.githubusercontent.com/your-repo/nexusrecon.py
chmod +x nexusrecon.py

Cara Penggunaan : 

# Basic usage
python3 nexusrecon.py -d example.com

# With company name
python3 nexusrecon.py -d example.com -n "Example Company"

# Save results to file
python3 nexusrecon.py -d example.com -o results.txt

# With API keys
python3 nexusrecon.py -d example.com --securitytrails YOUR_API_KEY
