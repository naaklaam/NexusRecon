# NexusRecon
# Cara Instalasi:

1. Install dependencies
pip3 install requests beautifulsoup4 dnspython python-whois

2. Download the tool
wget -O nexusrecon.py https://raw.githubusercontent.com/your-repo/nexusrecon.py
chmod +x nexusrecon.py

# Cara Penggunaan : 

1. Basic usage
python3 nexusrecon.py -d example.com

2. With company name
python3 nexusrecon.py -d example.com -n "Example Company"

3. Save results to file
python3 nexusrecon.py -d example.com -o results.txt

4. With API keys
python3 nexusrecon.py -d example.com --securitytrails YOUR_API_KEY
