## Compilation and Installation

### Prerequisites
- Ubuntu 24.04.2 LTS
- Python 3.11 (default on Ubuntu 24.04)
- Required Python libraries:
  - pycryptodome (for AES)
  - pytest (for testing)

### Installation
Create a virtual environment and install dependencies:

```bash
sudo apt update
sudo apt install python3 python3-venv python3-pip -y
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Testing
```bash
pytest
```