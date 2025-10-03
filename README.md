# BIGSdb_sync

Client software for synchronising sequence definition and isolate databases 
with a remote BIGSdb installation via the API using OAuth authentication.

## Installation
It is recommended that you install this in a virtual environment, e.g.

```
git clone https://github.com/kjolley/BIGSdb_sync.git
cd BIGSdb_sync
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

You can de-activate the virtual environment with:

```
deactivate
```