# DMconnect
> [!Important]
> The server is not yet fully developed, so it may experience instability and frequent updates to this repository.

Server for the decentralized DMconnect protocol.

It's extremely simple and lightweight, and you can even connect and communicate using Telnet. [Documentation](https://dmconnectspec.w10.site/) is also available.

## Requirements

- **Python 3.8+** (download it from [python.org](https://python.org/)).
- **pycryptodome** library (see below)

## Installation

1. Download and unzip the repository contents into any empty folder.
2. Install the **pycryptodome** library using the following command:

```
pip install pycryptodome
```

If you are using **Linux**, you can install it with the system package manager instead:

```
sudo apt install python3-pycryptodome
```
3. Go to line [67](DMCD.py#L67) in [`DMCD.py`](DMCD.py) and replace `MY_SERVER_HOST` with your server's public domain name or IP address, and `ADMIN_USERNAME` with the administrator username.
4. Start the server using this command:
```
python3 DMCD.py
```
5. Done!

---
## License

This project is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**.

See the [**LICENSE**](LICENSE) file for details.
