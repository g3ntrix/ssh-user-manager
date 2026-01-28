# SSH User Manager

A simple SSH user management tool with traffic tracking for Linux servers.

## Quick Install

```bash
sudo bash <(curl -s https://raw.githubusercontent.com/g3ntrix/ssh-user-manager/main/install.sh)
```

Or manually:

```bash
git clone https://github.com/g3ntrix/ssh-user-manager.git
cd ssh-user-manager
sudo bash install.sh
```

## Usage

```bash
sudo ssh-user-manager
```

## Features

- Create/delete SSH users
- Set traffic limits per user
- Set expiration dates
- Real-time traffic monitoring
- Automatic account locking when limits exceeded

## Requirements

- Linux (Debian/Ubuntu/CentOS)
- Root access

## License

MIT
