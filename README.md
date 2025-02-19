
# UnifiNotify

A Python command-line tool for managing UniFi Access webhooks and sending door access notifications via Pushover.  This was largerly written using Cursor/Claude AI.

## Features

- Manage UniFi Access webhooks (list/add/delete)
- Listen for door access events
- Send push notifications via Pushover
- Support for self-signed certificates
- Configuration via JSON file or command-line arguments
- Test mode for validating notifications

## Requirements

- Python 3.6+
- UniFi Access Controller
- Pushover account (for notifications)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/UnifiNotify.git
   cd UnifiNotify
   ```

2. Install required Python packages:
   ```bash
   pip install flask requests urllib3
   ```

3. Copy the example settings file:
   ```bash
   cp .vscode/settings.json.example .vscode/settings.json
   ```

4. Edit `.vscode/settings.json` with your configuration:
   ```json
   {
       "unifi": {
           "host": "https://your-unifi-host",
           "token": "your-api-token",
           "webhookHost": "your-webhook-host",
           "webhookPort": 8080,
           "webhookSecret": "your-webhook-secret"
       },
       "pushover": {
           "token": "your-pushover-app-token",
           "user": "your-pushover-user-key"
       }
   }
   ```

## Usage

### Command Line

List webhooks:
   ```bash
   ./UnifiNotify.py --host https://your-unifi-host --token your-token list
   ```

Add webhook:
   ```bash
   ./UnifiNotify.py --host https://your-unifi-host --token your-token add --url http://your-webhook-url:8080 --secret your-secret
   ```

Delete webhook:
   ```bash
   ./UnifiNotify.py --host https://your-unifi-host --token your-token delete webhook-id
   ```

Start webhook listener:
   ```bash
   ./UnifiNotify.py --config listen
   ```

Test notifications:
   ```bash
   ./UnifiNotify.py --config test --testfile test_event.json
   ```

### Using Configuration File

You can store your configuration in `settings.json` and use the `--config` flag:
   ```bash
   ./UnifiNotify.py --config command [options]
   ```

The script looks for `settings.json` in these locations:
1. `.vscode/settings.json`
2. `/opt/unifinotify/settings.json`
3. Same directory as the script

## Development

VS Code launch configurations are provided for debugging. See `.vscode/launch.json` for available configurations.

## TODO

- Add some test cases for debugging
- Installation scripts and/or docker container support
- Include image of entry in pushover notification

## License

MIT
