#!/usr/bin/env python3

import argparse
import hmac
import hashlib
import json
import sys
import urllib3
import http.client, urllib, ssl
from datetime import datetime
from flask import Flask, request, jsonify
import requests
from threading import Thread
import os

# Suppress insecure HTTPS warnings when verify_ssl is False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

class UnifiAccessWebhook:
    def __init__(self, host, token, verify_ssl=True):
        self.host = host.rstrip('/')
        self.token = token
        self.verify_ssl = verify_ssl
        self.headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }

    def add_webhook(self, url, events=None):
        """Add a new webhook endpoint"""
        endpoint = f"{self.host}:12445/api/v1/developer/webhooks/endpoints"
        
        data = {
            "name": "UnifiNotify",
            "endpoint": url,
            "events": events or ["access.door.unlock"] # Default to door unlock events if none specified
        }

        response = requests.post(endpoint, headers=self.headers, json=data, verify=self.verify_ssl)
        return response.json()

    def list_webhooks(self):
        """List all registered webhooks"""
        endpoint = f"{self.host}:12445/api/v1/developer/webhooks/endpoints"
        response = requests.get(endpoint, headers=self.headers, verify=self.verify_ssl)
        return response.json()

    def delete_webhook(self, webhook_id):
        """Delete a webhook by ID"""
        endpoint = f"{self.host}:12445/api/v1/developer/webhooks/endpoints/{webhook_id}"
        response = requests.delete(endpoint, headers=self.headers, verify=self.verify_ssl)
        return response.json()

class WebhookListener:
    def __init__(self, secret, port=8080, webhook_host='0.0.0.0', pushover_user=None, pushover_token=None, test_file=None):
        self.secret = secret
        self.port = port
        self.webhook_host = webhook_host
        self.pushover_user = pushover_user
        self.pushover_token = pushover_token
        self.test_file = test_file

    def validate_signature(self, payload, signature_header):
        """Validate the webhook signature"""
        try:
            # Parse signature header
            pairs = dict(pair.split('=') for pair in signature_header.split(','))
            timestamp = int(pairs['t'])
            received_sig = bytes.fromhex(pairs['v1'])

            # Compute expected signature
            mac = hmac.new(self.secret.encode(), digestmod=hashlib.sha256)
            mac.update(f"{timestamp}".encode())
            mac.update(b".")
            mac.update(payload)
            expected_sig = mac.digest()

            return hmac.compare_digest(expected_sig, received_sig)
        except Exception as e:
            print(f"Signature validation error: {e}", file=sys.stderr)
            return False

    def send_push_notification(self, title, message):
        """Send push notification via Pushover"""
        if not (self.pushover_user and self.pushover_token):
            return
            
        try:
            params = urllib.parse.urlencode({
                'token': self.pushover_token,
                'user': self.pushover_user,
                'title': title,
                'message': message
            })
            
            conn = http.client.HTTPSConnection("api.pushover.net", context=ssl._create_unverified_context())
            headers = {"Content-type": "application/x-www-form-urlencoded"}
            conn.request("POST", "/1/messages.json", params, headers)
            
            response = conn.getresponse()
            if response.status not in [200, 201]:
                raise Exception(f"HTTP {response.status}: {response.read().decode()}")
            conn.close()
        except Exception as e:
            print(f"Error sending push notification: {e}", file=sys.stderr)

    def process_event(self, event):
        """Process an event and send push notification"""
        print(f"Received event at {datetime.now().isoformat()}:")
        print(json.dumps(event, indent=2))
        
        try:
            door = event.get('data', {}).get('device', {}).get('alias', 'Unknown Door')
            actor = event.get('data', {}).get('actor', {}).get('name', 'Unknown User')
            auth_type = event.get('data', {}).get('object', {}).get('authentication_type', 'Unknown Method')
            result = event.get('data', {}).get('object', {}).get('result', 'Unknown Result')
            
            title = f"{door}"
            message = f"opened by {actor} via {auth_type}: {result}"
            self.send_push_notification(title, message)
        except Exception as e:
            print(f"Error creating push notification: {e}", file=sys.stderr)

    def test_mode(self):
        """Run in test mode using a JSON file"""
        try:
            with open(self.test_file, 'r') as f:
                event = json.load(f)
            self.process_event(event)
            print("Test completed successfully")
        except Exception as e:
            print(f"Error in test mode: {e}", file=sys.stderr)
            sys.exit(1)

    def start(self):
        """Start the webhook listener"""
        if self.test_file:
            self.test_mode()
            return

        @app.route('/', methods=['POST'])
        def webhook_handler():
            signature = request.headers.get('Signature')
            if not signature:
                return 'Missing signature', 401

            payload = request.get_data()
            if not self.validate_signature(payload, signature):
                return 'Invalid signature', 401

            try:
                event = json.loads(payload)
                self.process_event(event)
                return 'OK', 200
            except Exception as e:
                print(f"Error processing webhook: {e}", file=sys.stderr)
                return 'Error processing webhook', 400

        app.run(host=self.webhook_host, port=self.port)

def list_webhooks(host, token, verify_ssl=True, verbose=False):
    webhook = UnifiAccessWebhook(host, token, verify_ssl=verify_ssl)
    response = webhook.list_webhooks()
    if verbose:
        print(json.dumps(response, indent=2))
    else:
        for hook in response.get('data', []):
            print(f"ID: {hook.get('id')} - {hook.get('name')} -> {hook.get('endpoint')}")

def add_webhook(host, token, url, verify_ssl=True, verbose=False):
    webhook = UnifiAccessWebhook(host, token, verify_ssl=verify_ssl)
    response = webhook.add_webhook(url)
    if verbose:
        print(json.dumps(response, indent=2))
    else:
        if 'data' in response:
            print(f"Added webhook: {response['data'].get('id')}")
        else:
            print("Failed to add webhook")

def delete_webhook(host, token, webhook_id, verify_ssl=True, verbose=False):
    webhook = UnifiAccessWebhook(host, token, verify_ssl=verify_ssl)
    response = webhook.delete_webhook(webhook_id)
    if verbose:
        print(json.dumps(response, indent=2))
    else:
        print(f"Deleted webhook: {webhook_id}")

def load_config():
    """Load configuration from settings.json in standard locations"""
    config_paths = [
        '.vscode/settings.json',                    # Local development
        '/opt/unifinotify/settings.json',          # Service installation
        os.path.dirname(os.path.realpath(__file__)) + '/settings.json'  # Script directory
    ]
    
    for path in config_paths:
        if os.path.exists(path):
            try:
                with open(path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Error loading {path}: {e}", file=sys.stderr)
    
    raise FileNotFoundError("Could not find settings.json in any standard location")

def main():
    parser = argparse.ArgumentParser(description='UniFi Access Webhook Manager')
    
    # Move global arguments to parent parser
    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument('--config', nargs='?', const=True, 
                           help='Use settings.json for configuration. Optionally specify config file path')
    parent_parser.add_argument('--host', help='UniFi Access host URL')
    parent_parser.add_argument('--token', help='UniFi Access API token')
    parent_parser.add_argument('--no-verify-ssl', action='store_false', dest='verify_ssl', 
                           help='Disable SSL certificate verification')
    parent_parser.add_argument('-v', '--verbose', action='store_true',
                           help='Show detailed JSON output')

    # Create subparsers with parent
    subparsers = parser.add_subparsers(dest='command', required=True)

    # List command
    list_parser = subparsers.add_parser('list', help='List existing webhooks', parents=[parent_parser])

    # Add command
    add_parser = subparsers.add_parser('add', help='Add a new webhook', parents=[parent_parser])
    add_parser.add_argument('--url', required=True, help='Webhook URL')

    # Delete command
    delete_parser = subparsers.add_parser('delete', help='Delete a webhook', parents=[parent_parser])
    delete_parser.add_argument('webhook_id', help='ID of webhook to delete')

    # Listen command
    listen_parser = subparsers.add_parser('listen', help='Start webhook listener', parents=[parent_parser])
    listen_parser.add_argument('--secret', help='Webhook secret for validation')
    listen_parser.add_argument('--port', type=int, default=8080, help='Port to listen on (default: 8080)')
    listen_parser.add_argument('--webhook-host', help='Host to listen on (default: 0.0.0.0)')
    listen_parser.add_argument('--pushover-user', help='Pushover user key (found on your Pushover dashboard at pushover.net)')
    listen_parser.add_argument('--pushover-token', help='Pushover application token (create an application at pushover.net/apps/build)')

    # Test command
    test_parser = subparsers.add_parser('test', help='Test push notification with JSON event file', parents=[parent_parser])
    test_parser.add_argument('--testfile', required=True, help='JSON file containing test webhook data')
    test_parser.add_argument('--pushover-user', help='Pushover user key (found on your Pushover dashboard at pushover.net)')
    test_parser.add_argument('--pushover-token', help='Pushover application token (create an application at pushover.net/apps/build)')

    args = parser.parse_args()

    # Load config if specified
    if args.config:
        try:
            if isinstance(args.config, str):
                with open(args.config, 'r') as f:
                    settings = json.load(f)
            else:
                settings = load_config()

            # Always load host and token for all commands
            if not args.host:
                args.host = settings.get('unifi', {}).get('host')
            if not args.token:
                args.token = settings.get('unifi', {}).get('token')

            # Load additional settings only for commands that need them
            if args.command in ['listen', 'test']:
                if not hasattr(args, 'secret') or not args.secret:
                    args.secret = settings.get('unifi', {}).get('webhookSecret')
                if not hasattr(args, 'pushover_user') or not args.pushover_user:
                    args.pushover_user = settings.get('pushover', {}).get('user')
                if not hasattr(args, 'pushover_token') or not args.pushover_token:
                    args.pushover_token = settings.get('pushover', {}).get('token')
                if not hasattr(args, 'webhookhost') or not args.webhook_host:
                    args.webhook_host = settings.get('unifi', {}).get('webhookHost', '0.0.0.0')
                if not hasattr(args, 'port') or args.port == 8080:  # Only override if not specified or at default
                    args.port = settings.get('unifi', {}).get('webhookPort', 8080)

        except Exception as e:
            print(f"Error loading settings.json: {e}", file=sys.stderr)
            sys.exit(1)

    # Validate host and token are provided for commands that need them
    if args.command in ['list', 'add', 'delete', 'listen', 'test']:
        if not args.host or not args.token:
            parser.error(f"The {args.command} command requires --host and --token arguments or --config with valid settings.json")

    # Validate required arguments for listen command
    if args.command in ['listen', 'test']:
        if not args.secret:
            parser.error("listen command requires --secret argument or --config with webhookSecret")
        if not args.pushover_user or not args.pushover_token:
            parser.error("listen command requires --pushover-user and --pushover-token arguments or --config with pushover settings")

    if args.command == 'list':
        list_webhooks(args.host, args.token, args.verify_ssl, args.verbose)
    elif args.command == 'add':
        add_webhook(args.host, args.token, args.url, args.verify_ssl, args.verbose)
    elif args.command == 'delete':
        delete_webhook(args.host, args.token, args.webhook_id, args.verify_ssl, args.verbose)
    elif args.command in ['listen', 'test']:
        if not hasattr(args, 'testfile'): args.testfile=None
        listener = WebhookListener(
            args.secret, 
            args.port,
            webhook_host=args.webhook_host or '0.0.0.0',
            pushover_user=args.pushover_user,
            pushover_token=args.pushover_token,
            test_file=args.testfile
        )
        print(f"Starting webhook listener on {args.webhook_host or '0.0.0.0'}:{args.port}")
        if args.command == 'listen':
            listener.start()
        elif args.command == 'test':
            listener.test_mode()


if __name__ == '__main__':
    main() 