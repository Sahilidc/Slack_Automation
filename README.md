# Slack Secret Scanner

A Slack bot that scans messages in public and private channels for sensitive information (e.g., emails, API keys, passwords) and optionally checks for malicious URLs or files using VirusTotal. The bot deletes messages containing sensitive or malicious content and notifies users via direct messages (DMs). Scans can be triggered manually with the `/scan` Slack command or run automatically every 24 hours.

## Features
- **Secret Detection**: Identifies emails, API keys, and passwords in Slack messages using regex patterns.
- **Message Deletion**: Automatically deletes messages containing sensitive or malicious content.
- **User Notifications**: Sends DMs to users with details of detected secrets or malicious content.
- **Scheduled Scans**: Runs scans every 24 hours to check recent messages.
- **Manual Scans**: Supports the `/scan` Slack command for on-demand scanning.
- **VirusTotal Integration** (Optional): Scans URLs or files for malicious content (requires integration in `virus_total.py`).
- **Docker Support**: Run the bot in a containerized environment using Docker and Docker Compose.

## Prerequisites
- **Python 3.11+** (for local execution)
- **Docker and Docker Compose** (for containerized execution)
- **Slack Workspace** with admin access to create a Slack app
- **VirusTotal API Key** (optional, for URL/file scanning)
- **Ngrok** (optional, for local testing of Slack webhooks)

## File Structure
```
secret-scanner/
├── app.py                  # Main Flask app and bot logic
├── scanner/
│   ├── secret_detector.py  # Logic for detecting secrets in messages
│   ├── virus_total.py      # Logic for VirusTotal scanning (optional)
│   └── utils.py           # Slack API utilities (fetch messages, delete, DM)
├── .env                   # Environment variables (Slack and VirusTotal keys)
├── requirements.txt       # Python dependencies
├── Dockerfile             # Docker image definition
├── docker-compose.yml     # Docker Compose configuration
└── README.md              # Project documentation
```

## Setup Instructions

### 1. Clone the Repository
```bash
git clone https://github.com/your-username/secret-scanner.git
cd secret-scanner
```

### 2. Create a Slack App
1. Go to [Slack API](https://api.slack.com/apps) and create a new app.
2. Configure the app:
   - **Bot Token Scopes** (under **OAuth & Permissions**):
     ```
     channels:history
     channels:read
     chat:write
     chat:write.public
     files:read
     groups:history
     groups:read
     im:history
     im:write
     users:read
     ```
   - **Slash Commands** (under **Slash Commands**):
     - Create a command (e.g., `/scan`) with the Request URL set to `http://<your-host>:3000/slack/commands` (use Ngrok for local testing).
   - **Install App**: Install the app to your Slack workspace and copy the **Bot User OAuth Token** (starts with `xoxb-`).
3. Note the **Signing Secret** (under **Basic Information**).

### 3. Configure Environment Variables
Create a `.env` file in the project root with the following:
```bash
SLACK_BOT_TOKEN=xoxb-your-slack-bot-token
SLACK_SIGNING_SECRET=your-slack-signing-secret
VIRUSTOTAL_API_KEY=your-virustotal-api-key  # Optional, for VirusTotal
```

- Obtain a VirusTotal API key from [VirusTotal](https://www.virustotal.com/gui/join-us) if using the VirusTotal feature.

### 4. Install Dependencies (Local Execution)
1. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
   Ensure `requirements.txt` includes:
   ```
   flask==2.3.3
   slack_sdk==3.21.3
   python-dotenv==1.0.0
   schedule==1.2.0
   requests==2.31.0
   virustotal-python==1.1.0  # Optional, for VirusTotal
   ```

### 5. Run Locally
1. Start the bot:
   ```bash
   python app.py
   ```
   - The Flask server will run on `http://localhost:3000`.
   - The bot performs an initial scan and schedules scans every 24 hours.
2. Expose the server to Slack using Ngrok (for local testing):
   ```bash
   ngrok http 3000
   ```
   Update the Slack app’s **Request URL** to the Ngrok URL (e.g., `https://your-ngrok-url.ngrok.io/slack/commands`).
3. Test the bot:
   - Add the bot to Slack channels: `/invite @YourBotName`
   - Post a message with a secret (e.g., `password=Secret123!`) or URL (e.g., `http://example.com`).
   - Run `/scan` in Slack to trigger a manual scan.
   - Check DMs for notifications about detected secrets or malicious content.

### 6. Run with Docker
1. Ensure Docker and Docker Compose are installed:
   ```bash
   docker --version
   docker-compose --version
   ```
2. Build the Docker image:
   ```bash
   docker-compose build
   ```
3. Start the container:
   ```bash
   docker-compose up -d
   ```
4. View logs:
   ```bash
   docker-compose logs -f
   ```
   - Look for output like:
     ```
     slack-bot  |  * Running on http://0.0.0.0:3000
     slack-bot  | [+] Running Slack Secret Scanner...
     slack-bot  | [+] Scan complete.
     ```
5. Expose the container to Slack using Ngrok (if local):
   ```bash
   ngrok http 3000
   ```
6. Test as described in the local execution section.
7. Stop the container:
   ```bash
   docker-compose down
   ```

## VirusTotal Integration
The `virus_total.py` module is included but may not be fully integrated. To enable VirusTotal scanning (e.g., for URLs or files):
1. Ensure `VIRUSTOTAL_API_KEY` is set in `.env`.
2. Update `app.py` to call VirusTotal functions in `run_scheduled_scan` (see code comments or documentation).
3. Test with messages containing URLs (e.g., `http://example.com`).

## Troubleshooting
- **Slack API Errors** (e.g., `missing_scope`):
  - Verify bot scopes in the Slack app settings and reinstall the app.
- **VirusTotal Errors**:
  - Check for `VIRUSTOTAL_API_KEY` in `.env`.
  - Look for API errors in logs (e.g., rate limits, invalid key).
- **No Messages Scanned**:
  - Ensure the bot is added to channels (`/invite @YourBotName`).
  - Check logs for errors in `get_recent_messages`.
- **Slash Command Fails**:
  - Confirm the Request URL is reachable (use Ngrok or a public server).
  - Verify `SLACK_SIGNING_SECRET` in `.env`.
- **Docker Issues**:
  - Ensure `requirements.txt` and `.env` are present.
  - Check logs with `docker-compose logs`.

## Contributing
1. Fork the repository.
2. Create a feature branch: `git checkout -b feature-name`
3. Commit changes: `git commit -m "Add feature"`
4. Push to the branch: `git push origin feature-name`
5. Open a pull request.

## License
MIT License. See [LICENSE](LICENSE) for details.
