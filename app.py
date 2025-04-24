import os
import time
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import threading
import schedule
from flask import Flask, request, make_response
from slack_sdk import WebClient
from slack_sdk.signature import SignatureVerifier
from dotenv import load_dotenv

# Internal modules
from scanner.secret_detector import scan_message_for_secrets
from scanner.utils import get_recent_messages, delete_message, send_user_dm
from scanner.virustotal import check_hash_virustotal  # Import VirusTotal scan function

# Load environment variables
load_dotenv()
SLACK_BOT_TOKEN = os.getenv("SLACK_BOT_TOKEN")
SLACK_SIGNING_SECRET = os.getenv("SLACK_SIGNING_SECRET")

# Initialize clients
client = WebClient(token=SLACK_BOT_TOKEN)
signature_verifier = SignatureVerifier(signing_secret=SLACK_SIGNING_SECRET)

# Flask app for manual trigger
app = Flask(__name__)

@app.route("/slack/commands", methods=["POST"])
def slash_commands():
    # Verify request signature
    if not signature_verifier.is_valid_request(request.get_data(), request.headers):
        return make_response("Invalid request", 403)

    payload = request.form
    # Handle /scan slash command
    if payload.get("command") == "/scan":
        user_id = payload.get("user_id")
        # Trigger a scan (manual)
        run_scheduled_scan()
        # Acknowledge in Slack
        return make_response("🕵️ Manual scan triggered! Check your DMs for details.", 200)
    return make_response("", 200)


def run_scheduled_scan():
    """
    Fetch recent messages, scan for secrets, delete if found, and DM users.
    """
    print("[+] Running Slack Secret Scanner...")
    messages = get_recent_messages(client)

    for msg in messages:
        user_id = msg['user']
        text = msg['text']
        ts = msg['ts']
        channel = msg['channel']

        findings = scan_message_for_secrets(text)

        # Optional VT scan for hash type
        for finding in findings:
            if finding["type"] == "hash":  # Only scan hashes with VirusTotal
                vt_result = check_hash_virustotal(finding["original"])
                if vt_result and vt_result["malicious"] > 0:
                    finding["summary"] += f" ⚠️ VT flagged as malicious ({vt_result['malicious']} engines)"

        if findings:
            delete_message(client, channel, ts)
            summary_lines = [f"• {f['summary']}" for f in findings]
            summary_text = "Secrets detected & removed:\n" + "\n".join(summary_lines)
            send_user_dm(client, user_id, summary_text)

    print("[+] Scan complete.")


def scheduler_thread():
    # Schedule daily scan
    schedule.every(24).hours.do(run_scheduled_scan)
    # Initial immediate run
    run_scheduled_scan()
    while True:
        schedule.run_pending()
        time.sleep(60)


if __name__ == "__main__":
    # Start scheduler in background thread
    thread = threading.Thread(target=scheduler_thread, daemon=True)
    thread.start()
    # Start Flask app to listen for slash commands
    app.run(host="0.0.0.0", port=3000)
