import time
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

def get_recent_messages(client: WebClient, hours: int = 24) -> list:
    """
    Fetch messages from all joined channels within the past `hours` hours.
    Returns a list of dicts with keys: user, text, ts, channel.
    """
    messages = []
    now = time.time()
    oldest = now - hours * 3600

    try:
        # Fetch only channels the bot is a member of
        response = client.conversations_list(types="public_channel,private_channel", limit=1000)
        channels = response.get("channels", [])
    except SlackApiError as e:
        print(f"Error fetching channels: {e}")
        return messages

    for ch in channels:
        if not ch.get("is_member"):
            continue  # skip if bot is not in this channel

        # Optional: restrict to specific channels by name
        # Uncomment this block if you only want these:
        # allowed_names = {"alerts", "general", "random", "soar"}
        # if ch.get("name") not in allowed_names:
        #     continue

        channel_id = ch["id"]
        try:
            history = client.conversations_history(
                channel=channel_id,
                oldest=str(oldest),
                limit=1000
            )
        except SlackApiError as e:
            print(f"Error fetching history for channel {channel_id}: {e}")
            continue

        for msg in history.get("messages", []):
            if msg.get("user") and msg.get("text"):
                messages.append({
                    "user": msg["user"],
                    "text": msg["text"],
                    "ts": msg["ts"],
                    "channel": channel_id
                })

    return messages


def delete_message(client: WebClient, channel: str, timestamp: str) -> None:
    """
    Delete a message in a channel by timestamp.
    """
    try:
        client.chat_delete(channel=channel, ts=timestamp)
    except SlackApiError as e:
        print(f"Error deleting message {timestamp} in {channel}: {e}")


def send_user_dm(client: WebClient, user_id: str, text: str) -> None:
    """
    Send a direct message (DM) to a user.
    """
    try:
        # Open or retrieve an IM channel with the user
        conv = client.conversations_open(users=user_id)
        dm_channel = conv["channel"]["id"]
        client.chat_postMessage(channel=dm_channel, text=text)
    except SlackApiError as e:
        print(f"Error sending DM to user {user_id}: {e}")
