"""Publish only verified assets of a stable GrinSight release, as whole documents."""
import asyncio
import base64
import hashlib
import json
import os
import re
import struct
import tempfile
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen

from telethon import TelegramClient, functions, types
from telethon.tl.tlobject import TLObject
from telethon.sessions import MemorySession

API = "https://api.github.com/repos/DanilaGrinRus/GrinSight/releases/"
BRIDGE = "https://grinsight-release-bot.nurlinec.workers.dev/mirror/v1"


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def bridge(release, action, **fields):
    manifest = {key: release[key] for key in ("id", "tag_name", "name", "body", "draft", "prerelease", "html_url", "published_at")}
    manifest["assets"] = [{key: asset[key] for key in ("id", "name", "digest", "size", "browser_download_url")}
                          for asset in release["assets"]]
    payload = json.dumps(dict(id=release["id"], release=manifest, action=action, **fields)).encode()
    req = Request(BRIDGE, data=payload, headers={
        "Content-Type": "application/json", "User-Agent": "GrinSight-release-mirror", "Authorization": "Bearer " + os.environ["MIRROR_KEY"].strip()})
    try:
        with build_opener(NoRedirect()).open(req, timeout=50) as response:
            return json.load(response)
    except HTTPError as exc:
        try:
            reason = json.load(exc).get("error")
        except ValueError:
            reason = None
        allowed = {"invalid release manifest", "stable release unavailable", "forbidden", "incomplete archive",
                   "invalid asset receipt", "conflicting receipt", "announcement edit rejected", "announcement not confirmed"}
        raise SystemExit(f"Mirror {action}: HTTP {exc.code} ({reason if reason in allowed else 'check Worker response'})") from None


def stable_release():
    rid, tag = os.getenv("RELEASE_ID"), os.getenv("RELEASE_TAG")
    path = str(int(rid)) if rid else "tags/" + quote(tag, safe="") if tag else "latest"
    headers={"User-Agent": "GrinSight-release-mirror"}
    if os.getenv("GITHUB_TOKEN"):
        headers["Authorization"]="Bearer " + os.environ["GITHUB_TOKEN"]
    with build_opener(NoRedirect()).open(Request(API + path, headers=headers), timeout=45) as response:
        release = json.load(response)
    if release["draft"] or release["prerelease"] or not release["assets"]:
        raise ValueError("Expected a published stable release with assets")
    return release


def download(asset, destination):
    url = asset["browser_download_url"]
    if not url.startswith("https://github.com/DanilaGrinRus/GrinSight/releases/download/"):
        raise ValueError("Unexpected asset origin")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", asset.get("digest") or ""):
        raise ValueError("Missing GitHub SHA-256")
    digest, count = hashlib.sha256(), 0
    with urlopen(Request(url, headers={"User-Agent": "GrinSight-release-mirror"}), timeout=120) as src, destination.open("wb") as out:
        if urlparse(src.url).scheme != "https":
            raise ValueError("Insecure release download")
        while chunk := src.read(1024 * 1024):
            count += len(chunk)
            if count > asset["size"]:
                raise ValueError("Oversized download")
            digest.update(chunk)
            out.write(chunk)
    if count != asset["size"] or "sha256:" + digest.hexdigest() != asset["digest"]:
        raise ValueError("GitHub asset size or SHA-256 mismatch")


def telegram_document_id(document):
    # TDLib persistent document ID, v4, with the file reference from uploadMedia.
    location = struct.pack("<ii", 5 | (1 << 25), document.dc_id)
    location += TLObject.serialize_bytes(document.file_reference)
    location += struct.pack("<qqBB", document.id, document.access_hash, 30, 4)
    packed = re.sub(b"\x00{1,255}", lambda m: bytes([0, len(m[0])]), location)
    return base64.urlsafe_b64encode(packed).rstrip(b"=").decode()


def telegram(method, fields):
    url = "https://api.telegram.org/bot" + os.environ["TELEGRAM_BOT_TOKEN"] + "/" + method
    req = Request(url, data=json.dumps(fields).encode(), headers={"Content-Type": "application/json"})
    try:
        with build_opener(NoRedirect()).open(req, timeout=60) as response:
            return json.load(response)["result"]
    except HTTPError as exc:
        reason = json.load(exc).get("description", "rejected")
        raise SystemExit(f"Telegram {method}: {reason}") from None


async def upload(client, chat, media_peer, asset, path):
    name = asset["name"]
    handle = await client.upload_file(str(path), file_name=name)
    media = types.InputMediaUploadedDocument(file=handle, mime_type="application/octet-stream",
            attributes=[types.DocumentAttributeFilename(name)], force_file=True)
    caption = name + "\nSHA-256: " + asset["digest"][7:]
    # Resolve a real peer in this MTProto session. uploadMedia only stores the
    # document; the single visible message is addressed to the archive below.
    uploaded = await client(functions.messages.UploadMediaRequest(peer=media_peer, media=media))
    doc = uploaded.document
    if doc.size != asset["size"]:
        raise ValueError("Telegram stored an unexpected document size")
    result = telegram("sendDocument", {"chat_id": chat, "document": telegram_document_id(doc),
                      "caption": caption, "disable_notification": True})
    sent = result.get("document", {})
    if str(result["chat"]["id"]) != chat or sent.get("file_name") != name or sent.get("file_size") != asset["size"]:
        raise RuntimeError("Telegram document receipt mismatch")
    return result["message_id"]


async def main():
    for key in ("TELEGRAM_API_ID", "TELEGRAM_API_HASH", "TELEGRAM_BOT_TOKEN", "MIRROR_KEY"):
        if not os.getenv(key):
            raise SystemExit("Missing Actions secret: " + key)
    release = stable_release()
    rid = release["id"]
    preflight = bridge(release, "preflight")
    status = bridge(release, "status")
    if status.get("retired"):
        print("Release is outside the two-release Telegram archive:", rid)
        return
    if all(status["files"].get(str(a["id"]), {}).get("digest") == a["digest"] for a in release["assets"]):
        complete = bridge(release, "finish")
        print("Archive verified without uploading; retained release IDs:", complete["kept"], "announcement", complete["announcement_message"])
        return
    if not re.fullmatch(r"-100[1-9]\d*", status["chat"]):
        raise ValueError("Expected a Telegram supergroup or channel")
    client = TelegramClient(MemorySession(), int(os.environ["TELEGRAM_API_ID"]), os.environ["TELEGRAM_API_HASH"],
                            receive_updates=False)
    await client.start(bot_token=os.environ["TELEGRAM_BOT_TOKEN"])
    try:
        me = await client.get_me()
        if not me.bot or me.username.lower() != preflight["bot"].lower():
            raise ValueError("Actions and Cloudflare must use the same release bot")
        archive_chat = telegram("getChat", {"chat_id": status["chat"]})
        media_peer = await client.get_input_entity(archive_chat.get("username") or "grinsightwallet")
        for asset in sorted(release["assets"], key=lambda a: a["size"]):
            if status["files"].get(str(asset["id"]), {}).get("digest") == asset.get("digest") and asset.get("digest"):
                continue
            name = asset["name"]
            if not name or "/" in name or "\\" in name or any(ord(c) < 32 for c in name):
                raise ValueError("Invalid release asset name")
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "payload"
                download(asset, path)
                mid = await upload(client, status["chat"], media_peer, asset, path)
            bridge(release, "save", mid=mid, asset_id=asset["id"], digest=asset["digest"])
            print("Archived verified asset", asset["id"], asset["size"], "bytes", flush=True)
        complete = bridge(release, "finish")
        print("Release announcement is ready:", rid, "message", complete["announcement_message"])
    finally:
        await client.disconnect()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except HTTPError as error:
        raise SystemExit(f"HTTP {error.code} from {urlparse(error.url).hostname}") from None
