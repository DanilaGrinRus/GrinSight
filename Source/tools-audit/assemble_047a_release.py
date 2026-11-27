"""Build the source deliverables from a commit and verify the upload manifest locally."""
import argparse
import hashlib
import os
from html.parser import HTMLParser
from pathlib import Path
import subprocess
import tempfile
from zipfile import ZipFile

VERSION = "GrinSight-0.4.7A"
BASE = "be41231cd7ab73f158f8219e3fc44d1c3fe781f6"
BINARIES = ("windows-x64-portable.exe", "windows-x64-setup.exe", "android-arm64.apk",
            "linux-amd64.deb", "linux-x86_64.rpm", "linux-x86_64.tar.gz", "macos-universal.dmg")
REPO = Path(__file__).resolve().parents[2]


def git(*args, **kwargs):
    return subprocess.run(["git", "-C", REPO, *args], check=True, **kwargs)


def value(*args, **kwargs):
    return git(*args, stdout=subprocess.PIPE, **kwargs).stdout.decode("ascii").strip()


def checksum(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


class DownloadLinks(HTMLParser):
    def __init__(self):
        super().__init__()
        self.assets = set()

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            href = dict(attrs).get("href") or ""
            prefix = "https://github.com/DanilaGrinRus/GrinSight/releases/download/v0.4.7A/"
            if href.startswith(prefix):
                self.assets.add(href[len(prefix):])


def verify_pages():
    expected = {VERSION + "-" + suffix for suffix in (*BINARIES, "source.zip")}
    expected.add("SHA256SUMS.txt")
    for page in (REPO / "site/index.html", REPO / "site/en/index.html"):
        links = DownloadLinks()
        links.feed(page.read_text(encoding="utf8"))
        if links.assets != expected:
            raise ValueError(f"release links in {page.name}: {sorted(links.assets ^ expected)}")


def write_upgrade_patch(work, commit, destination):
    # A text deletion or a reverse binary hunk would distribute the old signing password.
    signing_script = "Source/build-android.ps1"
    attributes = work / "patch-attributes"
    attributes.write_text(signing_script + " -diff\n", encoding="ascii")
    options = ("diff", "--no-ext-diff", "--binary", "--full-index", BASE, commit)
    git(*options, "--", ".", ":(exclude)" + signing_script, stdout=destination)
    signing_change = git("-c", f"core.attributesFile={attributes.as_posix()}", *options,
                         "--", signing_script, stdout=subprocess.PIPE).stdout
    if signing_change:
        marker = b"GIT binary patch\n"
        header, found, hunks = signing_change.partition(marker)
        forward, separator, _ = hunks.partition(b"\n\n")
        if not found or not separator or not forward.startswith((b"literal ", b"delta ")):
            raise ValueError("cannot isolate forward signing-script change")
        destination.write(header + marker + forward + separator)


def sources(folder, revision):
    commit = value("rev-parse", "--verify", revision + "^{commit}")
    with tempfile.TemporaryDirectory(dir=folder.parent) as tmp:
        work = Path(tmp)
        archive = work / (VERSION + "-source.zip")
        git("archive", "--format=zip", "-o", archive, commit)
        with ZipFile(archive) as payload:
            if payload.testzip() is not None:
                raise ValueError("source ZIP failed CRC verification")
            files = {name for name in payload.namelist() if not name.endswith("/")}
            tracked = {name.decode("utf8") for name in git("ls-tree", "-rz", "--name-only", commit,
                       stdout=subprocess.PIPE).stdout.split(b"\0") if name}
            if files != tracked:
                raise ValueError("source ZIP differs from committed inventory")
            for item in files:
                parts = item.lower().split("/")
                name = parts[-1]
                if (any(p in {".git", ".secrets", "target", "profiles", "gcloud-config"} for p in parts)
                        or name in {"profile.json", "ui.txt", "wallet.seed", ".env", "release-key"}
                        or name.endswith((".local.txt", "api_secret", ".keystore", ".pfx", ".p12",
                                          ".jks", ".sqlite", ".sqlite3", ".mdb", ".vault"))):
                    raise ValueError("private data path in source archive")
                if name.endswith((".pem", ".key")):
                    if not item.startswith("Source/chain/tips/tests/certs/") or (
                            value("rev-parse", f"{BASE}:{item}") != value("rev-parse", f"{commit}:{item}")):
                        raise ValueError("unexpected key/certificate file in source archive")
        patch = work / (VERSION + "-from-0.4.6.patch")
        with patch.open("wb") as dst:
            write_upgrade_patch(work, commit, dst)
        env = dict(os.environ, GIT_INDEX_FILE=str(work / "test.index"))
        git("read-tree", BASE, env=env)
        git("apply", "--cached", "--whitespace=nowarn", patch, env=env)
        if value("write-tree", env=env) != value("rev-parse", commit + "^{tree}"):
            raise ValueError("patch did not reconstruct the release tree")
        notes = work / "RELEASE-0.4.7A.md"
        with notes.open("wb") as dst:
            git("show", f"{commit}:Documents/{notes.name}", stdout=dst)
        for artifact in (archive, patch, notes):
            dest = folder / artifact.name
            if dest.exists() and checksum(dest) != checksum(artifact):
                raise FileExistsError("different source artifacts already in release folder")
            if not dest.exists():
                artifact.replace(dest)
    print("Source archive and 0.4.6 patch verified against", commit)


def manifest(folder):
    verify_pages()
    expected = {VERSION + "-" + s for s in (*BINARIES, "source.zip", "from-0.4.6.patch")}
    expected.add("RELEASE-0.4.7A.md")
    actual = {p.name for p in folder.iterdir() if p.name != "SHA256SUMS.txt"}
    if expected != actual:
        raise ValueError(f"incomplete or unexpected release inventory: {sorted(expected ^ actual)}")
    entries = []
    for name in sorted(expected):
        path = folder / name
        if not path.is_file() or path.is_symlink() or path.stat().st_size == 0:
            raise ValueError("missing or linked artifact: " + name)
        entries.append(checksum(path) + "  " + name)
    with tempfile.NamedTemporaryFile(mode="w", encoding="ascii", newline="\n",
                                     dir=folder.parent, delete=False) as dst:
        dst.write("\n".join(entries) + "\n")
    Path(dst.name).replace(folder / "SHA256SUMS.txt")
    for entry in (folder / "SHA256SUMS.txt").read_text(encoding="ascii").splitlines():
        digest, name = entry.split("  ", 1)
        if checksum(folder / name) != digest:
            raise ValueError("SHA-256 mismatch: " + name)
    print(f"Verified {len(entries)} release files")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("sources", "manifest"))
    parser.add_argument("folder", type=Path)
    parser.add_argument("--revision", default="HEAD")
    args = parser.parse_args()
    args.folder.mkdir(parents=True, exist_ok=True)
    if args.action == "sources":
        sources(args.folder.resolve(), args.revision)
    else:
        manifest(args.folder.resolve())
