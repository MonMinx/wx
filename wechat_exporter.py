import os
import sys
import time
import logging
import struct
import binascii
import hashlib
import hmac
import datetime

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Check for required dependencies
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
except ImportError:
    logger.error("Missing dependency: cryptography")
    logger.error("Please install it using: pip install cryptography")
    sys.exit(1)

try:
    import pymem
    import pymem.process
    import pymem.pattern
except ImportError:
    pymem = None

try:
    import sqlite3
except ImportError:
    logger.error("Missing dependency: sqlite3")
    sys.exit(1)

class WeChatKeyExtractor:
    def __init__(self):
        self.pm = None
        self.module_base = None

    def connect(self):
        if not pymem:
            logger.warning("pymem not installed. Automatic key extraction disabled.")
            return False
        try:
            self.pm = pymem.Pymem("WeChat.exe")
            # Find WeChatWin.dll
            modules = list(self.pm.list_modules())
            for mod in modules:
                if mod.name.lower() == "wechatwin.dll":
                    self.module_base = mod.lpBaseOfDll
                    logger.info(f"Found WeChatWin.dll at 0x{self.module_base:X}")
                    return True
            logger.error("WeChatWin.dll not found in WeChat.exe")
            return False
        except Exception as e:
            logger.error(f"Failed to connect to WeChat: {e}")
            return False

    def get_key(self):
        if not self.connect():
            return None

        # Known offsets (Placeholder)
        known_offsets = [0x3E2B8D0, 0x3E2B8E0, 0x3275BE8]

        for offset in known_offsets:
            try:
                pointer_addr = self.module_base + offset
                key_struct_addr = self.pm.read_longlong(pointer_addr)
                key_bytes = self.pm.read_bytes(key_struct_addr, 32)
                if key_bytes and any(b != 0 for b in key_bytes):
                    logger.info(f"Potential key found at offset 0x{offset:X}")
                    return binascii.hexlify(key_bytes).decode('ascii')
            except Exception:
                continue
        logger.warning("Automatic key extraction failed with known offsets.")
        return None

class WeChatExporter:
    def __init__(self):
        self.key = None
        self.db_path = None
        self.out_dir = "output"
        if not os.path.exists(self.out_dir):
            os.makedirs(self.out_dir)

    def decrypt_db(self, encrypted_path, output_path):
        KEY_SIZE = 32
        DEFAULT_PAGESIZE = 4096
        KDF_ITER = 64000
        logger.info(f"Decrypting {encrypted_path}...")

        try:
            with open(encrypted_path, "rb") as f:
                salt = f.read(16)
                dk = hashlib.pbkdf2_hmac('sha1', self.key, salt, KDF_ITER, KEY_SIZE)

                with open(output_path, "wb") as out_f:
                    out_f.write(b"SQLite format 3\0")
                    out_f.write(b"\0" * (DEFAULT_PAGESIZE - 16))

                    f.seek(0)
                    page_no = 0
                    while True:
                        page_data = f.read(DEFAULT_PAGESIZE)
                        if len(page_data) < DEFAULT_PAGESIZE: break
                        page_no += 1

                        if page_no == 1:
                            iv = page_data[16:32]
                            encrypted_part = page_data[32:-48]
                        else:
                            iv = page_data[:16]
                            encrypted_part = page_data[16:-48]

                        cipher = Cipher(algorithms.AES(dk), modes.CBC(iv), backend=default_backend())
                        decryptor = cipher.decryptor()
                        decrypted_part = decryptor.update(encrypted_part) + decryptor.finalize()

                        if page_no == 1:
                            out_f.seek(0)
                            out_f.write(b"SQLite format 3\0")
                            out_f.write(decrypted_part)
                        else:
                            out_f.write(decrypted_part)

                        current_pos = out_f.tell()
                        pad = (page_no * DEFAULT_PAGESIZE) - current_pos
                        if pad > 0: out_f.write(b"\0" * pad)
            logger.info(f"Decryption complete. Output: {output_path}")
            return True
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return False

    def export_chat(self, cursor, talker_id):
        # Determine table name (MSG or message)
        table_name = "MSG"
        try:
            cursor.execute("SELECT count(*) FROM MSG")
        except sqlite3.OperationalError:
            table_name = "message"

        logger.info(f"Exporting chat for {talker_id} from table {table_name}...")

        query = f"""
            SELECT IsSender, Type, StrContent, CreateTime, StrTalker
            FROM {table_name}
            WHERE StrTalker = ? OR StrTalker LIKE ?
            ORDER BY CreateTime ASC
        """
        # Note: StrTalker might be the group ID.

        try:
            cursor.execute(query, (talker_id, talker_id))
            rows = cursor.fetchall()
        except Exception as e:
            logger.error(f"Query failed: {e}")
            return

        messages = []
        for is_sender, msg_type, content, create_time, str_talker in rows:
            # Handle Group Chat Sender
            sender = "Me" if is_sender else str_talker
            clean_content = content

            # If group chat, content usually starts with "wxid_...:\n"
            if not is_sender and str_talker.endswith("@chatroom"):
                if content and ":\n" in content[:30]: # Heuristic check
                    parts = content.split(":\n", 1)
                    if len(parts) == 2:
                        sender = parts[0]
                        clean_content = parts[1]

            # Format Time
            try:
                dt = datetime.datetime.fromtimestamp(create_time)
                time_str = dt.strftime("%Y-%m-%d %H:%M:%S")
            except:
                time_str = str(create_time)

            # Handle Types
            if msg_type == 1: # Text
                pass
            elif msg_type == 3: # Image
                clean_content = "[Image]"
            elif msg_type == 34: # Voice
                clean_content = "[Voice]"
            elif msg_type == 47: # Emoji
                clean_content = "[Emoji]"
            else:
                clean_content = f"[Type {msg_type} Message]"

            messages.append({
                "time": time_str,
                "sender": sender,
                "content": clean_content
            })

        # Write to File
        # Text Format
        txt_path = os.path.join(self.out_dir, f"{talker_id}.txt")
        with open(txt_path, "w", encoding="utf-8") as f:
            for m in messages:
                f.write(f"{m['sender']}--{m['content']}\n") # Requested Format: A--Hello
        logger.info(f"Saved text to {txt_path}")

        # HTML Format
        html_path = os.path.join(self.out_dir, f"{talker_id}.html")
        with open(html_path, "w", encoding="utf-8") as f:
            f.write("<html><head><meta charset='utf-8'><style>")
            f.write(".msg { margin: 10px; padding: 10px; border-radius: 5px; }")
            f.write(".sender { font-weight: bold; color: blue; }")
            f.write("</style></head><body>")
            for m in messages:
                f.write(f"<div class='msg'><span class='sender'>{m['sender']}</span>: {m['content']} <span style='font-size:0.8em;color:grey'>({m['time']})</span></div>")
            f.write("</body></html>")
        logger.info(f"Saved HTML to {html_path}")

    def run(self):
        logger.info("Starting WeChat Exporter...")

        # 1. Get Key
        extractor = WeChatKeyExtractor()
        key_hex = extractor.get_key()

        if key_hex:
            logger.info(f"Key detected: {key_hex[:6]}...{key_hex[-6:]}")
            self.key = bytes.fromhex(key_hex)
        else:
            print("\n" + "="*50)
            print("Could not auto-detect key.")
            print("Please enter the 64-character hex key manually.")
            print("You can retrieve it using tools like 'pywx-dump' or 'GetWeChatKey'.")
            print("="*50 + "\n")
            key_input = input("Enter Key (Hex): ").strip()
            if key_input:
                try:
                    self.key = bytes.fromhex(key_input)
                except ValueError:
                    logger.error("Invalid hex string.")
                    return
            else:
                logger.error("No key provided. Exiting.")
                return

        # 2. Get DB Path
        print("\nPlease enter the path to the decrypted DB or the encrypted .db file.")
        db_path = input("DB Path: ").strip().strip('"')

        if not os.path.exists(db_path):
            logger.error("File not found.")
            return

        self.db_path = db_path

        # Check if encrypted
        with open(db_path, "rb") as f:
            header = f.read(16)

        if header != b"SQLite format 3\0":
            decrypted_path = os.path.join(self.out_dir, "decrypted.db")
            if self.decrypt_db(db_path, decrypted_path):
                self.db_path = decrypted_path
            else:
                return

        # 3. Connect and Parse
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # List Top Chats
            table_name = "MSG"
            try:
                cursor.execute("SELECT count(*) FROM MSG")
            except:
                table_name = "message"

            print(f"\nScanning table {table_name} for chats...")
            cursor.execute(f"SELECT StrTalker, count(*) as c FROM {table_name} GROUP BY StrTalker ORDER BY c DESC LIMIT 10")
            chats = cursor.fetchall()

            print("Top Chats found:")
            for i, (talker, count) in enumerate(chats):
                print(f"{i+1}. {talker} ({count} messages)")

            choice = input("\nSelect chat number to export (or type exact Talker ID): ")

            target_talker = None
            if choice.isdigit() and 1 <= int(choice) <= len(chats):
                target_talker = chats[int(choice)-1][0]
            else:
                target_talker = choice

            if target_talker:
                self.export_chat(cursor, target_talker)
            else:
                logger.error("Invalid selection.")

            conn.close()

        except Exception as e:
            logger.error(f"Database error: {e}")

if __name__ == "__main__":
    exporter = WeChatExporter()
    exporter.run()
