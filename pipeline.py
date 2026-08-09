import os
import time
from imapclient import IMAPClient
from imapclient.exceptions import LoginError
import socket
import json
import base64
import imaplib
from logger import logg
import datetime
import tempfile
from tqdm import tqdm
from analyzers.extension_analyzer import analyze_bytes
from reports import build_combined_results, generate_report
import traceback
from analyzers.headers_chacker import analyse_raw_Headers

# stand alone functions ────────────────────────────────────────────────────────────

def path_creator(directory="mailState", filename="mailState.json"):
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, filename)
    return path


def write_json(data):
    path = path_creator()
    with tempfile.NamedTemporaryFile(prefix='temp_state',suffix='.json', delete=False,dir='mailState') as temp_state:
        temp_state.write(json.dumps(data, indent=2).encode('utf-8'))
        temp_state.flush()
        temp_dir = temp_state.name
    os.rename(temp_dir, path)


class EmailPipeline:
    def __init__(self, host, username, password, mailbox, backfill):
        self.server = None
        self.uidvalidity = 0
        self.uidnext = 0
        self.uid = 0
        self.host = host
        self.username = username
        self.password = password
        self.mailbox = mailbox
        self.backfill = backfill
        self.filename = None
        self.raw_bytes = None

# connection methods ────────────────────────────────────────────────────────────
    def connect(self):
        try:
            self.server = IMAPClient(self.host, ssl=True, port=993, timeout=600)
        except socket.gaierror as e:
            raise ConnectionError("Could not resolve host - check the address") from e
        except socket.timeout as e:
            raise ConnectionError("Time out: check your network or host") from e
        try:
            self.server.login(self.username, self.password)
            self.server.use_uid = True
        except LoginError:
            raise 
    def reconnect(self):
        wait = 30
        max_wait = 300
        while not self.is_connected():
            try:
                self.connect()
            except Exception:
                time.sleep(wait)
                wait = min(wait * 2, max_wait)
                logg.debug(f'retrying in {wait}')
    def is_connected(self):
        try:
            self.server.noop()   
            return True
        except Exception: 
            return False
    def select_mailbox(self):
        inbox = self.server.select_folder(self.mailbox, readonly=True)
        self.uidvalidity = inbox[b'UIDVALIDITY']
        self.uidnext     = inbox[b'UIDNEXT']
 
 # state methods ────────────────────────────────────────────────────────────
    def build_json(self):
            return {
                self.username:{
                    self.mailbox:{
                        "uidvalidity": 0,
                        "last_uid": 0,
                        "missed":[

                        ],
                    }
                }
            }

    def load_state(self):
        path = path_creator()
        if os.path.exists(path) and os.path.getsize(path) > 0:
            with open(path, "r") as f:
                data = json.load(f)
            data.setdefault(self.username, {}).setdefault(self.mailbox,{"uidvalidity": 0, "last_uid": 0,"missed":[]})
        else:
            data = self.build_json()
        return data

    def save_state(self):
        data = self.load_state()
        data[self.username][self.mailbox]["uidvalidity"] = self.uidvalidity 
        data[self.username][self.mailbox]["last_uid"]    = self.uid
        write_json(data)

    def add_missed_uid(self):
        failed_at = datetime.datetime.now().isoformat()
        missed_data = {"UID":self.uid, "failed_at":failed_at, "attempt":1}
        data = self.load_state()
        found = False
        for email in data[self.username][self.mailbox]["missed"]:
            if email["UID"] == self.uid:
                email["attempt"] += 1
                found = True
        if not found:
            data[self.username][self.mailbox]["missed"].append(missed_data)
        write_json(data)

    def remove_missed_uid(self):
        data = self.load_state()
        for email in data[self.username][self.mailbox]["missed"]:
            if email["UID"] == self.uid:
                data[self.username][self.mailbox]["missed"].remove(email)
                write_json(data)
                break

    def retry_missed(self):
        data = self.load_state()
        now = datetime.datetime.now()
        for email in data[self.username][self.mailbox]["missed"][:]:
            try:
                time_passed = now - datetime.datetime.fromisoformat(email["failed_at"]) 
                if email["attempt"] >=3:
                    logg.error(f"tried to process UID: {self.uid} 3 times, giving up")
                    original_uid = self.uid
                    self.uid = email["UID"]
                    self.remove_missed_uid()
                    self.uid = original_uid

                elif time_passed >= datetime.timedelta(hours=1):
                    logg.debug(f"retrying UID: {email['UID']}")
                    original_uid = self.uid
                    self.uid = email["UID"]
                    self.add_missed_uid() 
                    self.fetch_msg()
                    self.uid = original_uid
            except Exception as e:
                logg.debug(f"error while retrying UID {self.uid}:  {e}")

# fetch methods ────────────────────────────────────────────────────────────

    def flatten_structure(self,structure):
        flat = []
        if isinstance(structure, (tuple, list)):
            for item in structure:
                flat.extend(self.flatten_structure(item))
        else:
            flat.append(structure)
        return flat

    def get_attachment_name(self,flat):
        idx = flat.index(b'FILENAME')
        filename = flat[idx + 1].decode('utf-8')
        return filename
    def get_attachment_bytes(self,bodystructure):
        parts = bodystructure[0]
        for part_num,part in enumerate(parts, start=1):
            if len(part)>2 and isinstance(part[2], tuple) and part[2][0] == b'NAME':
                attachment = self.server.fetch([self.uid], [f'BODY[{part_num}]'])
                raw_bytes = attachment[self.uid][f'BODY[{part_num}]'.encode()]
                decoded_bytes = base64.b64decode(raw_bytes)
                return decoded_bytes
        return b''
    def fetch_msg(self):
        self.filename = None
        self.raw_bytes = None
        structure = self.server.fetch([self.uid], ['BODYSTRUCTURE'])
        bodystructure = structure[self.uid][b'BODYSTRUCTURE']
        flat = self.flatten_structure(bodystructure)
        headers = self.server.fetch([self.uid], ['BODY[HEADER]'])
        raw_headers = headers[self.uid][b'BODY[HEADER]']
        combined = build_combined_results(self.uid)

        if b'ATTACHMENT' in flat:
            self.filename = self.get_attachment_name(flat)
            self.raw_bytes = self.get_attachment_bytes(bodystructure)
            if self.filename:
                combined["attachment"] = analyze_bytes(self.filename, self.raw_bytes)
            print(type(combined), combined)
        combined["header_analysis"] = analyse_raw_Headers(raw_headers)
        generate_report(combined)
        logg.debug(f"processed file: {self.filename} in UID: {self.uid}")


# pipeline methods ────────────────────────────────────────────────────────────

    def idle_loop(self):
        while True:
            try:
                self.server.idle()
                logg.debug("idle mode") # this has to change
                responses = self.server.idle_check(timeout=600)
                self.server.idle_done()
                self.retry_missed()
                if responses and any(r[1] == b'EXISTS' for r in responses):
                    data = self.load_state()
                    self.uid = data[self.username][self.mailbox]["last_uid"]
                    self.search_new_messages()
            except KeyboardInterrupt:
                break
            except (imaplib.IMAP4.abort, OSError):
                        self.reconnect()
                        self.select_mailbox()
        self.server.idle_done()

    def search_new_messages(self):
        if self.backfill:
            self.uid = 0
        message_obj = self.server.search(['UID',f'{self.uid + 1}:*'])
        iterator = tqdm(message_obj, desc="Backfill progress", unit="msg") if self.backfill else message_obj

        last_processed = self.uid
        for new_uid in iterator:
            if new_uid > self.uid:
                self.uid = new_uid
                try:
                    self.fetch_msg()
                    self.save_state()
                    self.remove_missed_uid()
                    last_processed = self.uid
                    logg.debug(f"Processed UID {new_uid}")
                except Exception as e:
                    logg.error(f"failed to process UID {new_uid}: {e}")
                    logg.error(traceback.format_exc())
                    self.add_missed_uid() 
        self.uid = last_processed
        
    def run(self):
        self.connect()
        print("Connected")
        self.select_mailbox()
        data = self.load_state()
        is_new_user = data[self.username][self.mailbox]["last_uid"] == 0
        if is_new_user:
            self.uid = self.uidnext - 1
            self.save_state()
            self.search_new_messages()
            self.idle_loop()
        else:
            self.uid = data[self.username][self.mailbox]["last_uid"]
            self.search_new_messages()
            self.backfill = False
            self.idle_loop()
    

