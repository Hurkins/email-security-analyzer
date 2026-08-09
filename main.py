import os
import json
import argparse
import tempfile
import getpass
import questionary
from imapclient.exceptions import LoginError
from pipeline import path_creator, EmailPipeline
import datetime

def build_config():
   return{
        "Email": None,
        "Provider": None,
        "Mailbox": None,
    }
    
def load_config():
    path = path_creator("config", "config.json")
    if os.path.exists(path) and os.path.getsize(path) > 0:
        with open(path, "r") as c:
            data = json.load(c)
    else:
        data = build_config()
    return data

def save_config(email_addr, provider, mailbox):
    data = load_config()
    path = path_creator("config", "config.json")
    data["Email"] = email_addr
    data["Provider"] = provider
    data["Mailbox"] = mailbox
    with tempfile.NamedTemporaryFile(prefix='temp_cofig',suffix='.json', delete=False,dir='config') as temp_cofig:
        temp_cofig.write(json.dumps(data, indent=2).encode('utf-8'))
        temp_cofig.flush()
        temp_dir = temp_cofig.name
    data = os.rename(temp_dir, path)
    return data

def setup():
    data = load_config()
    email_addr = questionary.text("Enter your email address:",default=data["Email"] or "").ask()

    providers = {
        "Gmail":"imap.gmail.com",
        "Outlook":"outlook.office365.com"
    }

    reverse_proveders = {v: k for k, v in providers.items()}
    current_provider = reverse_proveders.get(data["Provider"], "Other")

    provider = questionary.select(
        "Select your email provider:",
        choices=["Gmail", "Outlook", "Other"],default=current_provider
    ).ask()
    if provider == "Other":
        provider = questionary.text("Enter your IMAP host:").ask()
    elif provider in providers:
        provider = providers[provider]

    emailbox = questionary.text("Mailbox to monitor:", default=data["Mailbox"] or "").ask()
    save_config(email_addr, provider, emailbox)
    

def main():
    try:
        counter = 0
        parser = argparse.ArgumentParser(description='Email Security Analyser')
        parser.add_argument('--setup', action='store_true', help='Configure email settings')
        parser.add_argument('--backfill', action='store_true', help='Process all previous emails')
        args = parser.parse_args()

        if args.setup:
            setup()

        config = load_config()
        if config["Email"] is None:
            print("No user configured. Run with --setup to get started")
            return
        password = getpass.getpass("Enter your app password: ")
        while not password:
            print("Empty password")
            password = getpass.getpass("Enter your app password: ")
        print(f"Connecting to {config['Provider']} as {config['Email']}....")
        try:
            pipeline = EmailPipeline(
                host=config["Provider"],
                username=config["Email"],
                password=password,
                mailbox=config["Mailbox"],
                backfill=args.backfill
            )
            pipeline.run()
        except LoginError as e:
            while counter < 3:
                print("Invalid credentails")
                password = getpass.getpass("Enter your app password: ")
                counter += 1
                try:
                    pipeline = EmailPipeline(
                        host=config["Provider"],
                        username=config["Email"],
                        password=password,
                        mailbox=config["Mailbox"],
                        backfill=args.backfill
                    )
                    pipeline.run()
                    break  
                except LoginError:
                    continue
            else:
                print("Too many failed attempts — exiting")
    except KeyboardInterrupt:
        return
main()