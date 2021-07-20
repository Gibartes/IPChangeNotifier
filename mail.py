# python -m pip install pypiwin32
# python -m pip install wim

from win32 import win32crypt
import wmi

import win32api
import win32con
import win32evtlog
import win32security
import win32evtlogutil

import copy
import hashlib
import json
import time
import random
import signal
import string
import os, sys, re
import requests, smtplib 
from email.mime.text import MIMEText
from multiprocessing import Process


class REPORT_CONSTANT(object):
    CONFIGURATION = {
        "IP_ADDR_PROVIDER": "http://jsonip.com",
        "IP_ADDR_PROVIDER_RESPONSE_TYPE" : "json",
        "IP_ADDR_PROVIDER_IP_ATTR_NAME"  : "ip",
        "SENDER_INFO_PATH" : "{0}".format(os.path.dirname(__file__) + os.sep + "host.bin"),
        "TARGET_INFO_PATH" : "{0}".format(os.path.dirname(__file__) + os.sep + "admin.bin"),
        "TIME_DELTA": 300,
        "TITLE"  :   "[Report] Your ip address was changed.",
        "MESSAGE": "Your ip address was changed. Your current ip address is #{ip} at #{time}"
    }

    EVENT_ID = {
        58701 : [win32evtlog.EVENTLOG_INFORMATION_TYPE, ["Initialize new email sender process",""]],
        58702 : [win32evtlog.EVENTLOG_INFORMATION_TYPE, ["Transport success"]],
        58703 : [win32evtlog.EVENTLOG_ERROR_TYPE, ["Connection disabled"]],
        58704 : [win32evtlog.EVENTLOG_WARNING_TYPE, ["Configuration changed"]],
        58705 : [win32evtlog.EVENTLOG_INFORMATION_TYPE, ["Service exit"]],
        58706 : [win32evtlog.EVENTLOG_WARNING_TYPE, ["Detect improper access"]],
        58799 : [win32evtlog.EVENTLOG_WARNING_TYPE, ["Missing event"]]
    }

class SecureMailSender(object):
    SALT_LENGTH = 24

    @staticmethod
    def randstring(text):
        return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(SecureMailSender.SALT_LENGTH)) + "||" +  \
                text + "||" + ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(SecureMailSender.SALT_LENGTH))

    @staticmethod
    def build_credential_to_json(cred):
        if(isinstance(cred, dict)):
            return json.dumps(cred)
        return None

    @staticmethod
    def encrypt_credential(path, text):
        if(path != None):
            if(os.path.exists(path)):
                os.remove(path)
            with open(path, "wb") as file:
                file.write(win32crypt.CryptProtectData(SecureMailSender.randstring(text).encode('utf-8'), None, None, None, None, 0))
            return b''
        return win32crypt.CryptProtectData(SecureMailSender.randstring(text).encode('utf-8'), None, None, None, None, 0)

    @staticmethod
    def generateHostID():
        c = wmi.WMI()
        seed = "{0}{1}".format(c.Win32_Processor()[0].ProcessorId, c.Win32_DiskDrive()[0].SerialNumber)
        return hashlib.sha256(seed.encode()).hexdigest()
    
    @staticmethod
    def decrypt_credential(path, text = None):
        result  = ('', b'')
        if(path != None):
            if(os.path.exists(path)):
                with open(path, "rb") as file:
                    line = file.read()
                    result = win32crypt.CryptUnprotectData(line, None, None, None, 0)
        else:
            result = win32crypt.CryptUnprotectData(text, None, None, None, 0)
        return result[-1].decode('utf-8').split("||")[1]

    @staticmethod
    def send_mail(sender, receiver, subject, body):
        credential = json.loads(sender)
        if(credential["mac"]!=SecureMailSender.generateHostID()):
            return (False, None)
        try:
            smtp = smtplib.SMTP(credential["server"], credential["port"])
            smtp.ehlo()
            smtp.starttls()	# TLS
            smtp.login(credential["email"], credential["key"])
            msg  = MIMEText(body)
            msg['Subject'] = subject
            msg['To'] = receiver
            smtp.sendmail(credential["email"],receiver,msg.as_string())
            smtp.quit()
        except Exception as e:
            del credential
            return (False, e)
        del credential
        return (True, None)

    @staticmethod
    def send_mail_s(sender, receiver, subject, body):
        credential = json.loads(sender)
        recv_accnt = json.loads(receiver)

        if(credential["mac"]!=SecureMailSender.generateHostID()):
            return (False, -1)

        try:
            smtp = smtplib.SMTP(credential["server"], credential["port"])
            smtp.ehlo()
            smtp.starttls()	# TLS
            smtp.login(credential["email"], credential["key"])
            msg  = MIMEText(body)
            msg['Subject'] = subject
            msg['To'] = recv_accnt["email"]
            smtp.sendmail(credential["email"], recv_accnt["email"], msg.as_string())
            smtp.quit()
        except Exception as e:
            del credential
            return (False, e)
        del credential
        return (True, None)


class EventLogger(object):
    def __init__(self, name, opcode):
        ph  = win32api.GetCurrentProcess()
        th  = win32security.OpenProcessToken(ph, win32con.TOKEN_READ)
        self.__sid = win32security.GetTokenInformation(th, win32security.TokenUser)[0]
        self.__opcode = opcode
        self.applicationName = name

    def __report(self, eventID, message):
        win32evtlogutil.ReportEvent(self.applicationName, eventID, eventCategory = 5, 
                                    eventType = REPORT_CONSTANT.EVENT_ID.get(eventID, 58799)[0], 
                                    strings = message, data = "Application\0Data".encode("ascii"), sid = self.__sid)
    
    def log_write(self, eventID, message):
        msg = REPORT_CONSTANT.EVENT_ID.get(eventID, 58799)[1]
        if(type(message)==str):
            msg += [message]
        else:
            msg += message
        if(self.__opcode == False):
            print(msg)
        else:
            self.__report(eventID, msg)

class IpNotifier(Process):
    def __init__(self, opcode):
        Process.__init__(self)

        self.__CONFIG = None
        self.__read_config()
        self.__logger = None
        self.__opcode = opcode
        self.__logger = EventLogger("IpNotifier", self.__opcode)
        
        self.__transTable = {
            "#{ip}" : "127.0.0.1",
            "#{time}" : time.ctime()
        }

    def __read_config(self):
        master =  os.path.dirname(__file__) + os.sep + "config.conf"
        self.__CONFIG = copy.deepcopy(REPORT_CONSTANT.CONFIGURATION)
        if(os.path.exists(master)==False):
            with open(master, "w") as file:
                file.write(json.dumps(REPORT_CONSTANT.CONFIGURATION, indent=4))
            return
        try:
            with open(master, "r") as file:
                self.__CONFIG = json.load(file)
            self.__CONFIG["TIME_DELTA"] = int(self.__CONFIG["TIME_DELTA"])
            if(self.__CONFIG["TIME_DELTA"] < 60):
                self.__CONFIG["TIME_DELTA"] = 300
        except:
            return

    def __update_table(self, ip):
        self.__transTable.update({"#{ip}": ip})
        self.__transTable.update({"#{time}": time.ctime()})

    def get_ip_address(self):
        if(self.__CONFIG["IP_ADDR_PROVIDER_RESPONSE_TYPE"].lower() == "json"):
            try:
                return (True, requests.get(self.__CONFIG["IP_ADDR_PROVIDER"]).json()[self.__CONFIG["IP_ADDR_PROVIDER_IP_ATTR_NAME"]])
            except Exception as e:
                return (False, e)
        return (False, 0)

    def write_form(self, sender, receiver, title, body):
        SecureMailSender.send_mail_s(sender, receiver, title, body)

    def register(self):
        if(os.path.exists(self.__CONFIG["SENDER_INFO_PATH"]) == False):
            sender_info = dict.fromkeys(['mac','server','email','key','port'])
            sender_info.update({"mac": str(SecureMailSender.generateHostID()).strip()})
            sender_info.update({"email": str(input("Enter your email account:\n")).strip()})
            sender_info.update({"key": str(input("Enter your app key to login your email account:\n")).strip()})
            sender_info.update({"server": str(input("Enter your SMTP server:\n"))})
            u = str(input("Enter SMTP server port:\n")).strip()
            sender_info.update({"port": int(u) if u.isdigit() and int(u) in range(1, 65536) else 587})
            SecureMailSender.encrypt_credential(self.__CONFIG["SENDER_INFO_PATH"], 
                SecureMailSender.build_credential_to_json(sender_info))
            self.__logger.log_write(58704, "New sender is registered.")
        if(os.path.exists(self.__CONFIG["TARGET_INFO_PATH"]) == False):
            recv_info = dict.fromkeys(['mac','server','email','key','port'], ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(SecureMailSender.SALT_LENGTH)))
            recv_info.update({"email": str(input("Enter listener's email account:\n")).strip()})
            SecureMailSender.encrypt_credential(self.__CONFIG["TARGET_INFO_PATH"], 
                SecureMailSender.build_credential_to_json(recv_info))
            self.__logger.log_write(58704, "New listener is registered.")

    def begin(self):
        pattern  = re.compile("|".join(map(re.escape,self.__transTable.keys())))
        sender   = ""
        receiver = ""
        current  = ""

        while(True):
            ip = self.get_ip_address()
            if(ip[0] == False):
                message = "[!] IP notifier is currently unable to obtain external IP addresses from [{0}]".format(self.__CONFIG["IP_ADDR_PROVIDER"])
                self.__logger.log_write(58703, message)
                break

            if(ip[1] != current):
                try:
                    sender   = SecureMailSender.decrypt_credential(self.__CONFIG["SENDER_INFO_PATH"])
                    receiver = SecureMailSender.decrypt_credential(self.__CONFIG["TARGET_INFO_PATH"])
                except:
                    message = "[!] Credentials are corrupted."
                    self.write_form(sender, receiver, "[!] Credentials are corrupted.", message)
                    self.__logger.log_write(58706, message)
                    break
                
                current = ip[1]
                self.__update_table(ip[1])
                title  = pattern.sub(lambda match: self.__transTable[match.group(0)], self.__CONFIG["TITLE"])
                body   = pattern.sub(lambda match: self.__transTable[match.group(0)], self.__CONFIG["MESSAGE"])
                r, e  = SecureMailSender.send_mail_s(sender, receiver, title, body)
                if(r == False and e == -1):
                    message = "[!] Credentials are corrupted."
                    self.write_form(sender,receiver, "[!] Credentials are corrupted.", message)
                    self.__logger.log_write(58706, message)
                    break
                elif(r == False):
                    message = "[!] An error has occurred: {0}".format(e)
                    self.__logger.log_write(58799, message)
                else:
                    self.__logger.log_write(58702, "")
            time.sleep(self.__CONFIG["TIME_DELTA"])

        self.__logger.log_write(58705, "")

    def run(self):
        self.register()
        self.begin()

if __name__ == "__main__":
    def signal_handler(signal, frame):
        sys.exit(0)
    signal.signal(signal.SIGINT, signal_handler)

    iNot = IpNotifier(True)
    iNot.register()
    iNot.begin()

    sys.exit(0)