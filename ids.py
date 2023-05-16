import os
import subprocess
import re
import time
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Paramètres du serveur SMTP
smtp_server = 'smtp.gmail.com'
smtp_port = 587
smtp_username = 'projetcyberB3'
smtp_password = 'iyguuzzroxwpzgkd'

# Adresse de l'expéditeur et destinataire
from_email = 'projetcyberB3@gmail.com'
to_email = 'projetcyberB3@gmail.com'

# Chemin vers le fichier de logs Apache
LOG_FILE_PATH = "/var/log/apache2/access.log"
LOGMYSQL = "/var/log/mysql/mysql.log"
# Commande pour ajouter une adresse IP à la liste noire d'Iptables
IPTABLES_CMD = "sudo iptables -A INPUT -s {} -j DROP"

# Liste pour stocker les adresses IP suspectes
BLACKLIST = []

LASTBODYMAIL = ""

# Fonction pour ajouter une adresse IP à la liste noire d'Iptables
def add_to_blacklist(ip):
    if ip not in BLACKLIST:
        BLACKLIST.append(ip)
        # Exécute la commande Iptables pour ajouter l'adresse IP à la liste noire
        subprocess.run(IPTABLES_CMD.format(ip), shell=True)

def sendmail(bodymail):
     global LASTBODYMAIL
     message = MIMEMultipart()
     message['From'] = from_email
     message['To'] = to_email
     message['Subject'] = 'Alerte Intrusion'

     message.attach(MIMEText(bodymail))
     if LASTBODYMAIL != bodymail :
         with smtplib.SMTP(smtp_server, smtp_port) as server:
              server.starttls()
              server.login(smtp_username, smtp_password)
              server.sendmail(from_email, to_email, message.as_string())
              LASTBODYMAIL = bodymail
              
def DetectionXSS(s):
    ArrayXSS = ['<script>','</script>']
    XSS = False
    for a in ArrayXSS:
        if a in s.lower():
            XSS = True
            break
                    
    if XSS:
       print("XSS trouvé")
       bodymail='XSS trouvé'
       sendmail(bodymail)
       XSS = False
       
def DetectionSQL(s,ip):
    if s.find("%27") > 0 :
       print("Injection sql détectée")
       if s.find("sqlmap") > 0 :
          print("avec Sqlmap")
          print("Adresse IP suspecte: ",ip)
          add_to_blacklist(ip)
       bodymail='Injection SQL détecté'
       sendmail(bodymail)
       
def BanIp(ip):
    print("Adresse IP suspecte détectée: ", ip)
    bodymail='Adresse IP suspecte détectée et ip bannie :'+ ip
    sendmail(bodymail)
    add_to_blacklist(ip)
    
def DetectionNikto(s,ip):
    if s.find("Nikto") > 0 :
       print("Nikto détecté")
       print("Adresse IP suspecte: ",ip)
       bodymail='Nikto détecté'
       sendmail(bodymail)
       add_to_blacklist(ip)
       
# Fonction pour analyser les logs Apache en temps réel
def analyze_logs():
    counter = 0
    NUM_REQUESTS_TO_CHECK = 20
    with open(LOG_FILE_PATH, "r") as log_file, open(LOGMYSQL, "r") as log_file2:
        log_file.seek(0, os.SEEK_END) # Se place à la fin du fichier pour lire les nouvelles entrées
        log_file2.seek(0, os.SEEK_END)
        while True:
            line1 = log_file2.readline()
            DetectionXSS(line1)
            line = log_file.readline()
            if not line:
                time.sleep(0.5) # Attente de 0.5 seconde pour les nouvelles entrées de log
                continue
            # Extraction de l'adresse IP et du timestamp de l'entrée de log
            match = re.search(r"(\d+\.\d+\.\d+\.\d+).*\[(\d+/\w+/\d+:\d+:\d+:\d+)", line)
            if match:
                ip = match.group(1)
                timestamp_str = match.group(2)
                timestamp = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S")
                if ip not in BLACKLIST:
                    DetectionSQL(line,ip)
                    # Vérification de conditions pour déterminer si l'adresse IP est suspecte
                    suspicious = False
                    for entry in log_file.readlines():
                        entry_match = re.search(r"(\d+\.\d+\.\d+\.\d+).*\[(\d+/\w+/\d+:\d+:\d+:\d+)", entry)
                        if entry_match:
                            entry_ip = entry_match.group(1)
                            entry_timestamp_str = entry_match.group(2)
                            entry_timestamp = datetime.strptime(entry_timestamp_str, "%d/%b/%Y:%H:%M:%S")
                            if (ip == entry_ip) and (timestamp - entry_timestamp).seconds <= 2:
                                counter = counter + 1
                                if counter == NUM_REQUESTS_TO_CHECK:
                                    suspicious = True
                                    counter = 0
                                    DetectionNikto(line,ip)
                            else:
                                counter = 0
                                break
                    if suspicious:
                       BanIp(ip)

if __name__ == "__main__":
    try:
         print("  ___ ____  ____")
         print(" |_ _|  _ \/ ___| ")
         print("  | || | | \___ \ ")
         print("  | || |_| |___) | ")
         print(" |___|____/|____/ ")
         print(" \n Analyse en temps réel de l'application web ")
         analyze_logs()
    except KeyboardInterrupt:
        print("Arrêt du programme...")
