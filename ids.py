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


NUM_REQUESTS_TO_CHECK = 10

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

# Fonction pour analyser les logs Apache en temps réel
def analyze_logs():

    counter = 0
    NUM_REQUESTS_TO_CHECK = 20
    with open(LOG_FILE_PATH, "r") as log_file, open(LOGMYSQL, "r") as log_file2:
        log_file.seek(0, os.SEEK_END) # Se place à la fin du fichier pour lire les nouvelles entrées
        log_file2.seek(0, os.SEEK_END)
        while True:
            line1 = log_file2.readline()
            if line1.find("<script>") > 0 :
               print("XSS trouvé")
               bodymail='XSS trouvé'
               sendmail(bodymail)

            line = log_file.readline()
#            print(line)
#            print(line1)
            if not line:
                time.sleep(0.5) # Attente de 1 seconde pour les nouvelles entrées de log
                continue
            # Extraction de l'adresse IP et du timestamp de l'entrée de log
            match = re.search(r"(\d+\.\d+\.\d+\.\d+).*\[(\d+/\w+/\d+:\d+:\d+:\d+)", line)
            if match:
                ip = match.group(1)
                timestamp_str = match.group(2)
                timestamp = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S")
                if ip not in BLACKLIST:

                    if line.find("%27") > 0 :
                       print("Injection sql détectée")
                       print("Adresse IP suspecte: ",ip)
                       bodymail='Injection SQL détecté'
                       sendmail(bodymail)
                       add_to_blacklist(ip)

                    # Vérification de conditions pour déterminer si l'adresse IP est suspecte
                    # Dans cet exemple, on considère comme suspectes les adresses IP qui ont plus de 10 requêtes en 5 secondes
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
                                    if line.find("Nikto") > 0 :
                                       print("Nikto détecté")
                                       print("Adresse IP suspecte: ",ip)
                                       bodymail='Nikto détecté'
                                       sendmail(bodymail)
                                       add_to_blacklist(ip)
                            else:
                                counter = 0
                                break
                    if suspicious:
                          print("Adresse IP suspecte détectée: ", ip)
                          bodymail='Adresse IP suspecte détectée et ip bannie :'+ ip
                          sendmail(bodymail)
                          add_to_blacklist(ip)

# Exécution du programme
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
