     ___ ____  ____
    |_ _|  _ \/ ___|
     | || | | \___ \
     | || |_| |___) |
    |___|____/|____/           Par Groupe 3   
    v1.0        


## IDS: Détection Injection SQL , Failles XXS , Outils (Nikto, Sqlmap) , BruteForce et DDOS avec Bannissement d'IP et envoi de mail à l'administrateur.

Notre IDS est fonctionnel avec apache et mysql. Il scan les fichiers de logs d'apache ainsi que celui de mysql pour détecter des vulnérabilités et des attaques malveillantes.

Apache : '/var/log/apache2/access.log'</br>
Mysql : '/var/log/mysql/mysql/log'</br>

![image](https://github.com/TFLR/IDS/assets/79453369/a6834b8c-a6c7-4f42-847b-80f628a66f6f)

Installation:
-------------

Requis:

- [Python2 >= 2.7 or Python >= 3.2](https://www.python.org) or [PyPy](https://pypy.org)
- python-setuptools, python-distutils or python3-setuptools for installation from source
- iptables
- apache2
- mysql-server

Activer les logs mysql:

SET GLOBAL general_log_file = "/var/log/mysql/mysql.log";</br>
SET GLOBAL general_log = 'ON';</br>

Exécution:

git clone https://github.com/TFLR/IDS.git</br>
cd IDS</br>
sudo python3 ids.py</br>

Configuration:

Le serveur SMTP</br>
L'email d'envoi</br>
L'email de reception est modifiable depuis le code.</br>
Emplacement fichiers de logs</br>
                                                                                                                   </br> Groupe 3
