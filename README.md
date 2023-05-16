     ___ ____  ____
    |_ _|  _ \/ ___|
     | || | | \___ \
     | || |_| |___) |
    |___|____/|____/           Par Groupe 3   
    v1.0        


## IDS: Détection Injection SQL , Failles XXS , Outils (Nikto, Sqlmap) , BruteForce et DDOS avec Bannissement d'IP.

Notre IDS est fonctionnel avec apache et mysql. Il scan les fichiers de logs d'apache ainsi que celui de mysql pour détecter des vulnérabilités et des attaques malveillantes.

Apache : '/var/log/apache2/access.log'
Mysql : '/var/log/mysql/mysql/log'

![image](https://github.com/TFLR/IDS/assets/79453369/a6834b8c-a6c7-4f42-847b-80f628a66f6f)

Installation:
-------------

Requis:
- [Python2 >= 2.7 or Python >= 3.2](https://www.python.org) or [PyPy](https://pypy.org)
- python-setuptools, python-distutils or python3-setuptools for installation from source

