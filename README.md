# be-sudoku2
Kit de récupération des données (malware de test: SUDOKU)

__Commande__: antisudoku.exe  
__Environnement d'exécution__: Windows 10  

__IOCs recherchés__:  
-  chaine dans les fichiers chiffrés: "GPGcryptor"  
-  file md5 .exe: "52fb8ba70fbc1ba8f9d665f21929bb50"  
-  file md5 .txt: "94899f983b8547cabbcf3be49dd9d5d5"  

__Exemple d’exécution__ 
~~~
ANTISUDOKU: Restauration des fichiers chiffrés par le malware Sudoku.exe  
 (identifié par Windows Defender comme Trojan:Win32/Sprisky.U!cl)

Actions exécutées:
    - suppression de la valeur _SuDOkU_ de la clé de registre HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
    - suppression de toutes les copies du programme Sudoku.exe et de ses clones
    - suppression des fichiers texte de demande de rançon
    - déchiffrement des fichiers personnels

Point de départ pour le parcours des répertoires: C:\Users\IEUser\Downloads
_________________ log d'exécution ___________________
*.exe: suppression de C:\Users\IEUser\Downloads\16268-7772-24292_.exe
REG: clé _SuDOkU_ supprimée
*.exe: suppression de C:\Users\IEUser\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\22087-5158-24341_.exe
*.exe: suppression de C:\Users\IEUser\Downloads\Sudoku.exe
Cyphered: C:\Users\IEUser\Downloads\cantedvortex.png (461942)    TROUVE key= 11/03/2019-10:14:19:436
Cyphered: C:\Users\IEUser\Downloads\Facture FC0017 - AOUT 2018 - CL0001.pdf (35214)    TROUVE key= 11/03/2019-10:14:19:436
Cyphered: C:\Users\IEUser\Downloads\html.jpg (68254)    TROUVE key= 11/03/2019-10:14:19:436
Cyphered: C:\Users\IEUser\Downloads\pots.gif (470862)    TROUVE key= 11/03/2019-10:14:19:436
Cyphered: C:\Users\IEUser\Downloads\test1.xls (26142)    TROUVE key= 11/03/2019-10:14:19:436
Cyphered: C:\Users\IEUser\Downloads\test1.xlsx (8558)    TROUVE key= 11/03/2019-10:14:19:436

_________________  Statistiques   ___________________
Nombre de fichiers trouvés chiffrés                       6
Nombre de fichiers déchiffrés avec succès                 6
Nombre de répertoires parcourus                           1
Nombre de fichiers README.txt supprimés                   1
Nombre de copies du programme SUDOKU.exe supprimées       3
Nombre de fichiers qui n'ont pût être contrôlés (Erreurs) 0
~~~
