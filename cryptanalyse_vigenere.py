# Sorbonne Université 3I024 2023-2024
# TME 2 : Cryptanalyse du chiffre de Vigenere
#
# Etudiant.e 1 : Samaha Elio 21105733
# Etudiant.e 2 : NOM ET NUMERO D'ETUDIANT

import sys, getopt, string, math
from collections import Counter

# Alphabet français
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Fréquence moyenne des lettres en français
# À modifier
freq_FR = [1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]

def mean(li):
    return sum(li)/len(li)

def frequence(file):
    Occurences = {}
    with open(file, "r") as f:
        s = f.read().strip()

    Occurences = Counter(s)
    length = len(s)
    Occurences = {k:v/length for k,v in Occurences.items()}
    return Occurences

freq_FR = frequence("germinal_nettoye")
#print(freq_FR)


# Chiffrement César
def chiffre_cesar(txt, key):
    """
    chiffre par cesar chaque lettre du texte txt par la clef key et puis renvoie le texte chiffré regroupé ensemble.
    """
    return ''.join([chr((((ord(e) - ord("A")) + key) % 26) + ord("A")) if e.isupper() else chr((((ord(e) - ord("a")) + key) % 26) + ord("a")) for e in txt])

# Déchiffrement César
def dechiffre_cesar(txt, key):
    """
    déchiffre par cesar chaque lettre du texte txt par la clef key et puis renvoie le texte déchiffré regroupé ensemble.
    """
    return ''.join([chr((((ord(e) - ord("A")) - key) % 26) + ord("A")) if e.isupper() else chr((((ord(e) - ord("a")) - key) % 26) + ord("a")) for e in txt])


# Chiffrement Vigenere
def chiffre_vigenere(txt, key):
    """
    chiffre avc vigenere le texte "xxx" avec la clef key qui est une liste contenant chaque decalage de chque colonne : key[i] = decalage de ma colonne i"
    """
    res = ['' for _ in range(len(txt))]
    n = len(key)
    for j in range(n): # parcours les clef
        d = key[j] #prend la valeur de decalage
        i = j # commence a la bonne position selon l indice de la clef
        while i < len(txt):
            res[i] = chr((((ord(txt[i]) - ord("A")) + d) % 26) + ord("A"))
            i += n #saute de n car on chiffre ici colonne par colonne

    return "".join(res)

#Question N : pour repondre au question

# Déchiffrement Vigenere
def dechiffre_vigenere(txt, key):
    """
    dechiffre avc vigenere le texte "xxx" avec la clef key qui est une liste contenant chaque decalage de chque colonne : key[i] = decalage de ma colonne i"
    """
    res = ['' for _ in range(len(txt))]
    n = len(key)
    for j in range(n): # parcours les clef
        d = key[j] #prend la valeur de decalage
        i = j # commence a la bonne position selon l indice de la clef
        while i < len(txt):
            res[i] = chr((((ord(txt[i]) - ord("A")) - d) % 26) + ord("A"))
            i += n #saute de n car on chiffre ici colonne par colonne

    return "".join(res)

# Analyse de fréquences
def freq(txt):
    """
    rend la liste des occurences des lettre de l alphabet dans le texte txt
    """
    Occurences = Counter(txt)
    hist=[0.0]*len(alphabet)
    for i , lettre in enumerate(alphabet): # indice , lettre
        hist[i] = Occurences[lettre]
    return hist

# Renvoie l'indice dans l'alphabet
# de la lettre la plus fréquente d'un texte
def lettre_freq_max(txt):
    """
    donne  l indice de l element qui a le nombre d'occurence maximale
    """
    occ = freq(txt)
    m = max(occ)
    for i , l in enumerate(occ):
        if l == m:
            return i
    return -1

# indice de coïncidence
def indice_coincidence(hist):
    """
    rend l'indice de coincidence d'un texte avec hist comme occurence des lettres
    """
    n = sum(hist)
    return sum([(ni * (ni - 1))/(n*(n-1)) for ni in hist]) if n != 0 else -1

# Recherche la longueur de la clé
def longueur_clef(cipher):
    """
    donne la bonne longueur de la clef grace au IC
    """
    n = len(cipher)
    for key in range(1 , 21):
        if key != 0:
            li = [[] for _ in range(key)] # chaque element de la liste est une colonne 
            for ind , let in enumerate(cipher):
                li[ind % key].append(let)           #mettre les elements selon leur module avec key 
            li = ["".join(e) for e in li]   #conversion en liste de chaine de charactere
            IC = mean([indice_coincidence(freq(e)) for e in li]) #moyenne des IC pour chaque colonne
            if IC > 0.06 : 
                return key 
    return 0


# Renvoie le tableau des décalages probables étant
# donné la longueur de la clé
# en utilisant la lettre la plus fréquente
# de chaque colonne
def clef_par_decalages(cipher, key_length):
    """
    rend une liste contenant la clef i.e chaque element i de la liste est le decalage de la colonne i
    """
    decalages=[0]*key_length
    
    li = [[] for _ in range(key_length)] # chaque element de la liste est une colonne 
    for ind , let in enumerate(cipher):
        li[ind % key_length].append(let)           #mettre les elements selon leur module avec key 
    li = ["".join(e) for e in li]   #conversion en liste de chaine de charactere
    for i in range(key_length):
        decalages[i] = (lettre_freq_max(li[i]) - 4) % 26                # E ---> µ donc dec = µ - E mod 26  
        
    return decalages
     
# Cryptanalyse V1 avec décalages par frequence max
def cryptanalyse_v1(cipher):
    """
    Documentation à écrire
    """
    return "TODO"


################################################################


### Les fonctions suivantes sont utiles uniquement
### pour la cryptanalyse V2.

# Indice de coincidence mutuelle avec décalage
def indice_coincidence_mutuelle(h1,h2,d):
    """
    Documentation à écrire
    """
    return 0.0

# Renvoie le tableau des décalages probables étant
# donné la longueur de la clé
# en comparant l'indice de décalage mutuel par rapport
# à la première colonne
def tableau_decalages_ICM(cipher, key_length):
    """
    Documentation à écrire
    """
    decalages=[0]*key_length
    return decalages

# Cryptanalyse V2 avec décalages par ICM
def cryptanalyse_v2(cipher):
    """
    Documentation à écrire
    """
    return "TODO"


################################################################


### Les fonctions suivantes sont utiles uniquement
### pour la cryptanalyse V3.

# Prend deux listes de même taille et
# calcule la correlation lineaire de Pearson
def correlation(L1,L2):
    """
    Documentation à écrire
    """
    return 0.0

# Renvoie la meilleur clé possible par correlation
# étant donné une longueur de clé fixée
def clef_correlations(cipher, key_length):
    """
    Documentation à écrire
    """
    key=[0]*key_length
    score = 0.0
    return (score, key)

# Cryptanalyse V3 avec correlations
def cryptanalyse_v3(cipher):
    """
    Documentation à écrire
    """
    return "TODO"


################################################################
# NE PAS MODIFIER LES FONCTIONS SUIVANTES
# ELLES SONT UTILES POUR LES TEST D'EVALUATION
################################################################


# Lit un fichier et renvoie la chaine de caracteres
def read(fichier):
    f=open(fichier,"r")
    txt=(f.readlines())[0].rstrip('\n')
    f.close()
    return txt

# Execute la fonction cryptanalyse_vN où N est la version
def cryptanalyse(fichier, version):
    cipher = read(fichier)
    if version == 1:
        return cryptanalyse_v1(cipher)
    elif version == 2:
        return cryptanalyse_v2(cipher)
    elif version == 3:
        return cryptanalyse_v3(cipher)

def usage():
    print ("Usage: python3 cryptanalyse_vigenere.py -v <1,2,3> -f <FichierACryptanalyser>", file=sys.stderr)
    sys.exit(1)

def main(argv):
    size = -1
    version = 0
    fichier = ''
    try:
        opts, args = getopt.getopt(argv,"hv:f:")
    except getopt.GetoptError:
        usage()
    for opt, arg in opts:
        if opt == '-h':
            usage()
        elif opt in ("-v"):
            version = int(arg)
        elif opt in ("-f"):
            fichier = arg
    if fichier=='':
        usage()
    if not(version==1 or version==2 or version==3):
        usage()

    print("Cryptanalyse version "+str(version)+" du fichier "+fichier+" :")
    print(cryptanalyse(fichier, version))
    
if __name__ == "__main__":
   main(sys.argv[1:])
