# Sorbonne Université 3I024 2023-2024
# TME 2 : Cryptanalyse du chiffre de Vigenere
#
# Etudiant 1 : Samaha Elio 21105733

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
    hist=[0.0]*len(alphabet)
    for i , lettre in enumerate(alphabet): # indice , lettre
        hist[i] = Occurences[lettre]
    return hist

freq_FR = frequence("germinal_nettoye")


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
    cryptanalyse et dechiffre le message par la methode suivante : On trouve la longeur de clef avec la meilleure IC puis on trouve le decalage de chaque colonne 
    """
    key_length = longueur_clef(cipher)
    key = clef_par_decalages(cipher , key_length)

    return dechiffre_vigenere(cipher , key)

#Question 9 : 18 tests avec success parmi 100, c'est faible pour plusieurs raisons : on a pas toujours forcement un lien direct entre la frequence max de la lettre dans le cipher et le e 
# car ce sont des statistiques faites sur un grand ensemble de donnés donc pour de petits textes cela ne reste pas vraie.
# (de meme qu on peut avoir plusieurs lettre de frequence max et nous on prend la plus petite.. pas toujours vraie). De meme il se peut que la clef soit de longueure plus grand que 20
# vu que prendre la plus petite clef qui donne une IC plus grande que 0.06 ne soit pas toujours la bonne solution mais entrainera que ces multiples auront une bonne valeure aussi 
# (ex : si on a un bon IC pour 7 on aura pour 14 mais si 21 ne donne pas une bonne IC mais 28 le donne donc 14 est meilleur que 7, un cas qu on ne prend pas en compte). <--- A verifier !!

################################################################


### Les fonctions suivantes sont utiles uniquement
### pour la cryptanalyse V2.


# Indice de coincidence mutuelle avec décalage
def indice_coincidence_mutuelle(h1,h2,d):
    """
    decale les elements de h2 par *d* indices et renvoie l'ICM de h1 et h2 (h1 : List , h2 : List , contenant les occurances des lettres du texte 1 et 2)  
    """
    h2 = [h2[(i+d)%26] for i in range(len(h2))] #texte2 décalé de d positions
    n1 , n2 = sum(h1) , sum(h2)
    return sum([(n1i * n2i) for n1i , n2i in zip(h1 , h2)])/(n1*n2) if (n1 != 0 and n2 != 0) else -1 #formule du cours

# Renvoie le tableau des décalages probables étant
# donné la longueur de la clé
# en comparant l'indice de décalage mutuel par rapport
# à la première colonne
def tableau_decalages_ICM(cipher, key_length):
    """
    a partir de la taille de la cle et du message chiffré, rend le tableau de de decalage de chaque colonne a partir de la premiere ( d0 - di = decalage[i])
    """
    decalages=[0]*key_length
    li = [[] for _ in range(key_length)] # chaque element de la liste est une colonne 
    for ind , let in enumerate(cipher):
        li[ind % key_length].append(let)           #mettre les elements selon leur module avec key 
    li = ["".join(e) for e in li]   #conversion en liste de chaine de charactere
    f0 = freq(li[0])
    for i in range(1 , key_length):
        tab = [indice_coincidence_mutuelle(f0 , freq(li[i]) , d) for d in range(26)]
        decalages[i] = tab.index(max(tab))
    return decalages

# Cryptanalyse V2 avec décalages par ICM
def cryptanalyse_v2(cipher):
    """
    dechiffre le texte cipher en retrouvant la taille de la clé puis trouver le decalage de chaque colonne par rapport a la 1ere en qui maximise l'ICM 
    entre d0 et di puis on trouve le texte chiffré par le decalage de d0 et on trouve d0 par analyse de frequence de ce texte. 
    """
    n = len(cipher)

    key_length = longueur_clef(cipher) # longueur de la clef deduite avec l'indice de coincidence
    decalage = tableau_decalages_ICM(cipher, key_length) # tableau des decalages de chaque colonne par rapport a la premiere (en utilisant l'ICM)
    
    
    cesar = "" 
    i = 0
    for c in cipher:
        cesar += chr((ord(c) - decalage[i%key_length] - ord('A') ) % 26 +ord('A') ) #on reconstruit le texte chiffré decalé de d0 en faisant le bon dacalage selon son emplacement dans le texte
        i += 1
    
    """
    li = [[cipher[i + k] for k in range(n//key_length + 1) if i+k < n] for i in range(key_length)] #on a une liste des colonnes
    cesar = [dechiffre_cesar(li[i], decalage[i]) for i in range(key_length)] #on decale chaque colonne pour obtenir un texte proche avec le la 1ere colonne
    cesar = "".join(transpose(cesar)) #on transpose la matrice obtenu et on la colle ensemble pour mettre les lignes bout a bout 
    """

    res = dechiffre_cesar(cesar, (lettre_freq_max(cesar) - 4) % 26)

    return res

#Question 12 : 43/100 success. On voit maintenant une amélioration par rapport a ce qu'on a vu avec v1 (18/100) car on a reglé quelques problemes. 
# Deja l outil pour trouver la taille de la clef reste le meme mais ce qui change c est que des qu on trouve la taille de la clef avec v1 on ne fait 
# que prendre la lettre de frequence max comme le chiffré de 'e' et on trouve la clef or dans v2 c est un peu plus poussé : on regarde plus de combinaison possible pour les clefs de chiffrement 
# car on est en train de lié le decalage d'une colonne par rapport a l'autre i.e les colonnes ne sont plus independante (d0 - di = decalage[i]).
# En effet on essaye de maximiser l'ICM par rapport a la 1ere colonne et donc on calcule plusieurs ICM qui fait que la possibilite d erreur et plus petite par rapport a v1.
# De plus on reduit l erreur car on n'utilise qu une seule fois la fonction dechiffre_cesar qui s'appuie sur l analyse de frequence qu on a vu qui n est pas fiable 
# surtout si le texte est court (on applique dechiffre_cesar sur le texte tout entier avec v2 et non pas sur une colonne (qu on faisait avec v1) donc on a moins de chance de faire des erreurs 
# car le nombre de charactere dans le texte est bien plus grand que celui dans la colonne donc les statistiques des frequences du texte seraient plus proche que celui de reference) 

################################################################


### Les fonctions suivantes sont utiles uniquement
### pour la cryptanalyse V3.

# Prend deux listes de même taille et
# calcule la correlation lineaire de Pearson
def correlation(L1,L2):
    """
    prend de liste de nombre et rend son coefficient de correlation (de Pearson)
    len(L1) == len(L2)
    """
    L1B , L2B = mean(L1) , mean(L2)
    
    return sum([(L1[i] - L1B) * (L2[i] - L2B) for i in range(len(L1))]) / ((sum([(L1[i] - L1B)**2 for i in range(len(L1))])) * (sum([(L2[i] - L2B)**2 for i in range(len(L2))])))**0.5


def decale(li , d):
    return [li[(i+d) % len(li)] for i in range(len(li))]



# Renvoie la meilleur clé possible par correlation
# étant donné une longueur de clé fixée


def clef_correlations(cipher, key_length):
    """
Prend un texte chiffre (cipher) et la longueur de sa clef (key_length) et renvoie la moyenne sur les colonnes des correlations obtenues avec pour chacune d'elles le 
decalage maximisant la correlation de Pearson de la colonne associe avec le texte de reference (germinal - FR) et retourne aussi la clef correspondante.
    """
    n = len(cipher)
    key=[0]*key_length
    score = [0]*key_length

    li = [[cipher[i + k] for k in range(0 , n , key_length) if i+k < n] for i in range(key_length)] #on a une liste des colonnes
    
    L2 = freq_FR #texte de reference

    for i in range(key_length):
        tab = li[i]      #on prend la colonne i
        tab = [correlation(decale(freq(tab) , d) , L2) for d in range(26)]     #on prend la liste des coefficients de Pearson entre la colonne i decale de d avec freq_FR
        score[i] = max(tab)    #on prend son max
        key[i] = tab.index(score[i])  #on prend l indice (donc le decalage) qui realise le max


    return (mean(score), key)

# Cryptanalyse V3 avec correlations
def cryptanalyse_v3(cipher):
    """
    Prend un texte (cipher) chiffré par Vigenere et retourne le texte dechiffré en utilisant la corrélation de Pearson pour déterminer la clef de chiffrement
    """
    score = 0
    decalage = []

    temp = [clef_correlations(cipher , key_length)[0] for key_length in range(1 , 21)] #on essaye toutes les taille de clef et on met dans une liste leur score
    
    score , decalage = clef_correlations(cipher , temp.index(max(temp)) + 1) #on prend le score et la clef qui realise le max ( = indice dans la liste + 1 car si on est a 0 c est que la taille de la clef vaut 1 etc)
    
    # on retourne le texte dechiffré avec cette clef 
    return dechiffre_vigenere(cipher, decalage) 

#Question 15 : 94 / 100 success

# 1)  Les textes courts peuvent ne pas fournir suffisamment de données pour une analyse de fréquence précise
# 2) Si la longueur de la clé est relativement longue par rapport à celle du texte, la méthode pourrait avoir du mal à trouver la clé correcte. 
# Cela est dû au fait que chaque fragment du texte chiffré (divisé par la longueur de la clé) serait trop court pour produire une distribution de fréquence fiable.
# 3) Si le texte en clair contient une distribution inhabituelle des lettres (par exemple, un texte comprenant principalement des termes techniques, des noms propres ou des mots étrangers), 
# la corrélation avec la distribution standard de fréquence des lettres pourrait être médiocre, conduisant à une détermination incorrecte de la clé.

# pourquoi v3 est mieux que v1 et v2 :
# 1) Précision Améliorée: La V3 utilise la corrélation de Pearson pour trouver la clé, ce qui est généralement plus précis que l'analyse de fréquence simple utilisée dans la V1 et l'indice de coïncidence mutuelle de la V2. 
# Elle prend en compte la relation globale entre les distributions de fréquences plutôt que de se concentrer uniquement sur les fréquences les plus élevées ou les correspondances d'indices. 
# 2) Évaluation Globale de la Clé: La V3 évalue la clé dans son ensemble pour la corrélation, plutôt que de traiter chaque partie de la clé indépendamment. 
# Cela permet de mieux gérer les interactions entre les différentes parties de la clé.

# Info trouve sur les textes qui ont echoues : (Disclaimer : la partie d'en dessous et que celle la a ete corriger orthographiquement et grammatiquement par chatgpt)

#Texte n°81: Dans le cas du texte numéro 81, la taille de la clé déterminée était la même que celle attendue. Cependant, la première valeur de la clé déchiffrée était 6, alors qu'elle aurait dû être 17, avec une différence de 11 par rapport à la valeur attendue.
#Texte n°86: Pour le texte numéro 86, la longueur de la clé était également correcte. Néanmoins, la dixième valeur (clef[9]) de la clé déchiffrée était 2 au lieu de la valeur correcte 18, ce qui représente un écart de 14.
#Texte n°88: Dans l'exemple du texte numéro 88, bien que la taille de la clé soit correcte, la cinquième valeur (clef[4]) de la clé trouvée était 7, alors qu'elle aurait dû être 11, soit un écart de 10.
#Texte n°89: Pour le texte numéro 89, la taille de la clé était encore une fois exacte. Cependant, il y avait deux erreurs dans les valeurs de la clé : la première valeur (clef[0]) était 5 au lieu de 9, et la quatrième valeur (clef[3]) était 18 au lieu de 5, ce qui donne des écarts de 9 et 13 respectivement.
#Texte n°94: Le texte numéro 94 présentait une clé de la bonne taille, mais comportait six erreurs sur les 18 valeurs de la clé, indiquant plusieurs déviations par rapport aux valeurs attendues.
#Texte n°96: Enfin, pour le texte numéro 96, la clé avait la bonne taille, mais deux valeurs étaient incorrectes sur les 11 composant la clé.

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
