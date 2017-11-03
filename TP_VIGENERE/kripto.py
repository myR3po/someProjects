#!/usr/bin/env python
# -*-coding:utf-8 -*

#   28-01-15
"""
  Ce programme effectue la cryptanalyse de l'algorithme de vigenère
Et peut éventuellement crypter ou décrypter un message,
en utilisant cet algorithme.


  CE PROGRAMME NE PREND EN COMPTE QUE DES LETTRES ET EN MAJUSCULES.

"""

import sys
import re
import argparse
import string


def main():

    parser = argparse.ArgumentParser(description="Crypter ou de décrypter\
                                 un message en utilisant l'algorithme de \
                                 Vigenère. \nEffectuer la cryptanalyse de \
                                 cet algorithme.")

    parser.add_argument("-a", "--action", help="L'action à réaliser.",
                        choices=['encrypt', 'decrypt'])
    parser.add_argument("infile", type=argparse.FileType('r'),
                        help="Fichier contenant le message.")
    parser.add_argument("-v", "--verbose", help="verbose.", action="store_true")
    parser.add_argument("-V", "--version", help="Affiche la version et \
                        quitte le programme.", action="store_true")
    parser.add_argument("-k", "--key", type=str, help="la clé à utiliser")
    parser.add_argument("-o", "--outfile", type=argparse.FileType('w'),
                        help="Fichier resultant de l'action.")
    parser.add_argument("-l", "--length", type=int, help="La taille max de la \
                        clé à tester au cours de la cryptanalyse.", default=10)

    args = parser.parse_args()

    if args.version:
        print "Version 0.1 \nCopyright © 2015"
        sys.exit(0)

    message = chargement(args.infile, args.verbose)

    if re.search(r"[a-z0-9]", message):
        print "Ce programme ne prend en compte que les lettres majuscules. "
        sys.exit(1)

    if args.action:
        if args.key:
            if args.outfile:
                sauvegarde(args.outfile,
                           vigenere(message, args.key, args.action,
                                    args.verbose),
                           args.verbose)
            else:
                print vigenere(message, args.key, args.action, args.verbose)
        else:
            print "Clé invalide ({0} -h pour de l'aide).".format(sys.argv[0])
            sys.exit(1)
    else:
        cle_possible(message, args.length, args.verbose)

# """
#
#   entree :
#       - nom_fichier
#
#   sortie :
#       retourne le contenu du fichier
#
def chargement(fichier, verbose=False):
    """
    """
    if verbose :
        print "Chargement du message en cours... "
    #mon_fichier = open(nom_fichier, "r")
    contenu = fichier.read()
    contenu.replace("\n",'')
    fichier.close()
    if verbose :
        print "Chargement du message terminé. "

    return contenu

#
#   entree :
#       - nom_fichier
#       - donnees
#
#   sortie :
#
def sauvegarde(fichier, donnees, verbose=False) :
    """
    """
    if verbose :
        print "Sauvegarde en cours... "

    fichier = open(fichier, "w")
    fichier.write(donnees)
    fichier.close()
    if verbose :
        print "Sauvegarde terminé. "


#
#   entree :
#       - dico
#
#   sortie :
#
#
def affichage_stat(dico):
    """  affiche le nombre d'occurences
    """
    for cle,valeur in dico.items():
        print("{0} -> {1}".format(cle,valeur))


#   entree :
#       - chaine
#
#   sortie :
#       retourne le resultat
#
def compte_occurence(chaine):
    """ Compte le nombre de fois qu'apparait chaque lettre de l'alphabet """

    alphabet = list(string.ascii_uppercase)
    statistique = dict( (cle,0) for cle in alphabet )
    val = 0
    for cle in statistique.keys() :
        statistique[cle] = chaine.count(cle)

    return statistique


#
#   entree :
#       - message
#       - taille_max
#   sortie :
#       retourne une liste de sous message
#
def liste_sous_chaine(message, pas_max=10) :
    """ Extrait des sequences du message suivant un pas """
    c = []
    taille = len(message)
    for i in range(1, pas_max + 1, 1) :
        c.append(message[0:taille:i] )

    return c

#
#   entree :
#       - liste_Chaine
#
#   sortie :
#       retourne une liste avec les longueurs de clé possible
#
def indice_de_coincidence(liste_Chaine, verbose=False) :
    """ Effectue le calcul des indices de coincidence.
        Et retourne un liste des longueurs de clé possible.
        une longueur est pris en compte si delta(indice trouvé - indice français) est compris
        entre ]-10%, 10%[ de l'indice de coincidence français
    """
    ic = []
    ic_temp = 0.0
    num = 0.0
    den = 0.0
    taille = 0
    ic_french = 0.0746
    pourcent = 0.1 * ic_french
    occurence = dict()

    if verbose :
        print "Estimation de la longueur de la clé. "

    for i,sous_chaine in enumerate(liste_Chaine) :

        taille = len(sous_chaine)

        den = (taille * taille) - taille

        occurence = compte_occurence(sous_chaine)

        ic_temp = 0.0

        for cle,valeur in occurence.items() :

            num = (valeur * valeur) - valeur
            try:
                ic_temp += float(num) / float(den)
            except:
                ic_temp += 0.

        if verbose :
                print "Longueur {0} -> indice {1}".format(i+1, ic_temp)

        delta = ic_temp - ic_french

        if delta > (0 - pourcent) and delta < pourcent :
            ic.append(i+1)

    return ic

#
#   entree :
#       - message
#       - taille_cle
#
#   sortie :
#       retourne la clé possible ou les clés possibles
#
def sans_nom(message, taille_cle, verbose=False) :
    """ """
    lc = []
    taille = len(message)

    if verbose :
        print "Recherche de la clé (ou des clés) possible(s). \n"
    # recherche la lettre la plus frequente pour chaque rang
    for i in range(taille_cle) :
        sc = message[0+i : taille : taille_cle]
        occurence = compte_occurence(sc)
        val_max = max(occurence.values() )
        lc.append( ''.join([cle for cle,valeur in occurence.items() if val_max == valeur] ) )

    # peut causer problème en cas de plusieurs lettre pour un rang
    liste_mot = []

    for l in lc :
        liste_mot = pa_sav(liste_mot, l)

    if liste_mot :
        for i in liste_mot :
            print i
    else:
        print "Aucune clé n'a été trouvé."


def pa_sav(liste, mot) :
    lc = []
    if liste :
        for i in liste :
            for lettre in mot :
                lc.append(i + chr( ord('A') + ( ord(lettre) - ord('E')) ))
    else :
        for lettre in mot :
            lc.append(chr( ord('A') + ( ord(lettre) - ord('E')) ))

    return lc

#
#   entree :
#       - message
#       - taille
#
#   sortie :
#       retourne le carre de vigenère
#
def cle_possible(message, pas_max=10, verbose=False) :
    ic = indice_de_coincidence(liste_sous_chaine(message, pas_max), verbose )
    if ic :
        for i in ic:
            sans_nom(message, i, verbose)
            print
    else :
        print "Impossible d'estimer la clé."

#
#   entree :
#       - cle
#
#   sortie :
#       retourne le carre de vigenère
#
def carre_vigenere(cle):
    """ effectue le carré de vigenère """
    lc = []
    Z = ord('Z')
    for lettre in cle :
        val = ord(lettre)
        lc.append([chr(i) for i in range(val,val + 26) if i <= Z] +
                  [chr(i-26) for i in range(val,val + 26) if i > Z] )

    return lc

#
#   entree :
#       - le_carre : le carre de vigenère correspondant à la clé
#       - la_lettre
#       - rang_cle : l'indice de la clé
#       - action : decrypt ou encrypt
#
#   sortie :
#       retourne la lettre cryptée ou décryptée
#
def trans_lettre(le_carre,la_lettre,rang_cle,action) :
    """ crypte ou decrypte une lettre """
    r = ""
    if action == "decrypt" :
        for i,lettre in enumerate(le_carre[rang_cle]) :
            if lettre == la_lettre :
                r = chr(ord('A')+ i)
                break
    else :
        r = le_carre[rang_cle][ord(la_lettre) - ord('A')]

    return r

#
#   entree :
#       - le_carre : le carre de vigenère correspondant à la clé
#       - mot
#       - cle
#       - action : decrypt ou encrypt
#
#   sortie :
#       retourne le mot crypté ou décrypté
#
def trans_mot(le_carre,mot,cle,action) :
    # le mot est de même longueur ou plus petit que la cle
    """ Crypte ou decrypte un mot """
    l = []
    for i in range(len(cle)) :
        try:
            l.append(trans_lettre(le_carre, mot[i], i, action) )
        except:
            pass

    return l

#
#   entree :
#       - message
#       - cle
#       - action : decrypt ou encrypt
#
#   sortie :
#       retourne le message crypté ou décrypté
#
def vigenere(message, cle, action, verbose=False) :
    """ Crypte ou decrypte un message """

    result = []
    taille_cle = len(cle)
    taille_message = len(message)
    le_carre = carre_vigenere(cle)

    if verbose :
        if action == "decrypt" :
            print "Décryptage du message en cours... "
        else:
            print "Encryptage du message en cours... "

    for i in range(0,taille_message,taille_cle ) :

        try:
            result += trans_mot(le_carre,message[i : i+taille_cle],cle,action)
        except:
            result += trans_mot(le_carre,message[i:],cle,action)

    if verbose :
        if action == "decrypt" :
            print "Décryptage du message terminé. "
        else:
            print "Encryptage du message terminé. "

    return ''.join(result)

if __name__ == '__main__':
    main()
