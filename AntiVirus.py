import os
import re
import time
from pathlib import Path

# === Définition des motifs pour détecter des commandes dangereuses ===
# Liste de motifs utilisant des expressions régulières pour identifier des commandes potentiellement malveillantes.
DANGEROUS_PATTERNS = [
    r'del\s+.+',                  # Commande pour supprimer des fichiers
    r'format\s+[A-Z]:',           # Commande pour formater un disque
    r'reg\s+(add|delete)\s+.*',   # Modification du registre Windows
    r'shutdown\s+(/s|/r|/t).*',   # Commande pour éteindre ou redémarrer la machine
    r'powershell\s+-.*',          # Appels à PowerShell avec des arguments
    r'cmd\s+/c\s+.*',             # Exécution de commandes en cascade via cmd
    r'vssadmin\s+delete\s+shadows', # Suppression des sauvegardes système
    r'wscript\s+.*',              # Utilisation de Windows Script Host
]

# === Fonction pour analyser un fichier batch (.bat) ===
def scan_bat_file(file_path):
    """
    Analyse un fichier batch pour détecter des commandes dangereuses.

    :param file_path: Chemin du fichier batch à analyser.
    :return: True si une commande suspecte est détectée, sinon False.
    """
    try:
        print(f"[DEBUG] Analyse du fichier : {file_path}")
        # Ouverture du fichier en mode lecture, avec gestion des erreurs d'encodage
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            # Lecture ligne par ligne
            for line_no, line in enumerate(file, 1):  # line_no correspond au numéro de la ligne
                for pattern in DANGEROUS_PATTERNS:
                    # Recherche d'un motif dans la ligne en cours
                    if re.search(pattern, line, re.IGNORECASE):
                        print(f"[ALERTE] Commande suspecte trouvée dans {file_path} à la ligne {line_no}: {line.strip()}")
                        return True  # Commande dangereuse trouvée
        print(f"[DEBUG] Aucun motif suspect trouvé dans {file_path}.")
    except Exception as e:
        print(f"[ERREUR] Impossible d'analyser le fichier {file_path}: {e}")
    return False

# === Fonction pour analyser un répertoire ===
def scan_directory(directory):
    """
    Parcourt un répertoire pour rechercher des fichiers batch (.bat) contenant des commandes dangereuses.

    :param directory: Chemin du répertoire à analyser.
    :return: Liste des fichiers suspects détectés.
    """
    suspicious_files = []  # Liste pour stocker les fichiers suspects
    for root, dirs, files in os.walk(directory):  # os.walk explore récursivement les dossiers
        for file in files:
            if file.lower().endswith('.bat'):  # Vérifie si le fichier a l'extension .bat
                file_path = os.path.join(root, file)
                if scan_bat_file(file_path):  # Appelle la fonction pour analyser le fichier
                    suspicious_files.append(file_path)
    return suspicious_files

# === Fonction pour ajouter le script au démarrage ===
def add_to_startup():
    """
    Ajoute ce script au démarrage de Windows.
    """
    try:
        # Chemin absolu de ce script
        script_path = Path(__file__).resolve()
        # Chemin vers le dossier "Startup" de l'utilisateur
        startup_path = os.path.expandvars(r"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup")
        shortcut_path = os.path.join(startup_path, "Antivirus.bat")

        if os.path.exists(shortcut_path):
            print("[INFO] Le script est déjà ajouté au démarrage.")
            return

        # Crée un fichier batch pour lancer ce script
        with open(shortcut_path, 'w') as shortcut:
            shortcut.write(f"@echo off\npython \"{script_path}\"\n")
        print("[INFO] Script ajouté au démarrage avec succès.")
    except Exception as e:
        print(f"[ERREUR] Échec de l'ajout au démarrage: {e}")

# === Fonction pour générer un rapport ===
def generate_report(suspicious_files):
    """
    Génère un rapport listant les fichiers suspects détectés.

    :param suspicious_files: Liste des fichiers suspects.
    """
    report_path = Path(os.path.expanduser("~")) / "antivirus_report.txt"  # Crée le rapport sur le bureau
    try:
        with open(report_path, 'w', encoding='utf-8') as report:
            if suspicious_files:
                report.write("Fichiers suspects détectés:\n")
                for file in suspicious_files:
                    report.write(f"  - {file}\n")
            else:
                report.write("Aucun fichier suspect détecté.\n")
        print(f"[INFO] Rapport généré : {report_path}")
    except Exception as e:
        print(f"[ERREUR] Impossible de générer le rapport : {e}")

# === Fonction principale ===
def main():
    """
    Fonction principale qui exécute toutes les étapes de l'analyse antivirus.
    """
    print("[INFO] Démarrage de l'antivirus...")

    # Liste des répertoires à analyser
    user_directories = [
        os.path.expanduser("~\\Desktop"),   # Bureau
        os.path.expanduser("~\\Documents"), # Documents
        os.path.expanduser("~\\Downloads")  # Téléchargements
    ]

    all_suspicious_files = []  # Pour stocker tous les fichiers suspects détectés
    for directory in user_directories:
        print(f"[INFO] Analyse du répertoire: {directory}")
        if os.path.exists(directory):  # Vérifie si le répertoire existe
            suspicious_files = scan_directory(directory)
            all_suspicious_files.extend(suspicious_files)  # Ajoute les fichiers détectés à la liste principale
        else:
            print(f"[ERREUR] Le répertoire n'existe pas : {directory}")

    # Affichage des résultats
    if all_suspicious_files:
        print("[ALERTE] Fichiers suspects détectés:")
        for file in all_suspicious_files:
            print(f"  - {file}")
    else:
        print("[INFO] Aucun fichier suspect détecté.")

    generate_report(all_suspicious_files)  # Génération du rapport

    # Pause avant de fermer le programme
    time.sleep(5)

# === Lancement du programme ===
if __name__ == "__main__":
    add_to_startup()  # Ajoute le script au démarrage
    main()  # Exécute le programme principal
