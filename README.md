# 📂 Catalogue des Requêtes BO — MDA

![Version](https://img.shields.io/badge/version-3.0.0-blue)
![Statut](https://img.shields.io/badge/statut-Production_Ready-success)
![Sécurité](https://img.shields.io/badge/sécurité-AES--256--GCM-orange)
![Sync](https://img.shields.io/badge/synchro-Auto_XLSX-brightgreen)

Application locale, hautement sécurisée et autonome permettant de cataloguer, gérer et consulter les requêtes BusinessObjects (BO) de la MDA.

> **Note de conception :** Cette application est conçue pour fonctionner **100% en local, sans serveur, sans dépendances (zéro NPM)**. Elle garantit la confidentialité des données grâce à un chiffrement de niveau militaire et un stockage hybride (IndexedDB + Synchronisation locale).

---

## ✨ Fonctionnalités Principales

- 🔐 **Sécurité Avancée :** Chiffrement AES-256-GCM via Web Crypto API. Système de **Clé de Récupération** en cas d'oubli du mot de passe.
- 🗄️ **Stockage Hybride :**
  - **IndexedDB :** Base de données principale ultra-rapide dans le navigateur.
  - **Synchronisation Auto (FSA API) :** Sauvegarde automatique en tâche de fond dans un fichier Excel local ou partagé à chaque modification.
- 👁️ **Vues Multiples :** Affichage par cartes (Cards), tableau détaillé ou arborescence.
- 🔍 **Recherche & Filtres :** Moteur de recherche full-text et filtres croisés dynamiques.
- 🏷️ **Référentiel CNSA :** Intégration complète du Référentiel statistique CNSA.
- 📤 **Interopérabilité XLSX/JSON :** 
  - **Export Avancé :** Génération de classeurs XLSX multi-onglets (Catalogue + Configuration complète).
  - **Import Intelligent :** Fusion de données depuis JSON ou XLSX avec détection de doublons.
- 🎨 **Interface Premium :** Design moderne avec mode sombre, icônes Material Symbols, et animations fluides.

## 🛠️ Stack Technique

- **Structure :** HTML5
- **Style :** CSS3 (Variables CSS, Grid, Flexbox, Glassmorphism)
- **Logique :** Vanilla JavaScript (ES6+)
- **Stockage :** IndexedDB & File System Access API
- **Bibliothèques Inline :** SheetJS (xlsx.mini.min.js) pour la gestion Excel.
- **Cryptographie :** Web Crypto API (SubtleCrypto)

## 🚀 Guide de Démarrage

### Premier Lancement
1. Ouvrir `BO_CatalogueRequetes_Inline.html` dans un navigateur moderne (Chrome, Edge).
2. Définissez un **mot de passe fort**.
3. **IMPORTANT :** Notez précieusement la **Clé de Récupération** affichée. C'est votre unique moyen de restaurer l'accès en cas d'oubli du mot de passe.
4. L'application se déverrouille avec un jeu de données de démonstration.

### Activation de la Synchronisation Excel
1. Allez dans l'onglet **Paramètres**.
2. Dans la section **Synchronisation locale**, cliquez sur **Lier un fichier**.
3. Sélectionnez ou créez un fichier Excel sur votre disque.
4. Désormais, chaque modification sera sauvegardée "silencieusement" dans ce fichier.

## ⌨️ Raccourcis Clavier

| Raccourci | Action |
| --- | --- |
| `Ctrl` + `N` | Créer une nouvelle requête |
| `Ctrl` + `L` | Verrouiller l'application immédiatement |
| `Échap` | Fermer les fenêtres modales / menus |

## 💾 Sauvegarde et Portabilité

Bien que la synchronisation automatique soit recommandée, vous pouvez effectuer des exports manuels :
- **Export Excel (XLSX) :** Génère un fichier complet incluant vos données et vos paramètres personnalisés (couleurs, univers, etc.).
- **Export JSON :** Format brut pour la restauration technique.

## 🆘 Sécurité et Dépannage

- **Mot de passe oublié :** Utilisez votre **Clé de Récupération** sur l'écran de verrouillage.
- **Permission de fichier expirée :** Si la synchronisation s'arrête, cliquez sur la bannière orange en haut de l'écran pour ré-autoriser l'accès au fichier Excel (mesure de sécurité standard des navigateurs).
- **Réinitialisation totale :** Pour vider l'application, utilisez les options dans l'onglet *Paramètres* > *Actions globales*.

---
*Conçu et développé pour la MDA de l'Orne.*

**Créé par Frédérick MURAT - Licence MIT - 2026**
