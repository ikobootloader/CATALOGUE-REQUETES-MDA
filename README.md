# Catalogue des Requetes BO - MDA

Application web locale pour cataloguer et suivre les requetes BusinessObjects.

## Contraintes techniques
- 100% local
- Sans serveur
- Sans npm
- Stockage navigateur (IndexedDB)

## Structure
- `BO_CatalogueRequetes_Inline.html` (point d'entree)
- `css/styles.css` (styles)
- `js/vendor-xlsx-inline.js` (bibliotheque XLSX inline externalisee)
- `js/catalogue-selection-domain.js` (domaine metier de selection multiple)
- `js/catalogue-filter-domain.js` (domaine metier de filtres/recherche)
- `js/catalogue-filter-options-domain.js` (domaine metier des options de filtres)
- `js/catalogue-config-domain.js` (domaine metier d'edition du parametrage)
- `js/app.js` (orchestrateur UI et logique applicative)

## Demarrage
1. Ouvrir `BO_CatalogueRequetes_Inline.html` dans un navigateur moderne (Chrome/Edge).
2. Definir le mot de passe de l'application au premier lancement.
3. Utiliser l'interface pour gerer le catalogue.

## Edition riche
- Le champ `Description / Objet metier` de la modale requete utilise Quill.js pour conserver la mise en forme.
- Fallback automatique sur textarea simple si Quill n'est pas charge.

## Architecture JS
- `DataManager`: persistance et operations metier sur les requetes
- `SelectionDomain`: regles de selection/bulk en domaine metier
- `FilterDomain`: regles de filtrage/recherche en domaine metier
- `FilterOptionsDomain`: preparation des options de filtres (univers/frequences)
- `FilterEngine`: orchestration des filtres et synchronisation UI
- `AppController`: orchestration UI et actions utilisateur
- `UIComponents`: rendu et composants d'interface

## Maintenance
- Toute evolution logicielle doit etre tracee dans `CHANGELOG.md`.
- Les seuls fichiers Markdown a maintenir sont `README.md` et `CHANGELOG.md`.
