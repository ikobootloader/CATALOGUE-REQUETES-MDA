# Changelog

## 2026-05-11
- Refactor structure: externalisation du CSS inline vers `css/styles.css`.
- Refactor structure: externalisation des scripts inline vers `js/vendor-xlsx-inline.js` et `js/app.js`.
- HTML: remplacement des blocs `<style>` et `<script>` inline par references externes.
- Correction: ajout de `DataManager.deleteBulk(ids)` dans la logique applicative pour retablir la suppression multiple.
- Refactor metier: creation de `SelectionDomain` dans `js/catalogue-selection-domain.js`.
- Refactor orchestrateur: `AppController` delegue les regles de selection au module domaine.
- Refactor metier: creation de `FilterDomain` dans `js/catalogue-filter-domain.js`.
- Refactor orchestrateur: `FilterEngine.applyFilters()` delegue les regles de filtrage/recherche au module domaine.
- Refactor metier: creation de `FilterOptionsDomain` dans `js/catalogue-filter-options-domain.js`.
- Refactor orchestrateur: `FilterEngine.populateFilters()` delegue la preparation des options au module domaine.
- Encodage: normalisation UTF-8 de `BO_CatalogueRequetes_Inline.html`, `js/app.js` et `js/catalogue-filter-options-domain.js` pour corriger les mojibakes.
- Performance UX: suppression du double declenchement de filtrage en retirant `oninput="applyFilters()"` du champ recherche (debounce JS conserve).
- Maintenance: suppression de logs debug verbeux dans le flux de navigation/filtres.
- Feature: integration de Quill.js sur `Description / Objet metier` dans la modale requete (edition riche avec preservation de mise en forme).
- Feature avancée: ajout d'une bascule optionnelle `Mode source HTML` dans la modale requete (synchro bidirectionnelle avec l'editeur visuel).
- Securite affichage: sanitation HTML pour le rendu detail et conversion texte pour l'apercu carte.
- UX: ajout d'un bouton `Se deconnecter` dans la topbar, branché sur `AppController.lock()`.
- UX: indicateur de sauvegarde header en 2 etats (`✓` vert quand OK, icone de synchronisation tournante pendant l'ecriture), pilote par `SyncManager`.
- Robustesse sync: gestion explicite de `NotFoundError` (fichier Excel supprimé/deplacé) avec invalidation du handle, desactivation sync et demande de reliaison.
- Console: suppression du `console.error` pour le cas `NotFoundError` attendu (moins de bruit en debug).
- Correctif critique: en reconnexion, remplacement de `DataManager.initializeFirstTime(...)` par `DataManager.loadAll()` dans `verifyPassword()`, pour eviter tout reset du catalogue et du parametrage.
- Correctif UX session: reactivation explicite du bouton verrouillage (`lock-btn.disabled=false`) dans `showLockScreen()` et `showFirstSetup()` apres deconnexion/retour ecran lock.
- Documentation: mise a jour de `README.md`.

## 2026-05-12
- Correctif UX paramétrage: ajout de l'édition des entrées déjà sauvegardées (univers, domaines, statuts, fréquences, responsables) sans suppression/récréation.
- Refactor métier: création de `js/catalogue-config-domain.js` pour centraliser validation de renommage, détection de doublons et propagation des libellés dans le catalogue.
- Orchestrateur/UI: ajout de boutons `Modifier` dans les listes de paramétrage et sauvegarde cohérente `config + data` lors des renommages.
- Feature domaines: ajout d'une catégorisation par groupe (`domain.group`) au paramétrage des domaines fonctionnels.
- Sidebar: affichage des domaines regroupés par catégorie dans la section "Par domaine".
- Rétrocompatibilité: migration douce des configurations existantes via `DataManager.migrateConfig()` (ajout automatique du groupe `Sans groupe` sans perte de données).
- Import XLSX: les domaines importés reçoivent un groupe par défaut puis passent par la migration de configuration.
