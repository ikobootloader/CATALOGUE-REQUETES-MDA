try {
    
    


// MODULE: UTILS
// ═══════════════════════════════════════════════════════════════
var Utils = {
  TAG_COLORS: [
    {bg:'#E8EDF5',color:'#1B3A6B'}, {bg:'#FEF0E6',color:'#C05A0E'},
    {bg:'#EAF3DE',color:'#3B6D11'}, {bg:'#E6F1FB',color:'#185FA5'},
    {bg:'#FAEEDA',color:'#854F0B'}, {bg:'#FBEAF0',color:'#993556'}
  ],
  tagColor(t) {
    let h = 0;
    for (let i = 0; i < t.length; i++) {
      h = (h * 31 + t.charCodeAt(i)) & 0xffffff;
    }
    return this.TAG_COLORS[h % this.TAG_COLORS.length];
  },
  escapeHtml(s) {
    return String(s || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  },
  stripHtml(s) {
    const html = String(s || '');
    const temp = document.createElement('div');
    temp.innerHTML = html;
    return temp.textContent || temp.innerText || '';
  },
  sanitizeRichHtml(s) {
    const source = String(s || '');
    if (!source) return '';
    const allowedTags = new Set(['P', 'BR', 'STRONG', 'B', 'EM', 'I', 'U', 'S', 'UL', 'OL', 'LI', 'A', 'SPAN']);
    const container = document.createElement('div');
    container.innerHTML = source;
    const elements = container.querySelectorAll('*');
    elements.forEach(el => {
      if (!allowedTags.has(el.tagName)) {
        const text = document.createTextNode(el.textContent || '');
        el.replaceWith(text);
        return;
      }
      [...el.attributes].forEach(attr => {
        const name = attr.name.toLowerCase();
        if (name.startsWith('on')) {
          el.removeAttribute(attr.name);
          return;
        }
        if (el.tagName === 'A') {
          if (name === 'href') return;
          if (name === 'target' || name === 'rel') return;
          el.removeAttribute(attr.name);
          return;
        }
        if (name !== 'style') {
          el.removeAttribute(attr.name);
        }
      });
      if (el.tagName === 'A') {
        const href = el.getAttribute('href') || '';
        const isSafeHref = href.startsWith('http://') || href.startsWith('https://') || href.startsWith('mailto:');
        if (!isSafeHref) {
          el.removeAttribute('href');
        } else {
          el.setAttribute('target', '_blank');
          el.setAttribute('rel', 'noopener noreferrer');
        }
      }
    });
    return container.innerHTML.trim();
  },
  /**
   * Échappe les caractères pour utilisation dans du code JavaScript inline
   * @param {string} s - Chaîne à échapper
   * @returns {string} - Chaîne échappée pour JS
   */
  escapeJs(s) {
    return String(s || '')
      .replace(/\\/g, '\\\\')
      .replace(/'/g, "\\'")
      .replace(/"/g, '\\"')
      .replace(/\n/g, '\\n')
      .replace(/\r/g, '\\r');
  },
  initials(s) {
    return (s || '?')
      .split(' ')
      .map(w => w[0])
      .join('')
      .slice(0, 2)
      .toUpperCase();
  },
  formatDate(dateStr) {
    if (!dateStr) return '—';
    return new Date(dateStr).toLocaleDateString('fr-FR');
  },
  generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  },
  debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
      const later = () => {
        clearTimeout(timeout);
        func(...args);
      };
      clearTimeout(timeout);
      timeout = setTimeout(later, wait);
    };
  },
  deepClone(obj) {
    return JSON.parse(JSON.stringify(obj));
  }
};
window.Utils = Utils;

// ═══════════════════════════════════════════════════════════════
// MODULE: CRYPTO-MANAGER
// ═══════════════════════════════════════════════════════════════

var CryptoManager = {
  // Clé de chiffrement (dérivée du mot de passe)
  cryptoKey: null,

  // Salt pour la dérivation de clé (stocké en base64 dans sessionStorage)
  salt: null,

  /**
   * Dérive une clé de chiffrement depuis un mot de passe
   * @param {string} password - Mot de passe utilisateur
   * @returns {Promise<CryptoKey>}
   */
  async deriveKey(password) {
    // Générer ou récupérer le salt (doit être persistant pour dériver la même clé)
    if (!this.salt) {
      const storedSalt = localStorage.getItem('mda_salt') || sessionStorage.getItem('mda_salt');
      if (storedSalt) {
        // Récupérer le salt existant
        this.salt = Uint8Array.from(atob(storedSalt), c => c.charCodeAt(0));
        localStorage.setItem('mda_salt', storedSalt); // Assurer la persistance
      } else {
        // Générer un nouveau salt
        this.salt = crypto.getRandomValues(new Uint8Array(16));
        const encodedSalt = btoa(String.fromCharCode(...this.salt));
        localStorage.setItem('mda_salt', encodedSalt);
      }
    }

    // Encoder le mot de passe
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(password);

    // Importer le mot de passe comme clé de base
    const baseKey = await crypto.subtle.importKey(
      'raw',
      passwordBuffer,
      'PBKDF2',
      false,
      ['deriveBits', 'deriveKey']
    );

    // Dériver une clé AES-GCM
    const derivedKey = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: this.salt,
        iterations: 100000, // 100k itérations pour sécurité
        hash: 'SHA-256'
      },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );

    this.cryptoKey = derivedKey;
    return derivedKey;
  },

  /**
   * Chiffre des données
   * @param {Object} data - Données à chiffrer
   * @returns {Promise<string>} - Données chiffrées en base64
   */
  async encrypt(data) {
    if (!this.cryptoKey) {
      throw new Error('Clé de chiffrement non initialisée');
    }

    // Convertir les données en JSON puis en buffer
    const encoder = new TextEncoder();
    const plaintext = encoder.encode(JSON.stringify(data));

    // Générer un IV aléatoire (nonce)
    const iv = crypto.getRandomValues(new Uint8Array(12));

    // Chiffrer
    const ciphertext = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv
      },
      this.cryptoKey,
      plaintext
    );

    // Combiner IV + ciphertext
    const combined = new Uint8Array(iv.length + ciphertext.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(ciphertext), iv.length);

    // Retourner en base64
    return btoa(String.fromCharCode(...combined));
  },

  /**
   * Déchiffre des données
   * @param {string} encryptedData - Données chiffrées en base64
   * @returns {Promise<Object>} - Données déchiffrées
   */
  async decrypt(encryptedData) {
    if (!this.cryptoKey) {
      throw new Error('Clé de chiffrement non initialisée');
    }

    // Décoder depuis base64
    const combined = Uint8Array.from(atob(encryptedData), c => c.charCodeAt(0));

    // Extraire IV et ciphertext
    const iv = combined.slice(0, 12);
    const ciphertext = combined.slice(12);

    try {
      // Déchiffrer
      const plaintext = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: iv
        },
        this.cryptoKey,
        ciphertext
      );

      // Décoder et parser JSON
      const decoder = new TextDecoder();
      const json = decoder.decode(plaintext);
      return JSON.parse(json);
    } catch (error) {
      throw new Error('Échec du déchiffrement - Mot de passe incorrect ou données corrompues');
    }
  },

  /**
   * Vérifie si un mot de passe est correct
   * @param {string} password - Mot de passe à tester
   * @param {string} testData - Données chiffrées de test
   * @returns {Promise<boolean>}
   */
  async verifyPassword(password, testData) {
    try {
      await this.deriveKey(password);
      await this.decrypt(testData);
      return true;
    } catch {
      this.cryptoKey = null;
      return false;
    }
  },

  /**
   * Génère un hash du mot de passe pour vérification
   * @param {string} password - Mot de passe
   * @returns {Promise<string>} - Hash en hex
   */
  async hashPassword(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  },

  /**
   * Chiffre le mot de passe avec une clé de récupération
   * @param {string} password 
   * @param {string} recoveryKey 
   * @returns {Promise<Object>} { encryptedPassword, recoverySalt }
   */
  async encryptWithRecoveryKey(password, recoveryKey) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const encodedSalt = btoa(String.fromCharCode(...salt));
    
    const encoder = new TextEncoder();
    const baseKey = await crypto.subtle.importKey(
      'raw', encoder.encode(recoveryKey), 'PBKDF2', false, ['deriveKey']
    );
    const derivedKey = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' },
      baseKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt']
    );
    
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv }, derivedKey, encoder.encode(password)
    );
    
    const combined = new Uint8Array(iv.length + ciphertext.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(ciphertext), iv.length);
    
    return {
      encryptedPassword: btoa(String.fromCharCode(...combined)),
      recoverySalt: encodedSalt
    };
  },

  /**
   * Déchiffre le mot de passe avec une clé de récupération
   * @param {string} encryptedPasswordB64 
   * @param {string} recoverySaltB64 
   * @param {string} recoveryKey 
   * @returns {Promise<string|null>}
   */
  async decryptWithRecoveryKey(encryptedPasswordB64, recoverySaltB64, recoveryKey) {
    try {
      const salt = Uint8Array.from(atob(recoverySaltB64), c => c.charCodeAt(0));
      const encoder = new TextEncoder();
      const baseKey = await crypto.subtle.importKey(
        'raw', encoder.encode(recoveryKey), 'PBKDF2', false, ['deriveKey']
      );
      const derivedKey = await crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' },
        baseKey, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
      );
      
      const combined = Uint8Array.from(atob(encryptedPasswordB64), c => c.charCodeAt(0));
      const iv = combined.slice(0, 12);
      const ciphertext = combined.slice(12);
      
      const plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv }, derivedKey, ciphertext
      );
      return new TextDecoder().decode(plaintext);
    } catch(e) {
      return null;
    }
  },

  /**
   * Nettoie les clés en mémoire (lors de la déconnexion)
   */
  clear() {
    this.cryptoKey = null;
    this.salt = null;
    // Ne SURTOUT PAS supprimer le salt (localStorage) sinon la clé ne pourra
    // plus jamais être dérivée à l'identique pour ce mot de passe.
  }
};

// Export global

// ═══════════════════════════════════════════════════════════════
// MODULE: DATA-MANAGER
// ═══════════════════════════════════════════════════════════════

var DataManager = {
  // État de l'application
  data: [],          // Catalogue de requêtes
  config: {},        // Configuration
  editingId: null,   // ID en cours d'édition
  db: null,          // Instance IndexedDB
  isLocked: true,    // État de verrouillage

  // Configuration IndexedDB
  DB_NAME: 'MDA_BO_Catalogue',
  DB_VERSION: 1,
  STORE_NAME: 'encrypted_data',

  /**
   * Initialise IndexedDB
   * @returns {Promise<IDBDatabase>}
   */
  async initDB() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.DB_NAME, this.DB_VERSION);

      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        this.db = request.result;
        resolve(this.db);
      };

      request.onupgradeneeded = (event) => {
        const db = event.target.result;

        // Créer l'object store si nécessaire
        if (!db.objectStoreNames.contains(this.STORE_NAME)) {
          db.createObjectStore(this.STORE_NAME, { keyPath: 'key' });
        }
      };
    });
  },

  /**
   * Sauvegarde des données chiffrées dans IndexedDB
   * @param {string} key - Clé de stockage
   * @param {string} encryptedValue - Valeur chiffrée
   * @returns {Promise<void>}
   */
  async saveToIndexedDB(key, encryptedValue) {
    if (!this.db) await this.initDB();

    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction([this.STORE_NAME], 'readwrite');
      const store = transaction.objectStore(this.STORE_NAME);
      const request = store.put({ key, value: encryptedValue, timestamp: Date.now() });

      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  },

  /**
   * Récupère des données chiffrées depuis IndexedDB
   * @param {string} key - Clé de stockage
   * @returns {Promise<string|null>}
   */
  
  async deleteFromIndexedDB(key) {
    if (!this.db) await this.initDB();
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction([this.STORE_NAME], 'readwrite');
      const store = transaction.objectStore(this.STORE_NAME);
      const request = store.delete(key);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  },
  async loadFromIndexedDB(key) {
    if (!this.db) await this.initDB();

    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction([this.STORE_NAME], 'readonly');
      const store = transaction.objectStore(this.STORE_NAME);
      const request = store.get(key);

      request.onsuccess = () => {
        const result = request.result;
        resolve(result ? result.value : null);
      };
      request.onerror = () => reject(request.error);
    });
  },

  /**
   * Sauvegarde le catalogue (chiffré)
   * @returns {Promise<void>}
   */
  async saveData() {
    try {
      const encrypted = await CryptoManager.encrypt(this.data);
      await this.saveToIndexedDB('catalogue', encrypted);
      if (typeof SyncManager !== 'undefined') SyncManager.triggerSync();
    } catch (error) {
      console.error('Erreur sauvegarde données:', error);
      throw error;
    }
  },

  /**
   * Sauvegarde la configuration (chiffrée)
   * @returns {Promise<void>}
   */
  async saveConfig() {
    try {
      const encrypted = await CryptoManager.encrypt(this.config);
      await this.saveToIndexedDB('config', encrypted);
      if (typeof SyncManager !== 'undefined') SyncManager.triggerSync();
    } catch (error) {
      console.error('Erreur sauvegarde config:', error);
      throw error;
    }
  },

  /**
   * Charge toutes les données (après authentification)
   * @returns {Promise<void>}
   */
  async loadAll() {
    try {
      // Charger le catalogue
      const encryptedData = await this.loadFromIndexedDB('catalogue');
      if (encryptedData) {
        this.data = await CryptoManager.decrypt(encryptedData);
      } else {
        this.data = [];
      }

      // Charger la configuration
      const encryptedConfig = await this.loadFromIndexedDB('config');
      if (encryptedConfig) {
        this.config = await CryptoManager.decrypt(encryptedConfig);
      } else {
        this.config = this.getDefaultConfig();
      }
      this.config = this.migrateConfig(this.config);

      this.isLocked = false;
    } catch (error) {
      console.error('Erreur chargement données:', error);
      throw error;
    }
  },
  /**
   * Réinitialise complètement l'application (vidage total)
   */
  async resetAllData() {
    if (!this.db) await this.initDB();
    
    // 1. Supprimer toutes les clés d'IndexedDB
    const keys = ['catalogue', 'config', 'password_hash', 'recovery_data', 'sync_handle'];
    for (const key of keys) {
      await this.deleteFromIndexedDB(key);
    }
    
    // 2. Réinitialiser l'état mémoire
    this.data = [];
    this.config = this.getDefaultConfig();
    
    // 3. Recharger la page pour revenir à l'écran de création
    window.location.reload();
  },

  /**
   * Initialisation forcée lors du premier démarrage
   * @param {boolean} loadDemo - Charger ou non les données de démo
   */
  async initializeFirstTime(loadDemo) {
    this.config = this.getDefaultConfig();
    await this.saveConfig();
    
    if (loadDemo) {
      this.data = this.getDemoData();
    } else {
      this.data = [];
    }
    await this.saveData();
  },

  /**
   * Verrouille l'application
   */
  lock() {
    this.data = [];
    this.config = {};
    this.isLocked = true;
    CryptoManager.clear();
  },

  /**
   * Ajoute ou met à jour une requête
   * @param {Object} requete - Objet requête
   * @returns {Promise<void>}
   */
  async saveRequete(requete) {
    if (this.editingId) {
      // Mise à jour
      const index = this.data.findIndex(r => r.id === this.editingId);
      if (index >= 0) {
        this.data[index] = requete;
      }
    } else {
      // Ajout
      this.data.unshift(requete);
    }

    await this.saveData();
    this.editingId = null;
  },

  /**
   * Supprime une requête
   * @param {string} id - ID de la requête
   * @returns {Promise<void>}
   */
  async deleteRequete(id) {
    this.data = this.data.filter(r => r.id !== id);
    await this.saveData();
  },

  /**
   * Supprime plusieurs requêtes en une seule opération.
   * @param {string[]} ids - IDs à supprimer
   * @returns {Promise<void>}
   */
  async deleteBulk(ids) {
    if (!Array.isArray(ids) || ids.length === 0) return;
    const idsToDelete = new Set(ids);
    this.data = this.data.filter(r => !idsToDelete.has(r.id));
    await this.saveData();
  },

  /**
   * Duplique une requête
   * @param {string} id - ID de la requête à dupliquer
   * @returns {Promise<string>} - ID de la nouvelle requête
   */
  async duplicateRequete(id) {
    const original = this.data.find(r => r.id === id);
    if (!original) throw new Error('Requête introuvable');

    const duplicate = {
      ...original,
      id: this.generateId(),
      nom: original.nom + ' (copie)',
      statut: 'Brouillon',
      date: new Date().toISOString().split('T')[0]
    };

    this.data.unshift(duplicate);
    await this.saveData();

    return duplicate.id;
  },

  /**
   * Génère un nouvel ID auto-incrémenté
   * @returns {string}
   */
  generateId() {
    let nextNum = this.config.next;

    if (!nextNum) {
      // Trouver le plus grand numéro existant
      nextNum = this.data.reduce((max, r) => {
        const num = parseInt((r.id || '').replace(/\D/g, '')) || 0;
        return Math.max(max, num);
      }, 0) + 1;
    }

    const prefix = this.config.prefix || 'REQ';
    const sep = this.config.sep || '-';
    const pad = parseInt(this.config.pad) || 3;

    const id = prefix + sep + String(nextNum).padStart(pad, '0');

    this.config.next = nextNum + 1;
    this.saveConfig(); // Fire and forget

    return id;
  },

  /**
   * Retourne les données de démo
   * @returns {Array}
   */
  getDemoData() {
    return [
      {id:'REQ-001',nom:'LCD01 — Flux annuel CNSA',domaine:'LCD / CNSA',statut:'Actif',univers:'Solis_MDPH_Prod',freq:'Annuelle',proprio:'M. Dupont',date:'2023-01-15',desc:"Indicateurs de flux entrants/sortants du guichet MDPH pour le reporting LCD01 annuel transmis à la CNSA.",tags:['CNSA','LCD01','annuel'],limites:"Ne pas lancer avant clôture de l'exercice."},
      {id:'REQ-002',nom:'LCD02 — Délais d\'instruction',domaine:'LCD / CNSA',statut:'Actif',univers:'Solis_MDPH_Prod',freq:'Trimestrielle',proprio:'M. Dupont',date:'2023-03-10',desc:'Délais moyens d\'instruction par type de prestation (PCH, AEEH, AAH…).',tags:['CNSA','LCD02','délais'],limites:'Délais en jours ouvrés.'},
      {id:'REQ-003',nom:'Droits notifiés par prestation',domaine:'Droits et notifications',statut:'Actif',univers:'Solis_MDPH_Prod',freq:'Mensuelle',proprio:'C. Martin',date:'2022-11-05',desc:'Volume de droits notifiés par type de prestation et par période.',tags:['droits','notification','CDAPH'],limites:''},
      {id:'REQ-004',nom:'Droits ouverts — suivi annuel',domaine:'Droits et notifications',statut:'En révision',univers:'Solis_MDPH_Prod',freq:'Annuelle',proprio:'C. Martin',date:'2024-02-01',desc:'Droits effectivement ouverts (démarrage effectif de la prestation), distincts des droits notifiés.',tags:['droit ouvert','CNSA'],limites:'Requête en cours de validation métier.'},
      {id:'REQ-005',nom:'Orientations — taux réponse ES',domaine:'Orientations',statut:'Actif',univers:'Solis_MDPH_Prod',freq:'Trimestrielle',proprio:'L. Bernard',date:'2023-06-01',desc:'Taux de réponse des établissements aux orientations CDAPH.',tags:['orientations','ESMS'],limites:''},
      {id:'REQ-006',nom:'Orientations expirées sans suite',domaine:'Orientations',statut:'Actif',univers:'Solis_MDPH_Prod',freq:'Mensuelle',proprio:'L. Bernard',date:'2023-09-15',desc:'Orientations dont la date de fin est dépassée sans remplacement.',tags:['orientations','expiration','alerte'],limites:'Exécuter en début de mois.'},
      {id:'REQ-007',nom:'Flux entrants — hebdo guichet',domaine:'Flux et délais',statut:'Actif',univers:'Solis_MDPH_Prod',freq:'Hebdomadaire',proprio:'Service Accueil',date:'2022-05-12',desc:'Dossiers déposés par semaine, par canal (physique, courrier, démat).',tags:['flux','accueil'],limites:''},
      {id:'REQ-008',nom:'Tableaux de bord DG — trimestriel',domaine:'Pilotage interne',statut:'Actif',univers:'Solis_MDPH_Prod',freq:'Trimestrielle',proprio:'Direction',date:'2023-01-01',desc:'Synthèse consolidée à destination de la Direction Générale.',tags:['pilotage','DG','KPI'],limites:'Lancer hors pics d\'usage BO (>3 min).'},
      {id:'REQ-009',nom:'Suivi absentéisme — RH mensuel',domaine:'Ressources humaines',statut:'Brouillon',univers:'RH_Prod',freq:'Mensuelle',proprio:'DRH',date:'2024-09-01',desc:'Taux d\'absentéisme par direction sur 12 mois glissants.',tags:['RH','absentéisme','brouillon'],limites:'Ne pas utiliser en production.'},
      {id:'REQ-010',nom:'AEEH — dossiers actifs',domaine:'Droits et notifications',statut:'Actif',univers:'Solis_MDPH_Prod',freq:'À la demande',proprio:'C. Martin',date:'2022-08-20',desc:'Dossiers AEEH avec droits en cours de validité, filtrables par âge et territoire.',tags:['AEEH','enfant','droits actifs'],limites:''}
    ];
  },

  /**
   * Retourne la configuration par défaut
   * @returns {Object}
   */
  getDefaultConfig() {
    return {
      prefix: 'REQ',
      sep: '-',
      pad: 3,
      next: null,
      univers: [
        {name:'Solis_MDPH_Prod', desc:'Univers Solis production MDPH'},
        {name:'Solis_MDPH_Test', desc:'Univers Solis recette/test'},
        {name:'RH_Prod', desc:'Univers Ressources Humaines'}
      ],
      domaines: [
        {name:'LCD / CNSA', icon:'📊', bg:'#E8EDF5', group:'Reporting'},
        {name:'Droits et notifications', icon:'📋', bg:'#FEF0E6', group:'Metier'},
        {name:'Orientations', icon:'🔀', bg:'#EAF3DE', group:'Metier'},
        {name:'Flux et délais', icon:'⏱', bg:'#E6F1FB', group:'Metier'},
        {name:'Pilotage interne', icon:'📈', bg:'#FAEEDA', group:'Pilotage'},
        {name:'Ressources humaines', icon:'👥', bg:'#FBEAF0', group:'Support'},
        {name:'Autre', icon:'📁', bg:'#F1EFE8', group:'Sans groupe'}
      ],
      statuts: [
        {name:'Actif', color:'#3B6D11', bg:'#EAF3DE', desc:'Requête validée, en production'},
        {name:'Brouillon', color:'#854F0B', bg:'#FAEEDA', desc:'En cours de conception'},
        {name:'En révision', color:'#185FA5', bg:'#E6F1FB', desc:'En cours de validation métier'},
        {name:'Obsolète', color:'#A32D2D', bg:'#FCEBEB', desc:'Hors usage, conservée pour archivage'}
      ],
      frequences: ['À la demande','Quotidienne','Hebdomadaire','Mensuelle','Trimestrielle','Annuelle'],
      responsables: [
        {name:'M. Dupont', service:'Pôle Statistiques'},
        {name:'C. Martin', service:'Pôle Droits'},
        {name:'L. Bernard', service:'Pôle Orientations'},
        {name:'Service Accueil', service:'Guichet MDPH'},
        {name:'Direction', service:'DG'},
        {name:'DRH', service:'Ressources Humaines'}
      ]
    };
  },

  /**
   * Migration douce et retrocompatible de configuration.
   * Garantit les nouveaux champs sans perte de donnees existantes.
   */
  migrateConfig(config) {
    const base = config || this.getDefaultConfig();
    if (typeof ConfigDomain !== 'undefined' && ConfigDomain.ensureDomainGroups) {
      ConfigDomain.ensureDomainGroups(base);
    } else if (Array.isArray(base.domaines)) {
      base.domaines = base.domaines.map(d => ({ ...d, group: (d && d.group) ? d.group : 'Sans groupe' }));
    }
    return base;
  }
};

// Export global

// ═══════════════════════════════════════════════════════════════
// MODULE: FILTER-ENGINE
// ═══════════════════════════════════════════════════════════════

var FilterEngine = {
  // État des filtres
  currentView: 'cards',          // cards | table | tree
  navFilter: 'all',              // all | domaine:xxx | statut:xxx
  filteredData: [],              // Données filtrées

  /**
   * Applique tous les filtres actifs
   * @returns {Array} - Données filtrées
   */
  applyFilters() {
    const searchQuery = document.getElementById('search-input')?.value.toLowerCase() || '';
    const universeFilter = document.getElementById('filter-univers')?.value || '';
    const freqFilter = document.getElementById('filter-freq')?.value || '';
    this.filteredData = FilterDomain.applyFilters(DataManager.data, {
      navFilter: this.navFilter,
      searchQuery,
      universeFilter,
      freqFilter
    });

    // Mettre à jour le compteur de résultats
    const countElement = document.getElementById('result-count');
    if (countElement) {
      countElement.textContent = `${this.filteredData.length} requête(s)`;
    }

    return this.filteredData;
  },

  /**
   * Filtre par navigation (sidebar)
   * @param {string} filterKey - Clé du filtre (ex: "domaine:LCD / CNSA")
   * @param {HTMLElement} buttonElement - Bouton cliqué
   */
  filterByNav(filterKey, buttonElement) {
    // Désactiver tous les boutons de navigation
    document.querySelectorAll('.nav-item').forEach(btn => {
      btn.classList.remove('active');
    });

    // Activer le bouton cliqué
    if (buttonElement) {
      buttonElement.classList.add('active');
    }

    this.navFilter = filterKey;

    // Retourner sur la vue catalogue si l'utilisateur était ailleurs
    document.getElementById('view-settings').style.display = 'none';
    document.getElementById('view-ref').style.display = 'none';
    document.getElementById('view-catalogue').style.display = 'flex';

    this.applyFilters();

    // Déclencher le rendu
    if (ViewRenderer) {
      ViewRenderer.render();
    AppController.updateBulkBar();
    }
  },

  /**
   * Change la vue active (cards, table, tree)
   * @param {string} viewName - Nom de la vue
   */
  setView(viewName) {
    this.currentView = viewName;

    // Mettre à jour les boutons de vue
    ['cards', 'table', 'tree'].forEach(view => {
      const btn = document.getElementById(`btn-${view}`);
      if (btn) {
        btn.classList.toggle('active', view === viewName);
      }
    });

    // Déclencher le rendu
    if (ViewRenderer) {
      ViewRenderer.render();
    }
  },

  /**
   * Peuple les listes déroulantes de filtres
   */
  populateFilters() {
    // Filtre univers
    const universSelect = document.getElementById('filter-univers');
    if (universSelect) {
      const currentValue = universSelect.value;
      const universes = FilterOptionsDomain.getUniverseOptions(DataManager.data);

      universSelect.innerHTML = '<option value="">Tous les univers</option>' +
        universes.map(u => `<option value="${Utils.escapeHtml(u)}" ${u === currentValue ? 'selected' : ''}>${Utils.escapeHtml(u)}</option>`).join('');
    }

    // Filtre frequence
    const freqSelect = document.getElementById('filter-freq');
    if (freqSelect) {
      const currentValue = freqSelect.value;
      const frequencies = FilterOptionsDomain.getFrequencyOptions(DataManager.config);

      freqSelect.innerHTML = '<option value="">Toutes frequences</option>' +
        frequencies.map(f => `<option value="${Utils.escapeHtml(f)}" ${f === currentValue ? 'selected' : ''}>${Utils.escapeHtml(f)}</option>`).join('');
    }
  },

  /**
   * Réinitialise tous les filtres
   */
  resetFilters() {
    this.navFilter = 'all';

    const searchInput = document.getElementById('search-input');
    if (searchInput) searchInput.value = '';

    const universSelect = document.getElementById('filter-univers');
    if (universSelect) universSelect.value = '';

    const freqSelect = document.getElementById('filter-freq');
    if (freqSelect) freqSelect.value = '';

    // Réactiver le bouton "Toutes"
    const allBtn = document.getElementById('nav-all');
    if (allBtn) {
      document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
      allBtn.classList.add('active');
    }

    this.applyFilters();

    if (ViewRenderer) {
      ViewRenderer.render();
    }
  },

  /**
   * Recherche en temps réel
   */
  initSearch() {
    const searchInput = document.getElementById('search-input');
    if (searchInput) {
      const debouncedSearch = Utils.debounce(() => {
        this.applyFilters();
        if (ViewRenderer) {
          ViewRenderer.render();
        }
      }, 300);

      searchInput.addEventListener('input', debouncedSearch);
    }
  }
};

// Export global

// ═══════════════════════════════════════════════════════════════
// MODULE: VIEW-RENDERER
// ═══════════════════════════════════════════════════════════════

var ViewRenderer = {
  /**
   * Rend la vue active
   */
  render() {
    const container = document.getElementById('view-container');
    if (!container) return;

    const data = FilterEngine.filteredData;

    // État vide
    if (!data.length) {
      container.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-icon">🔍</div>
          <h3>Aucune requête trouvée</h3>
          <p>Modifiez vos filtres ou créez une nouvelle requête.</p>
        </div>`;
      return;
    }

    // Rendu selon la vue active
    switch (FilterEngine.currentView) {
      case 'cards':
        this.renderCards(container, data);
        break;
      case 'table':
        this.renderTable(container, data);
        break;
      case 'tree':
        this.renderTree(container, data);
        break;
    }
  },

  /**
   * Rend la vue en cartes
   */
  renderCards(container, data) {
    container.innerHTML = '<div class="cards-grid">' +
      data.map(r => this.generateCardHTML(r)).join('') +
      '</div>';
  },

  /**
   * Génère le HTML d'une carte
   */
  generateCardHTML(requete) {
    const domain = this.getDomainInfo(requete.domaine);
    const status = this.getStatusInfo(requete.statut);
    const tags = (requete.tags || [])
      .slice(0, 3)
      .map(t => {
        const color = Utils.tagColor(t);
        return `<span class="tag" style="background:${color.bg};color:${color.color}">${Utils.escapeHtml(t)}</span>`;
      })
      .join('');

    return `
      
      <div class="req-card ${AppController.selectedIds.includes(requete.id) ? 'selected' : ''}" onclick="UIComponents.openDetail('${Utils.escapeHtml(requete.id)}')">
        <div class="card-selection ${AppController.selectedIds.includes(requete.id) ? 'selected' : ''}" onclick="AppController.toggleSelection('${Utils.escapeHtml(requete.id)}', event)">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>
        </div>
        <div class="card-header">
          <div class="card-domain-icon" style="background:${domain.bg}">${domain.icon}</div>
          <div class="card-meta">
            <div class="card-title" title="${Utils.escapeHtml(requete.nom)}">${Utils.escapeHtml(requete.nom)}</div>
            <div class="card-subtitle">${Utils.escapeHtml(requete.id || '')} ${requete.univers ? '· ' + Utils.escapeHtml(requete.univers) : ''}</div>
          </div>
        </div>
        ${requete.desc ? `<div class="card-desc">${Utils.escapeHtml(Utils.stripHtml(requete.desc))}</div>` : ''}
        ${tags ? `<div class="card-tags">${tags}</div>` : ''}
        <div class="card-footer">
          ${this.generateStatusBadge(requete)}
          <span style="font-size:11px;color:var(--gray-400);margin-left:4px">${Utils.escapeHtml(requete.freq || '')}</span>
          ${requete.proprio ? `<div class="card-owner"><div class="avatar-sm">${Utils.initials(requete.proprio)}</div>${Utils.escapeHtml(requete.proprio)}</div>` : ''}
        </div>
      </div>`;
  },

  /**
   * Rend la vue en tableau
   */
  renderTable(container, data) {
    container.innerHTML = `
      <div class="table-view">
        <table>
          <thead>
            <tr>
              
              <th class="row-selection">
                <div class="check-custom ${AppController.selectedIds.length === data.length && data.length > 0 ? 'selected' : ''}" onclick="AppController.selectAll()">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>
                </div>
              </th>
              <th>ID</th>
              <th>Nom</th>
              <th>Domaine</th>
              <th>Univers</th>
              <th>Statut</th>
              <th>Fréquence</th>
              <th>Tags</th>
              <th>Responsable</th>
            </tr>
          </thead>
          <tbody>
            ${data.map(r => this.generateTableRowHTML(r)).join('')}
          </tbody>
        </table>
      </div>`;
  },

  /**
   * Génère le HTML d'une ligne de tableau
   */
  generateTableRowHTML(requete) {
    const isSelected = AppController.selectedIds.includes(requete.id);
    const domain = this.getDomainInfo(requete.domaine);
    const tags = (requete.tags || [])
      .slice(0, 2)
      .map(t => {
        const color = Utils.tagColor(t);
        return `<span class="tag" style="background:${color.bg};color:${color.color};font-size:10px">${Utils.escapeHtml(t)}</span>`;
      })
      .join(' ');

    return `
      
      <tr class="${isSelected ? 'selected' : ''}" onclick="UIComponents.openDetail('${Utils.escapeHtml(requete.id)}')">
        <td class="row-selection" onclick="AppController.toggleSelection('${Utils.escapeHtml(requete.id)}', event)">
          <div class="check-custom ${isSelected ? 'selected' : ''}">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>
          </div>
        </td>
        <td style="font-family:var(--font-mono);font-size:11px;color:var(--gray-400)">${Utils.escapeHtml(requete.id || '—')}</td>
        <td><strong style="color:var(--gray-800)">${Utils.escapeHtml(requete.nom)}</strong></td>
        <td>${domain.icon} ${Utils.escapeHtml(requete.domaine)}</td>
        <td style="font-family:var(--font-mono);font-size:11px">${Utils.escapeHtml(requete.univers || '—')}</td>
        <td>${this.generateStatusBadge(requete)}</td>
        <td>${Utils.escapeHtml(requete.freq || '—')}</td>
        <td>${tags}</td>
        <td>${Utils.escapeHtml(requete.proprio || '—')}</td>
      </tr>`;
  },

  /**
   * Rend la vue en arbre
   */
  renderTree(container, data) {
    const domains = [...new Set(data.map(r => r.domaine))];

    container.innerHTML = domains.map(domainName => {
      const items = data.filter(r => r.domaine === domainName);
      const domain = this.getDomainInfo(domainName);
      const treeId = 'tr' + domainName.replace(/\W/g, '');

      return `
        <div class="tree-domain">
          <div class="tree-domain-header" onclick="ViewRenderer.toggleTree('${treeId}')">
            <span style="font-size:20px">${domain.icon}</span>
            <span style="font-weight:600;font-size:14px;color:var(--gray-800)">${Utils.escapeHtml(domainName)}</span>
            <span class="tree-domain-count">${items.length}</span>
            <svg class="chevron open" id="cv${treeId}" width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="var(--gray-400)" stroke-width="2">
              <path d="M5 3l4 4-4 4"/>
            </svg>
          </div>
          <div class="tree-items" id="${treeId}">
            ${items.map(r => this.generateTreeItemHTML(r)).join('')}
          </div>
        </div>`;
    }).join('');
  },

  /**
   * Génère le HTML d'un élément d'arbre
   */
  generateTreeItemHTML(requete) {
    const status = this.getStatusInfo(requete.statut);

    return `
      <div class="tree-item" onclick="UIComponents.openDetail('${Utils.escapeHtml(requete.id)}')">
        <span style="width:8px;height:8px;border-radius:50%;background:${status.color};flex-shrink:0"></span>
        <span class="tree-item-name">${Utils.escapeHtml(requete.nom)}</span>
        <span class="tree-item-id">${Utils.escapeHtml(requete.id || '')}</span>
        ${this.generateStatusBadge(requete)}
      </div>`;
  },

  /**
   * Toggle l'affichage d'une section d'arbre
   */
  toggleTree(treeId) {
    const element = document.getElementById(treeId);
    const chevron = document.getElementById('cv' + treeId);

    if (element && chevron) {
      const isVisible = element.style.display !== 'none';
      element.style.display = isVisible ? 'none' : '';
      chevron.classList.toggle('open', !isVisible);
    }
  },

  /**
   * Génère un badge de statut
   */
  generateStatusBadge(requete) {
    const status = this.getStatusInfo(requete.statut);

    return `
      <span style="background:${status.bg};color:${status.color};font-size:11px;font-weight:500;padding:3px 8px;border-radius:4px;display:inline-flex;align-items:center;gap:4px">
        <span style="width:6px;height:6px;border-radius:50%;background:${status.color}"></span>
        ${Utils.escapeHtml(requete.statut)}
      </span>`;
  },

  /**
   * Récupère les infos d'un domaine
   */
  getDomainInfo(domainName) {
    return DataManager.config.domaines?.find(d => d.name === domainName) || {
      icon: '📁',
      bg: '#F1EFE8'
    };
  },

  /**
   * Récupère les infos d'un statut
   */
  getStatusInfo(statusName) {
    return DataManager.config.statuts?.find(s => s.name === statusName) || {
      color: '#9B9990',
      bg: '#F8F7F4'
    };
  },

  /**
   * Rend la sidebar avec les compteurs
   */
  renderSidebar() {
    // Mettre à jour le compteur total
    const countAll = document.getElementById('count-all');
    if (countAll) {
      countAll.textContent = DataManager.data.length;
    }

    // Rendre la navigation par domaine
    const domainNav = document.getElementById('domain-nav');
    if (domainNav && DataManager.config.domaines) {
      const grouped = ConfigDomain.groupDomainsByCategory(DataManager.config.domaines);
      const groupNames = Object.keys(grouped);
      domainNav.innerHTML = groupNames.map(groupName => {
        const domainButtons = grouped[groupName].map(domain => {
          const count = DataManager.data.filter(r => r.domaine === domain.name).length;
          return `
            <button class="nav-item" data-filter-key="domaine:${Utils.escapeHtml(domain.name)}">
              ${domain.icon} ${Utils.escapeHtml(domain.name)}
              <span class="nav-count">${count}</span>
            </button>`;
        }).join('');
        return `
          <div class="nav-subgroup">
            <div class="nav-subgroup-title">${Utils.escapeHtml(groupName)}</div>
            ${domainButtons}
          </div>`;
      }).join('');

      // Attacher les événements pour les domaines
      const domainButtons = domainNav.querySelectorAll('.nav-item');
      domainButtons.forEach(btn => {
        const filterKey = btn.getAttribute('data-filter-key');
        btn.addEventListener('click', function() {
          FilterEngine.filterByNav(this.getAttribute('data-filter-key'), this);
        });
      });
    }

    // Rendre la navigation par statut
    const statusNav = document.getElementById('status-nav');
    if (statusNav && DataManager.config.statuts) {
      statusNav.innerHTML = DataManager.config.statuts.map(status => {
        const count = DataManager.data.filter(r => r.statut === status.name).length;
        return `
          <button class="nav-item" data-filter-key="statut:${Utils.escapeHtml(status.name)}">
            <span class="nav-dot" style="background:${status.color}"></span>
            ${Utils.escapeHtml(status.name)}
            <span class="nav-count">${count}</span>
          </button>`;
      }).join('');

      // Attacher les événements pour les statuts
      const statusButtons = statusNav.querySelectorAll('.nav-item');
      statusButtons.forEach(btn => {
        const filterKey = btn.getAttribute('data-filter-key');
        btn.addEventListener('click', function() {
          FilterEngine.filterByNav(this.getAttribute('data-filter-key'), this);
        });
      });
    }
  },

  /**
   * Rend la barre de statistiques
   */
  renderStats() {
    const statsBar = document.getElementById('stats-bar');
    if (!statsBar) return;

    const total = DataManager.data.length;
    const actives = DataManager.data.filter(r => r.statut === 'Actif').length;
    const uniqueUniverses = [...new Set(DataManager.data.map(r => r.univers).filter(Boolean))].length;
    const uniqueDomains = [...new Set(DataManager.data.map(r => r.domaine))].length;
    const percentage = total ? Math.round(actives / total * 100) : 0;

    statsBar.innerHTML = `
      <div class="stat-card">
        <div class="stat-label">Total</div>
        <div class="stat-value">${total}</div>
        <div class="stat-sub">requêtes</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Actives</div>
        <div class="stat-value" style="color:var(--green)">${actives}</div>
        <div class="stat-sub">${percentage}%</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Domaines</div>
        <div class="stat-value" style="color:var(--navy)">${uniqueDomains}</div>
        <div class="stat-sub">fonctionnels</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Univers</div>
        <div class="stat-value" style="color:var(--orange)">${uniqueUniverses}</div>
        <div class="stat-sub">BO sources</div>
      </div>`;
  }
};

// Export global

// ═══════════════════════════════════════════════════════════════
// MODULE: EXPORT-HANDLER
// ═══════════════════════════════════════════════════════════════

var ExportHandler = {
  /**
   * Exporte tout en JSON
   */
  exportJSON() {
    const exportData = {
      catalogue: DataManager.data,
      config: DataManager.config,
      exportDate: new Date().toISOString(),
      version: '2.0'
    };

    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `catalogue_BO_${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);

    UIComponents.showToast('Export JSON téléchargé.', 'success');
  },

  /**
   * Exporte en Excel (XLSX) - VERSION CORRIGÉE
   * Utilise une approche simplifiée avec CSV encodé en UTF-8 BOM
   */
  exportExcel() {
    // Définir les colonnes
    const columns = [
      { key: 'id', label: 'Identifiant BO' },
      { key: 'nom', label: 'Nom de la requête' },
      { key: 'domaine', label: 'Domaine fonctionnel' },
      { key: 'statut', label: 'Statut' },
      { key: 'univers', label: 'Univers BO' },
      { key: 'freq', label: 'Fréquence' },
      { key: 'proprio', label: 'Responsable' },
      { key: 'date', label: 'Date de création' },
      { key: 'desc', label: 'Description / Objet métier' },
      { key: 'tags', label: 'Tags' },
      { key: 'limites', label: 'Limites & précautions' }
    ];

    // Créer le CSV avec BOM UTF-8
    const BOM = '\uFEFF';

    // En-têtes
    let csv = BOM + columns.map(c => this.escapeCSV(c.label)).join('\t') + '\n';

    // Données
    DataManager.data.forEach(row => {
      const values = columns.map(col => {
        let value = row[col.key] || '';
        if (col.key === 'tags' && Array.isArray(row.tags)) {
          value = row.tags.join(', ');
        }
        return this.escapeCSV(String(value));
      });
      csv += values.join('\t') + '\n';
    });

    // Créer le fichier Excel (format TSV compatible Excel)
    const blob = new Blob([csv], { type: 'text/tab-separated-values;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `catalogue_BO_${new Date().toISOString().slice(0, 10)}.xls`;
    a.click();
    URL.revokeObjectURL(url);

    UIComponents.showToast(`Export Excel — ${DataManager.data.length} requête(s).`, 'success');
  },

  /**
   * Échappe les valeurs CSV
   */
  escapeCSV(value) {
    if (typeof value !== 'string') value = String(value);

    // Si la valeur contient des guillemets, tabulations ou retours chariot
    if (value.includes('"') || value.includes('\t') || value.includes('\n')) {
      return '"' + value.replace(/"/g, '""') + '"';
    }

    return value;
  },

  /**
   * Export XLSX avancé (OpenXML format) - VERSION ALTERNATIVE
   * Cette version génère un vrai fichier XLSX si nécessaire
   */
  /**
   * Génère le Blob Excel avec SheetJS
   * @returns {Blob} Blob du fichier Excel
   */
  generateExcelBlob() {
    if (typeof XLSX === 'undefined') {
      throw new Error("La librairie XLSX n'est pas chargée.");
    }
    
    const wb = XLSX.utils.book_new();

    // --- ONGLET 1 : CATALOGUE ---
    const columns = [
      'Identifiant BO', 'Nom de la requête', 'Domaine fonctionnel',
      'Statut', 'Univers BO', 'Fréquence', 'Responsable',
      'Date de création', 'Description / Objet métier', 'Tags',
      'Limites & précautions'
    ];
    
    const rows = DataManager.data.map(r => [
      r.id || '',
      r.nom || '',
      r.domaine || '',
      r.statut || '',
      r.univers || '',
      r.freq || '',
      r.proprio || '',
      r.date || '',
      r.desc || '',
      (r.tags || []).join(', '),
      r.limites || ''
    ]);
    
    const wsCatalogue = XLSX.utils.aoa_to_sheet([columns, ...rows]);
    XLSX.utils.book_append_sheet(wb, wsCatalogue, "Catalogue BO");

    // --- ONGLET 2 : CONFIGURATION ---
    const configRows = [
      ['Type', 'Valeur', 'Couleur_Icone_Email']
    ];
    
    const conf = DataManager.config;
    if (conf.univers) conf.univers.forEach(u => configRows.push(['Univers', u.name, '']));
    if (conf.domaines) conf.domaines.forEach(d => configRows.push(['Domaine', d.name, d.icon || '']));
    if (conf.statuts) conf.statuts.forEach(s => configRows.push(['Statut', s.name, s.color || '']));
    if (conf.frequences) conf.frequences.forEach(f => configRows.push(['Fréquence', f.name, '']));
    if (conf.responsables) conf.responsables.forEach(r => configRows.push(['Responsable', r.name, r.email || '']));
    
    const wsConfig = XLSX.utils.aoa_to_sheet(configRows);
    XLSX.utils.book_append_sheet(wb, wsConfig, "Configuration");

    const wbout = XLSX.write(wb, { bookType: 'xlsx', type: 'array' });
    return new Blob([wbout], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' });
  },

  async exportExcelAdvanced() {
    try {
      const blob = this.generateExcelBlob();
      
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `catalogue_BO_${new Date().toISOString().slice(0, 10)}.xlsx`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      UIComponents.showToast(`Export Excel — ${DataManager.data.length} requête(s) et config.`, 'success');
    } catch (error) {
      console.error('Erreur export Excel:', error);
      UIComponents.showToast("Erreur lors de l'export Excel.", 'error');
    }
  },

  /**
   * Importe des données depuis JSON
   */
  async importJSON() {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json';

    input.onchange = async (e) => {
      const file = e.target.files[0];
      if (!file) return;

      try {
        const text = await file.text();
        const parsed = JSON.parse(text);

        if (Array.isArray(parsed)) {
          // Format ancien (array simple)
          DataManager.data = parsed;
        } else if (parsed.catalogue) {
          // Format nouveau (object avec catalogue + config)
          DataManager.data = parsed.catalogue;
          if (parsed.config) {
            DataManager.config = { ...DataManager.config, ...parsed.config };
          }
        } else {
          throw new Error('Format JSON invalide');
        }

        await DataManager.saveData();
        await DataManager.saveConfig();

        // Rafraîchir l'interface
        if (window.AppController) {
          window.AppController.refresh();
        }

        UIComponents.showToast(`${DataManager.data.length} requêtes importées.`, 'success');
      } catch (error) {
        console.error('Erreur import:', error);
        UIComponents.showToast('Fichier JSON invalide.', 'error');
      }
    };

    input.click();
  }
};

// Export global

// ═══════════════════════════════════════════════════════════════
// MODULE: CONFIG-MANAGER
// ═══════════════════════════════════════════════════════════════

var ConfigManager = {
  /**
   * Rend tous les panneaux de configuration
   */
  renderAll() {
    this.renderUniverses();
    this.renderDomains();
    this.renderStatuses();
    this.renderFrequencies();
    this.renderResponsibles();
    this.loadNumberingConfig();
  },

  /**
   * Compte l'utilisation d'une valeur dans un champ
   */
  countUsage(field, value) {
    return DataManager.data.filter(r => r[field] === value).length;
  },

  /**
   * Génère un bouton de suppression
   */
  deleteButton(onclick) {
    return `<button class="btn-icon del" onclick="${onclick}" title="Supprimer">✕</button>`;
  },
  editButton(onclick) {
    return `<button class="btn-icon" onclick="${onclick}" title="Modifier">✎</button>`;
  },

  // ═══════════════ UNIVERS ═══════════════
  renderUniverses() {
    const list = document.getElementById('list-univers');
    if (!list) return;

    const items = DataManager.config.univers || [];
    list.innerHTML = items.map((u, i) => {
      const count = this.countUsage('univers', u.name);
      return `
        <div class="s-row">
          <span class="s-row-icon">🗄</span>
          <div class="s-row-main">
            <div class="s-row-label">${Utils.escapeHtml(u.name)}</div>
            ${u.desc ? `<div class="s-row-sub">${Utils.escapeHtml(u.desc)}</div>` : ''}
          </div>
          <span class="s-badge">${count} requête${count !== 1 ? 's' : ''}</span>
          ${this.editButton(`ConfigManager.editUniverse(${i})`)}
          ${this.deleteButton(`ConfigManager.deleteUniverse(${i})`)}
        </div>`;
    }).join('') || '<div class="s-empty">Aucun univers configuré.</div>';
  },

  addUniverse() {
    const nameInput = document.getElementById('ui-name');
    const descInput = document.getElementById('ui-desc');
    const name = nameInput.value.trim();
    const desc = descInput.value.trim();

    if (!name) {
      UIComponents.showToast('Nom obligatoire.', 'error');
      return;
    }

    if (DataManager.config.univers.find(u => u.name === name)) {
      UIComponents.showToast('Cet univers existe déjà.', 'error');
      return;
    }

    DataManager.config.univers.push({ name, desc });
    DataManager.saveConfig();
    this.renderUniverses();
    FilterEngine.populateFilters();

    nameInput.value = '';
    descInput.value = '';
    UIComponents.showToast('Univers ajouté.', 'success');
  },

  deleteUniverse(index) {
    DataManager.config.univers.splice(index, 1);
    DataManager.saveConfig();
    this.renderUniverses();
    FilterEngine.populateFilters();
    UIComponents.showToast('Univers supprimé.', 'success');
  },
  async editUniverse(index) {
    const item = DataManager.config.univers[index];
    if (!item) return;
    const oldName = item.name;
    const newNameRaw = prompt('Modifier le nom de l\'univers :', oldName || '');
    if (newNameRaw === null) return;
    const newName = ConfigDomain.normalizeText(newNameRaw);
    const newDescRaw = prompt('Modifier la description (optionnelle) :', item.desc || '');
    if (newDescRaw === null) return;
    const newDesc = ConfigDomain.normalizeText(newDescRaw);
    if (!newName) {
      UIComponents.showToast('Nom obligatoire.', 'error');
      return;
    }
    if (ConfigDomain.isDuplicateName(DataManager.config.univers, newName, index)) {
      UIComponents.showToast('Cet univers existe déjà.', 'error');
      return;
    }
    item.name = newName;
    item.desc = newDesc;
    ConfigDomain.renameInData(DataManager.data, 'univers', oldName, newName);
    await DataManager.saveData();
    await DataManager.saveConfig();
    this.renderUniverses();
    FilterEngine.populateFilters();
    if (window.AppController) window.AppController.refresh();
    UIComponents.showToast('Univers modifié.', 'success');
  },

  // ═══════════════ DOMAINES ═══════════════
  renderDomains() {
    const list = document.getElementById('list-domaines');
    if (!list) return;

    const items = DataManager.config.domaines || [];
    list.innerHTML = items.map((d, i) => {
      const count = this.countUsage('domaine', d.name);
      return `
        <div class="s-row">
          <input class="emoji-input" type="text" maxlength="2" value="${Utils.escapeHtml(d.icon)}"
            onchange="DataManager.config.domaines[${i}].icon=this.value;DataManager.saveConfig();AppController.refresh()"
            style="width:40px;height:30px;font-size:17px" title="Emoji">
          <div class="color-swatch" title="Couleur de fond">
            <div class="color-preview" style="background:${d.bg}" id="dp${i}"></div>
            <input type="color" value="${d.bg}"
              oninput="DataManager.config.domaines[${i}].bg=this.value;document.getElementById('dp${i}').style.background=this.value"
              onchange="DataManager.saveConfig();AppController.refresh()">
          </div>
          <div class="s-row-main">
            <div class="s-row-label">${Utils.escapeHtml(d.name)}</div>
            <div class="s-row-sub">Groupe : ${Utils.escapeHtml((d.group || 'Sans groupe'))}</div>
          </div>
          <span class="s-badge">${count} requête${count !== 1 ? 's' : ''}</span>
          ${this.editButton(`ConfigManager.editDomain(${i})`)}
          ${count === 0 ? this.deleteButton(`ConfigManager.deleteDomain(${i})`) : '<span class="s-used">utilisé</span>'}
        </div>`;
    }).join('') || '<div class="s-empty">Aucun domaine configuré.</div>';
  },

  addDomain() {
    const iconInput = document.getElementById('di-icon');
    const nameInput = document.getElementById('di-name');
    const groupInput = document.getElementById('di-group');
    const icon = iconInput.value.trim() || '📁';
    const name = nameInput.value.trim();
    const group = ConfigDomain.normalizeDomainGroup(groupInput?.value);

    if (!name) {
      UIComponents.showToast('Nom obligatoire.', 'error');
      return;
    }

    if (DataManager.config.domaines.find(d => d.name === name)) {
      UIComponents.showToast('Ce domaine existe déjà.', 'error');
      return;
    }

    DataManager.config.domaines.push({ name, icon, bg: '#F1EFE8', group });
    DataManager.saveConfig();
    this.renderDomains();

    if (window.AppController) {
      window.AppController.refresh();
    }

    iconInput.value = '';
    nameInput.value = '';
    if (groupInput) groupInput.value = '';
    UIComponents.showToast('Domaine ajouté.', 'success');
  },

  deleteDomain(index) {
    DataManager.config.domaines.splice(index, 1);
    DataManager.saveConfig();
    this.renderDomains();

    if (window.AppController) {
      window.AppController.refresh();
    }

    UIComponents.showToast('Domaine supprimé.', 'success');
  },
  async editDomain(index) {
    const item = DataManager.config.domaines[index];
    if (!item) return;
    const oldName = item.name;
    const newNameRaw = prompt('Modifier le nom du domaine :', oldName || '');
    if (newNameRaw === null) return;
    const newName = ConfigDomain.normalizeText(newNameRaw);
    const newGroupRaw = prompt('Modifier le groupe du domaine :', item.group || 'Sans groupe');
    if (newGroupRaw === null) return;
    const newGroup = ConfigDomain.normalizeDomainGroup(newGroupRaw);
    if (!newName) {
      UIComponents.showToast('Nom obligatoire.', 'error');
      return;
    }
    if (ConfigDomain.isDuplicateName(DataManager.config.domaines, newName, index)) {
      UIComponents.showToast('Ce domaine existe déjà.', 'error');
      return;
    }
    item.name = newName;
    item.group = newGroup;
    ConfigDomain.renameInData(DataManager.data, 'domaine', oldName, newName);
    await DataManager.saveData();
    await DataManager.saveConfig();
    this.renderDomains();
    if (window.AppController) window.AppController.refresh();
    UIComponents.showToast('Domaine modifié.', 'success');
  },

  // ═══════════════ STATUTS ═══════════════
  renderStatuses() {
    const list = document.getElementById('list-statuts');
    if (!list) return;

    const items = DataManager.config.statuts || [];
    list.innerHTML = items.map((s, i) => {
      const count = this.countUsage('statut', s.name);
      return `
        <div class="s-row">
          <span class="color-dot" style="background:${s.color}"></span>
          <div class="s-row-main">
            <div class="s-row-label">${Utils.escapeHtml(s.name)}</div>
            ${s.desc ? `<div class="s-row-sub">${Utils.escapeHtml(s.desc)}</div>` : ''}
          </div>
          <span class="s-badge">${count} requête${count !== 1 ? 's' : ''}</span>
          ${this.editButton(`ConfigManager.editStatus(${i})`)}
          ${count === 0 ? this.deleteButton(`ConfigManager.deleteStatus(${i})`) : '<span class="s-used">utilisé</span>'}
        </div>`;
    }).join('') || '<div class="s-empty">Aucun statut configuré.</div>';
  },

  addStatus() {
    const colorInput = document.getElementById('si-color');
    const nameInput = document.getElementById('si-name');
    const descInput = document.getElementById('si-desc');
    const color = colorInput.value;
    const name = nameInput.value.trim();
    const desc = descInput.value.trim();

    if (!name) {
      UIComponents.showToast('Nom obligatoire.', 'error');
      return;
    }

    if (DataManager.config.statuts.find(s => s.name === name)) {
      UIComponents.showToast('Ce statut existe déjà.', 'error');
      return;
    }

    DataManager.config.statuts.push({ name, color, bg: color + '20', desc });
    DataManager.saveConfig();
    this.renderStatuses();

    if (window.AppController) {
      window.AppController.refresh();
    }

    nameInput.value = '';
    descInput.value = '';
    UIComponents.showToast('Statut ajouté.', 'success');
  },

  deleteStatus(index) {
    DataManager.config.statuts.splice(index, 1);
    DataManager.saveConfig();
    this.renderStatuses();

    if (window.AppController) {
      window.AppController.refresh();
    }

    UIComponents.showToast('Statut supprimé.', 'success');
  },
  async editStatus(index) {
    const item = DataManager.config.statuts[index];
    if (!item) return;
    const oldName = item.name;
    const newNameRaw = prompt('Modifier le nom du statut :', oldName || '');
    if (newNameRaw === null) return;
    const newName = ConfigDomain.normalizeText(newNameRaw);
    const newDescRaw = prompt('Modifier la description (optionnelle) :', item.desc || '');
    if (newDescRaw === null) return;
    const newDesc = ConfigDomain.normalizeText(newDescRaw);
    if (!newName) {
      UIComponents.showToast('Nom obligatoire.', 'error');
      return;
    }
    if (ConfigDomain.isDuplicateName(DataManager.config.statuts, newName, index)) {
      UIComponents.showToast('Ce statut existe déjà.', 'error');
      return;
    }
    item.name = newName;
    item.desc = newDesc;
    ConfigDomain.renameInData(DataManager.data, 'statut', oldName, newName);
    await DataManager.saveData();
    await DataManager.saveConfig();
    this.renderStatuses();
    if (window.AppController) window.AppController.refresh();
    UIComponents.showToast('Statut modifié.', 'success');
  },

  // ═══════════════ FRÉQUENCES ═══════════════
  renderFrequencies() {
    const list = document.getElementById('list-frequences');
    if (!list) return;

    const items = DataManager.config.frequences || [];
    list.innerHTML = items.map((f, i) => {
      const count = this.countUsage('freq', f);
      return `
        <div class="s-row">
          <span class="s-row-icon">🔄</span>
          <div class="s-row-label">${Utils.escapeHtml(f)}</div>
          <span class="s-badge">${count} requête${count !== 1 ? 's' : ''}</span>
          ${this.editButton(`ConfigManager.editFrequency(${i})`)}
          ${count === 0 ? this.deleteButton(`ConfigManager.deleteFrequency(${i})`) : '<span class="s-used">utilisée</span>'}
        </div>`;
    }).join('') || '<div class="s-empty">Aucune fréquence.</div>';
  },

  addFrequency() {
    const nameInput = document.getElementById('fi-name');
    const name = nameInput.value.trim();

    if (!name) {
      UIComponents.showToast('Nom obligatoire.', 'error');
      return;
    }

    if (DataManager.config.frequences.includes(name)) {
      UIComponents.showToast('Déjà existante.', 'error');
      return;
    }

    DataManager.config.frequences.push(name);
    DataManager.saveConfig();
    this.renderFrequencies();
    FilterEngine.populateFilters();

    nameInput.value = '';
    UIComponents.showToast('Fréquence ajoutée.', 'success');
  },

  deleteFrequency(index) {
    DataManager.config.frequences.splice(index, 1);
    DataManager.saveConfig();
    this.renderFrequencies();
    FilterEngine.populateFilters();
    UIComponents.showToast('Fréquence supprimée.', 'success');
  },
  async editFrequency(index) {
    const current = DataManager.config.frequences[index];
    if (!current) return;
    const newNameRaw = prompt('Modifier la fréquence :', current);
    if (newNameRaw === null) return;
    const newName = ConfigDomain.normalizeText(newNameRaw);
    if (!newName) {
      UIComponents.showToast('Nom obligatoire.', 'error');
      return;
    }
    if (ConfigDomain.isDuplicateName(DataManager.config.frequences, newName, index)) {
      UIComponents.showToast('Déjà existante.', 'error');
      return;
    }
    DataManager.config.frequences[index] = newName;
    ConfigDomain.renameInData(DataManager.data, 'freq', current, newName);
    await DataManager.saveData();
    await DataManager.saveConfig();
    this.renderFrequencies();
    FilterEngine.populateFilters();
    if (window.AppController) window.AppController.refresh();
    UIComponents.showToast('Fréquence modifiée.', 'success');
  },

  // ═══════════════ RESPONSABLES ═══════════════
  renderResponsibles() {
    const list = document.getElementById('list-responsables');
    if (!list) return;

    const items = DataManager.config.responsables || [];
    list.innerHTML = items.map((r, i) => {
      const count = this.countUsage('proprio', r.name);
      return `
        <div class="s-row">
          <div class="avatar-sm" style="width:28px;height:28px;font-size:10px">${Utils.initials(r.name)}</div>
          <div class="s-row-main">
            <div class="s-row-label">${Utils.escapeHtml(r.name)}</div>
            ${r.service ? `<div class="s-row-sub">${Utils.escapeHtml(r.service)}</div>` : ''}
          </div>
          <span class="s-badge">${count} requête${count !== 1 ? 's' : ''}</span>
          ${this.editButton(`ConfigManager.editResponsible(${i})`)}
          ${this.deleteButton(`ConfigManager.deleteResponsible(${i})`)}
        </div>`;
    }).join('') || '<div class="s-empty">Aucun responsable.</div>';
  },

  addResponsible() {
    const nameInput = document.getElementById('ri-name');
    const serviceInput = document.getElementById('ri-service');
    const name = nameInput.value.trim();
    const service = serviceInput.value.trim();

    if (!name) {
      UIComponents.showToast('Nom obligatoire.', 'error');
      return;
    }

    DataManager.config.responsables.push({ name, service });
    DataManager.saveConfig();
    this.renderResponsibles();

    nameInput.value = '';
    serviceInput.value = '';
    UIComponents.showToast('Responsable ajouté.', 'success');
  },

  deleteResponsible(index) {
    DataManager.config.responsables.splice(index, 1);
    DataManager.saveConfig();
    this.renderResponsibles();
    UIComponents.showToast('Responsable supprimé.', 'success');
  },
  async editResponsible(index) {
    const item = DataManager.config.responsables[index];
    if (!item) return;
    const oldName = item.name;
    const newNameRaw = prompt('Modifier le nom du responsable :', oldName || '');
    if (newNameRaw === null) return;
    const newName = ConfigDomain.normalizeText(newNameRaw);
    const newServiceRaw = prompt('Modifier le service (optionnel) :', item.service || '');
    if (newServiceRaw === null) return;
    const newService = ConfigDomain.normalizeText(newServiceRaw);
    if (!newName) {
      UIComponents.showToast('Nom obligatoire.', 'error');
      return;
    }
    if (ConfigDomain.isDuplicateName(DataManager.config.responsables, newName, index)) {
      UIComponents.showToast('Ce responsable existe déjà.', 'error');
      return;
    }
    item.name = newName;
    item.service = newService;
    ConfigDomain.renameInData(DataManager.data, 'proprio', oldName, newName);
    await DataManager.saveData();
    await DataManager.saveConfig();
    this.renderResponsibles();
    if (window.AppController) window.AppController.refresh();
    UIComponents.showToast('Responsable modifié.', 'success');
  },

  // ═══════════════ NUMÉROTATION ═══════════════
  loadNumberingConfig() {
    const prefixInput = document.getElementById('cfg-prefix');
    const sepInput = document.getElementById('cfg-sep');
    const padInput = document.getElementById('cfg-pad');
    const nextInput = document.getElementById('cfg-next');

    if (prefixInput) prefixInput.value = DataManager.config.prefix || 'REQ';
    if (sepInput) sepInput.value = DataManager.config.sep || '-';
    if (padInput) padInput.value = String(DataManager.config.pad || 3);
    if (nextInput) nextInput.value = DataManager.config.next || '';

    this.previewId();
  },

  previewId() {
    const preview = document.getElementById('id-preview');
    if (!preview) return;

    const prefix = document.getElementById('cfg-prefix')?.value || DataManager.config.prefix || 'REQ';
    const sep = document.getElementById('cfg-sep')?.value ?? DataManager.config.sep ?? '-';
    const pad = parseInt(document.getElementById('cfg-pad')?.value || DataManager.config.pad) || 3;
    const nextValue = parseInt(document.getElementById('cfg-next')?.value) ||
      DataManager.data.reduce((max, r) => {
        const num = parseInt((r.id || '').replace(/\D/g, '')) || 0;
        return Math.max(max, num);
      }, 0) + 1;

    preview.textContent = prefix + sep + String(nextValue).padStart(pad, '0');
  },

  saveNumberingConfig() {
    DataManager.config.prefix = document.getElementById('cfg-prefix').value || 'REQ';
    DataManager.config.sep = document.getElementById('cfg-sep').value;
    DataManager.config.pad = parseInt(document.getElementById('cfg-pad').value) || 3;

    const nextValue = parseInt(document.getElementById('cfg-next').value);
    DataManager.config.next = isNaN(nextValue) ? null : nextValue;

    DataManager.saveConfig();
    this.previewId();
    UIComponents.showToast('Configuration enregistrée.', 'success');
  },

  resetConfig() {
    if (!confirm('Réinitialiser toute la configuration aux valeurs par défaut ?')) {
      return;
    }

    DataManager.config = DataManager.getDefaultConfig();
    DataManager.saveConfig();
    this.renderAll();

    if (window.AppController) {
      window.AppController.refresh();
    }

    UIComponents.showToast('Paramétrage réinitialisé.', 'success');
  }
};

// Export global

// ═══════════════════════════════════════════════════════════════
// MODULE: UI-COMPONENTS
// ═══════════════════════════════════════════════════════════════

var UIComponents = {
  toastTimer: null,
  quillEditor: null,
  isDescriptionSourceMode: false,

  // ═══════════════ PANEL DE DÉTAILS ═══════════════
  openDetail(id) {
    const requete = DataManager.data.find(r => r.id === id);
    if (!requete) return;

    const domain = ViewRenderer.getDomainInfo(requete.domaine);
    const status = ViewRenderer.getStatusInfo(requete.statut);

    // En-tête
    const header = document.getElementById('dp-head');
    if (header) {
      header.innerHTML = `
        <div class="card-domain-icon" style="background:${domain.bg};font-size:22px;width:44px;height:44px;border-radius:10px">${domain.icon}</div>
        <div style="flex:1;min-width:0">
          <div style="font-size:15px;font-weight:600;color:var(--gray-800)">${Utils.escapeHtml(requete.nom)}</div>
          <div style="font-size:12px;color:var(--gray-400);margin-top:3px;font-family:var(--font-mono)">${Utils.escapeHtml(requete.id || '')}</div>
        </div>
        <button class="detail-panel-close" onclick="UIComponents.closeDetail()">✕</button>`;
    }

    // Corps
    const tags = (requete.tags || []).map(t => {
      const color = Utils.tagColor(t);
      return `<span class="tag" style="background:${color.bg};color:${color.color}">${Utils.escapeHtml(t)}</span>`;
    }).join('');

    const body = document.getElementById('dp-body');
    if (body) {
      body.innerHTML = `
        <div class="detail-section">
          <div class="detail-section-title">Identification</div>
          <div class="detail-grid">
            <div class="detail-field">
              <label>Domaine</label>
              <span>${domain.icon} ${Utils.escapeHtml(requete.domaine)}</span>
            </div>
            <div class="detail-field">
              <label>Statut</label>
              ${ViewRenderer.generateStatusBadge(requete)}
            </div>
            <div class="detail-field">
              <label>Univers BO</label>
              <span style="font-family:var(--font-mono);font-size:12px">${Utils.escapeHtml(requete.univers || '—')}</span>
            </div>
            <div class="detail-field">
              <label>Fréquence</label>
              <span>${Utils.escapeHtml(requete.freq || '—')}</span>
            </div>
            <div class="detail-field">
              <label>Responsable</label>
              <span>${Utils.escapeHtml(requete.proprio || '—')}</span>
            </div>
            <div class="detail-field">
              <label>Créé le</label>
              <span>${Utils.formatDate(requete.date)}</span>
            </div>
          </div>
        </div>
        ${requete.desc ? `
          <div class="detail-section">
            <div class="detail-section-title">Objet métier</div>
            <div class="detail-desc">${Utils.sanitizeRichHtml(requete.desc)}</div>
          </div>` : ''}
        ${requete.limites ? `
          <div class="detail-section">
            <div class="detail-section-title">Limites & précautions</div>
            <div class="detail-desc" style="background:var(--amber-bg);color:var(--amber)">
              ⚠ ${Utils.escapeHtml(requete.limites)}
            </div>
          </div>` : ''}
        ${tags ? `
          <div class="detail-section">
            <div class="detail-section-title">Tags</div>
            <div class="detail-tags">${tags}</div>
          </div>` : ''}`;
    }

    // Actions
    const actions = document.getElementById('dp-act');
    if (actions) {
      actions.innerHTML = `
        <button class="btn-secondary" onclick="UIComponents.openEdit('${Utils.escapeHtml(requete.id)}')">
          <svg width="13" height="13" viewBox="0 0 13 13" fill="currentColor">
            <path d="M9.5 1a1 1 0 0 1 1.414 0l1 1A1 1 0 0 1 12 3.5L4.5 11H2V8.5L9.5 1z"/>
          </svg>
          Modifier
        </button>
        <button class="btn-secondary" onclick="UIComponents.duplicate('${Utils.escapeHtml(requete.id)}')">
          <svg width="13" height="13" viewBox="0 0 13 13" fill="currentColor">
            <rect x="4" y="4" width="8" height="8" rx="1" stroke="currentColor" stroke-width="1.2" fill="none"/>
            <path d="M2 9V2h7" stroke="currentColor" stroke-width="1.2" fill="none"/>
          </svg>
          Dupliquer
        </button>
        <button class="btn-danger" onclick="UIComponents.confirmDelete('${Utils.escapeHtml(requete.id)}', '${Utils.escapeHtml(requete.nom)}')">
          Supprimer
        </button>`;
    }

    // Afficher l'overlay
    const overlay = document.getElementById('detail-overlay');
    if (overlay) {
      overlay.style.display = 'flex';
    }
  },

  closeDetail(event) {
    if (event && event.target !== document.getElementById('detail-overlay')) {
      return;
    }

    const overlay = document.getElementById('detail-overlay');
    if (overlay) {
      overlay.style.display = 'none';
    }
  },

  // ═══════════════ MODAL REQUÊTE ═══════════════
  populateFormSelects(requete) {
    // Domaines
    const domainSelect = document.getElementById('f-domaine');
    if (domainSelect) {
      domainSelect.innerHTML = '<option value="">— Sélectionner —</option>' +
        DataManager.config.domaines.map(d =>
          `<option ${requete && requete.domaine === d.name ? 'selected' : ''}>${Utils.escapeHtml(d.name)}</option>`
        ).join('');
    }

    // Statuts
    const statusSelect = document.getElementById('f-statut');
    if (statusSelect) {
      statusSelect.innerHTML = DataManager.config.statuts.map(s =>
        `<option ${requete && requete.statut === s.name ? 'selected' : ''}>${Utils.escapeHtml(s.name)}</option>`
      ).join('');
    }

    // Univers
    const universeSelect = document.getElementById('f-univers');
    if (universeSelect) {
      universeSelect.innerHTML = '<option value="">— Sélectionner —</option>' +
        DataManager.config.univers.map(u =>
          `<option ${requete && requete.univers === u.name ? 'selected' : ''}>${Utils.escapeHtml(u.name)}</option>`
        ).join('');
    }

    // Fréquences
    const freqSelect = document.getElementById('f-freq');
    if (freqSelect) {
      freqSelect.innerHTML = DataManager.config.frequences.map(f =>
        `<option ${requete && requete.freq === f ? 'selected' : ''}>${Utils.escapeHtml(f)}</option>`
      ).join('');
    }

    // Datalist des responsables
    const respDatalist = document.getElementById('resp-dl');
    if (respDatalist) {
      respDatalist.innerHTML = DataManager.config.responsables.map(r =>
        `<option value="${Utils.escapeHtml(r.name)}">`
      ).join('');
    }
  },

  initDescriptionEditor() {
    const editorHost = document.getElementById('f-desc-editor');
    const fallbackTextarea = document.getElementById('f-desc');
    if (!editorHost || !fallbackTextarea) return;

    if (typeof Quill === 'undefined') {
      editorHost.style.display = 'none';
      fallbackTextarea.style.display = 'block';
      fallbackTextarea.className = 'form-control';
      fallbackTextarea.rows = 6;
      return;
    }

    if (this.quillEditor) return;
    this.quillEditor = new Quill('#f-desc-editor', {
      theme: 'snow',
      placeholder: 'Périmètre, indicateurs, filtres principaux…',
      modules: {
        toolbar: [
          ['bold', 'italic', 'underline'],
          [{ list: 'ordered' }, { list: 'bullet' }],
          ['link', 'clean']
        ]
      }
    });
    editorHost.style.display = 'block';
    fallbackTextarea.style.display = 'none';
    this.setDescriptionSourceMode(false);
  },

  setDescriptionSourceMode(enabled) {
    const editorHost = document.getElementById('f-desc-editor');
    const sourceTextarea = document.getElementById('f-desc-source');
    const toggleBtn = document.getElementById('btn-desc-source');
    if (!editorHost || !sourceTextarea || !toggleBtn) return;

    this.isDescriptionSourceMode = !!enabled;
    editorHost.style.display = this.isDescriptionSourceMode ? 'none' : 'block';
    sourceTextarea.style.display = this.isDescriptionSourceMode ? 'block' : 'none';
    toggleBtn.textContent = this.isDescriptionSourceMode ? 'Mode visuel' : 'Mode source HTML';
  },

  toggleDescriptionSourceMode() {
    const sourceTextarea = document.getElementById('f-desc-source');
    if (!sourceTextarea) return;
    this.initDescriptionEditor();

    if (!this.isDescriptionSourceMode) {
      sourceTextarea.value = this.getDescriptionValue();
      this.setDescriptionSourceMode(true);
      return;
    }

    const sanitized = Utils.sanitizeRichHtml(sourceTextarea.value);
    if (this.quillEditor) {
      this.quillEditor.root.innerHTML = sanitized;
    } else {
      const fallbackTextarea = document.getElementById('f-desc');
      if (fallbackTextarea) fallbackTextarea.value = sanitized;
    }
    this.setDescriptionSourceMode(false);
  },

  setDescriptionValue(value) {
    const content = String(value || '');
    this.initDescriptionEditor();
    const fallbackTextarea = document.getElementById('f-desc');
    if (this.quillEditor) {
      const safeHtml = Utils.sanitizeRichHtml(content);
      this.quillEditor.root.innerHTML = safeHtml || '';
      if (fallbackTextarea) fallbackTextarea.value = safeHtml;
      const sourceTextarea = document.getElementById('f-desc-source');
      if (sourceTextarea) sourceTextarea.value = safeHtml;
      this.setDescriptionSourceMode(false);
      return;
    }
    if (fallbackTextarea) fallbackTextarea.value = content;
    const sourceTextarea = document.getElementById('f-desc-source');
    if (sourceTextarea) sourceTextarea.value = content;
  },

  getDescriptionValue() {
    const fallbackTextarea = document.getElementById('f-desc');
    const sourceTextarea = document.getElementById('f-desc-source');
    if (this.isDescriptionSourceMode && sourceTextarea) {
      const sanitized = Utils.sanitizeRichHtml(sourceTextarea.value);
      if (this.quillEditor) {
        this.quillEditor.root.innerHTML = sanitized;
      } else if (fallbackTextarea) {
        fallbackTextarea.value = sanitized;
      }
      const text = Utils.stripHtml(sanitized).trim();
      const valueFromSource = text ? sanitized : '';
      if (fallbackTextarea) fallbackTextarea.value = valueFromSource;
      return valueFromSource;
    }
    if (this.quillEditor) {
      const html = Utils.sanitizeRichHtml(this.quillEditor.root.innerHTML);
      const text = Utils.stripHtml(html).trim();
      const value = text ? html : '';
      if (fallbackTextarea) fallbackTextarea.value = value;
      return value;
    }
    return fallbackTextarea ? fallbackTextarea.value.trim() : '';
  },

  openAddModal() {
    DataManager.editingId = null;

    const title = document.getElementById('m-title');
    if (title) title.textContent = 'Nouvelle requête';

    // Réinitialiser les champs
    ['f-nom', 'f-id', 'f-proprio', 'f-date', 'f-tags', 'f-limites'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.value = '';
    });
    this.setDescriptionValue('');

    // Date du jour par défaut
    const dateInput = document.getElementById('f-date');
    if (dateInput) {
      dateInput.value = new Date().toISOString().split('T')[0];
    }

    this.populateFormSelects(null);

    const modal = document.getElementById('modal-req');
    if (modal) modal.style.display = 'flex';
  },

  openEdit(id) {
    const requete = DataManager.data.find(r => r.id === id);
    if (!requete) return;

    DataManager.editingId = id;

    const title = document.getElementById('m-title');
    if (title) title.textContent = 'Modifier la requête';

    // Remplir les champs
    const fields = {
      'f-nom': requete.nom,
      'f-id': requete.id,
      'f-proprio': requete.proprio,
      'f-date': requete.date,
      'f-tags': (requete.tags || []).join(', '),
      'f-limites': requete.limites
    };

    for (const [id, value] of Object.entries(fields)) {
      const el = document.getElementById(id);
      if (el) el.value = value || '';
    }
    this.setDescriptionValue(requete.desc || '');

    this.populateFormSelects(requete);

    const modal = document.getElementById('modal-req');
    if (modal) modal.style.display = 'flex';

    this.closeDetail();
  },

  closeModal() {
    const modal = document.getElementById('modal-req');
    if (modal) modal.style.display = 'none';
  },

  async saveRequete() {
    const nom = document.getElementById('f-nom')?.value.trim();
    const domaine = document.getElementById('f-domaine')?.value;

    if (!nom) {
      this.showToast('Le nom est obligatoire.', 'error');
      return;
    }

    if (!domaine) {
      this.showToast('Le domaine est obligatoire.', 'error');
      return;
    }

    const requete = {
      id: document.getElementById('f-id')?.value.trim() || (DataManager.editingId || DataManager.generateId()),
      nom,
      domaine,
      statut: document.getElementById('f-statut')?.value,
      univers: document.getElementById('f-univers')?.value,
      freq: document.getElementById('f-freq')?.value,
      proprio: document.getElementById('f-proprio')?.value.trim(),
      date: document.getElementById('f-date')?.value,
      desc: this.getDescriptionValue(),
      tags: document.getElementById('f-tags')?.value.split(',').map(t => t.trim()).filter(Boolean),
      limites: document.getElementById('f-limites')?.value.trim()
    };

    try {
      await DataManager.saveRequete(requete);
      this.closeModal();

      if (window.AppController) {
        window.AppController.refresh();
      }

      const message = DataManager.editingId ? 'Requête mise à jour.' : 'Requête ajoutée.';
      this.showToast(message, 'success');
    } catch (error) {
      console.error('Erreur sauvegarde:', error);
      this.showToast('Erreur lors de la sauvegarde.', 'error');
    }
  },

  async duplicate(id) {
    try {
      const newId = await DataManager.duplicateRequete(id);

      if (window.AppController) {
        window.AppController.refresh();
      }

      this.closeDetail();
      this.showToast('Requête dupliquée.', 'success');
    } catch (error) {
      console.error('Erreur duplication:', error);
      this.showToast('Erreur lors de la duplication.', 'error');
    }
  },

  // ═══════════════ CONFIRMATION ═══════════════
  confirmDelete(id, nom) {
    this.confirm(
      `Supprimer « ${nom} » ? Cette action est irréversible.`,
      async () => {
        try {
          await DataManager.deleteRequete(id);

          if (window.AppController) {
            window.AppController.refresh();
          }

          this.closeDetail();
          this.showToast('Requête supprimée.', 'success');
        } catch (error) {
          console.error('Erreur suppression:', error);
          this.showToast('Erreur lors de la suppression.', 'error');
        }
      }
    );
  },

  confirm(message, onConfirm) {
    const msgElement = document.getElementById('confirm-msg');
    if (msgElement) {
      msgElement.textContent = message;
    }

    const okButton = document.getElementById('confirm-ok');
    if (okButton) {
      okButton.onclick = () => {
        onConfirm();
        this.closeConfirm();
      };
    }

    const modal = document.getElementById('modal-confirm');
    if (modal) modal.style.display = 'flex';
  },

  closeConfirm() {
    const modal = document.getElementById('modal-confirm');
    if (modal) modal.style.display = 'none';
  },

  // ═══════════════ TOAST ═══════════════
  showToast(message, type = '') {
    const toast = document.getElementById('toast');
    if (!toast) return;

    toast.textContent = message;
    toast.className = 'show ' + type;

    clearTimeout(this.toastTimer);
    this.toastTimer = setTimeout(() => {
      toast.className = '';
    }, 3200);
  },

  // ═══════════════ NAVIGATION ═══════════════
  goSettings() {
    document.getElementById('view-catalogue').style.display = 'none';
    document.getElementById('view-ref').style.display = 'none';
    document.getElementById('view-settings').style.display = 'block';

    ConfigManager.renderAll();
    ConfigManager.previewId();
  },

  goRef() {
    document.getElementById('view-catalogue').style.display = 'none';
    document.getElementById('view-settings').style.display = 'none';
    document.getElementById('view-ref').style.display = 'block';

    document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
    const refBtn = document.getElementById('nav-ref');
    if (refBtn) refBtn.classList.add('active');
  },

  goBack() {
    document.getElementById('view-settings').style.display = 'none';
    document.getElementById('view-ref').style.display = 'none';
    document.getElementById('view-catalogue').style.display = 'flex';

    document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
    const allBtn = document.getElementById('nav-all');
    if (allBtn) allBtn.classList.add('active');
  },

  scrollRef(sectionId, button) {
    document.querySelectorAll('.toc-item').forEach(t => t.classList.remove('active'));
    if (button) button.classList.add('active');

    const section = document.getElementById(sectionId);
    if (section) {
      section.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  },

  switchTab(tabName, button) {
    document.querySelectorAll('.s-tab').forEach(t => t.classList.remove('active'));
    if (button) button.classList.add('active');

    document.querySelectorAll('.s-panel').forEach(p => p.classList.remove('active'));
    const panel = document.getElementById('panel-' + tabName);
    if (panel) panel.classList.add('active');

    if (tabName === 'numerotation') {
      ConfigManager.previewId();
    }
  },

  // ═══════════════ EXPORT MENU ═══════════════
  toggleExportMenu(event) {
    event.stopPropagation();
    const dropdown = document.getElementById('export-dropdown');
    if (dropdown) {
      dropdown.classList.toggle('open');
    }
  },

  closeExportMenu() {
    const dropdown = document.getElementById('export-dropdown');
    if (dropdown) {
      dropdown.classList.remove('open');
    }
  },

  // ═══════════════ CHANGEMENT MOT DE PASSE ═══════════════
  openChangePasswordModal() {
    const modal = document.getElementById('modal-change-password');
    if (!modal) return;

    // Réinitialiser les champs
    document.getElementById('current-password').value = '';
    document.getElementById('new-password').value = '';
    document.getElementById('confirm-password').value = '';

    // Masquer les erreurs
    const errorDiv = document.getElementById('change-password-error');
    if (errorDiv) errorDiv.style.display = 'none';

    // Réinitialiser le bouton
    const changeBtn = modal.querySelector('.btn-primary');
    if (changeBtn) {
      changeBtn.disabled = false;
      changeBtn.textContent = 'Changer le mot de passe';
    }

    // Afficher le modal
    modal.style.display = 'flex';

    // Focus sur le premier champ
    setTimeout(() => {
      document.getElementById('current-password').focus();
    }, 100);
  },

  closeChangePasswordModal() {
    const modal = document.getElementById('modal-change-password');
    if (modal) modal.style.display = 'none';
  }
};

// Fermer le menu export au clic ailleurs
document.addEventListener('click', () => {
  UIComponents.closeExportMenu();
});

// Export global

// ═══════════════════════════════════════════════════════════════
// MODULE: SYNC-MANAGER
// ═══════════════════════════════════════════════════════════════

var SyncManager = {
  fileHandle: null,
  isSyncEnabled: false,
  syncTimeout: null,

  setHeaderIndicatorState(state) {
    const indicator = document.getElementById('sync-indicator');
    if (!indicator) return;
    if (state === 'syncing') {
      indicator.classList.add('syncing');
      indicator.title = 'Sauvegarde en cours...';
      return;
    }
    indicator.classList.remove('syncing');
    indicator.title = 'Sauvegarde OK';
  },

  async init() {
    try {
      if (!window.showSaveFilePicker) return;
      this.setHeaderIndicatorState('ok');
      
      const handle = await DataManager.loadFromIndexedDB('sync_handle');
      if (handle) {
        this.fileHandle = handle;
        this.isSyncEnabled = true;
        this.updateUIStatus();
        // Déclencher une vérification immédiate
        this.triggerSync();
      }
    } catch (e) {
      console.error("Erreur init SyncManager:", e);
    }
  },

  async linkFile() {
    try {
      if (!window.showSaveFilePicker) {
        UIComponents.showToast("Votre navigateur ne supporte pas la synchronisation de fichiers locaux.", "error");
        return;
      }
      
      const handle = await window.showSaveFilePicker({
        suggestedName: `catalogue_BO_${new Date().toISOString().slice(0, 10)}.xlsx`,
        types: [{
          description: 'Fichier Excel',
          accept: {'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': ['.xlsx']}
        }]
      });
      
      this.fileHandle = handle;
      this.isSyncEnabled = true;
      await DataManager.saveToIndexedDB('sync_handle', handle, false);
      
      UIComponents.showToast('Synchronisation Excel activée', 'success');
      this.updateUIStatus();
      
      if (Notification.permission !== "granted" && Notification.permission !== "denied") {
        await Notification.requestPermission();
      }
      
      this.triggerSync();
    } catch (e) {
      if (e.name !== 'AbortError') {
        console.error("Erreur liaison fichier:", e);
        UIComponents.showToast('Erreur lors de la liaison', 'error');
      }
    }
  },

  async unlinkFile() {
    this.fileHandle = null;
    this.isSyncEnabled = false;
    await DataManager.deleteFromIndexedDB('sync_handle');
    this.updateUIStatus();
    UIComponents.showToast('Synchronisation Excel désactivée', 'success');
  },

  async verifyPermission() {
    if (!this.fileHandle) return false;
    const options = { mode: 'readwrite' };
    
    if ((await this.fileHandle.queryPermission(options)) === 'granted') {
      return true;
    }
    
    this.showPermissionBanner();
    return false;
  },

  showPermissionBanner() {
    const statusEl = document.getElementById('sync-status-text');
    if (statusEl) {
      statusEl.innerHTML = '<span style="color:var(--orange)">⚠️ Permission requise (cliquez sur la bannière)</span>';
    }
    let banner = document.getElementById('sync-permission-banner');
    if (!banner) {
      banner = document.createElement('div');
      banner.id = 'sync-permission-banner';
      banner.style.cssText = 'position:fixed;top:0;left:0;right:0;background:var(--orange);color:white;text-align:center;padding:12px;z-index:9999;font-weight:500;cursor:pointer;box-shadow:0 4px 12px rgba(0,0,0,0.15);';
      banner.innerHTML = '⚠️ La permission d\'écriture pour la synchronisation Excel a expiré. <u>Cliquez ici pour autoriser l\'écriture asynchrone.</u>';
      
      banner.onclick = async () => {
        const options = { mode: 'readwrite' };
        try {
          if ((await this.fileHandle.requestPermission(options)) === 'granted') {
            document.body.removeChild(banner);
            this.updateUIStatus();
            this.triggerSync();
            UIComponents.showToast('Permission accordée. Synchronisation reprise.', 'success');
          }
        } catch (e) {
          console.error(e);
        }
      };
      document.body.appendChild(banner);
      
      if (Notification.permission === "granted") {
        new Notification("Catalogue BO - Synchronisation", {
          body: "Cliquez sur la bannière dans l'application pour ré-autoriser l'accès au fichier Excel."
        });
      }
    }
  },

  triggerSync() {
    if (!this.isSyncEnabled || !this.fileHandle) return;
    
    if (this.syncTimeout) clearTimeout(this.syncTimeout);
    this.syncTimeout = setTimeout(() => this.performSync(), 2000);
  },

  async performSync(retries = 3) {
    this.setHeaderIndicatorState('syncing');
    
    try {
      const hasPermission = await this.verifyPermission();
      if (!hasPermission) {
        this.setHeaderIndicatorState('ok');
        return;
      }

      const blob = ExportHandler.generateExcelBlob(); 

      const writable = await this.fileHandle.createWritable();
      await writable.write(blob);
      await writable.close();
      
      console.log('✅ Synchronisation Excel asynchrone réussie');
      
      const statusEl = document.getElementById('sync-status-text');
      if (statusEl) {
        statusEl.innerHTML = `<span style="color:var(--green)">Synchronisé à ${new Date().toLocaleTimeString()}</span>`;
      }
    } catch (error) {
      if (error && error.name === 'NotFoundError') {
        // Le fichier lié n'existe plus (déplacé/supprimé) : on invalide le handle.
        this.fileHandle = null;
        this.isSyncEnabled = false;
        await DataManager.deleteFromIndexedDB('sync_handle');
        this.updateUIStatus();
        UIComponents.showToast('Fichier de synchronisation introuvable. Veuillez relier un fichier Excel.', 'error');
        this.setHeaderIndicatorState('ok');
        return;
      }
      console.error('Erreur synchronisation:', error);
      if (retries > 0) {
        setTimeout(() => this.performSync(retries - 1), 5000);
      } else {
        const statusEl = document.getElementById('sync-status-text');
        if (statusEl) {
          statusEl.innerHTML = `<span style="color:var(--red)">Erreur de synchronisation</span>`;
        }
      }
    } finally {
      // Laisser l'animation visible un court instant pour signaler l'action
      setTimeout(() => this.setHeaderIndicatorState('ok'), 400);
    }
  },
  
  updateUIStatus() {
    const statusEl = document.getElementById('sync-status-text');
    const btnLink = document.getElementById('btn-sync-link');
    const btnUnlink = document.getElementById('btn-sync-unlink');
    
    if (!statusEl) return;
    
    if (this.isSyncEnabled) {
      statusEl.innerHTML = '<span style="color:var(--orange)">En attente de synchronisation...</span>';
      if (btnLink) btnLink.style.display = 'none';
      if (btnUnlink) btnUnlink.style.display = 'inline-flex';
    } else {
      statusEl.innerHTML = '<span style="color:var(--gray-400)">Non lié</span>';
      if (btnLink) btnLink.style.display = 'inline-flex';
      if (btnUnlink) btnUnlink.style.display = 'none';
    }
  }
};

// ═══════════════════════════════════════════════════════════════
// MODULE: APP-CONTROLLER
// ═══════════════════════════════════════════════════════════════

var AppController = {
  isAuthenticated: false,
  selectedIds: [],
  passwordHash: null,

  /**
   * Initialise l'application
   */
  
  toggleSelection(id, event) {
    if (event) {
        event.stopPropagation();
        event.preventDefault();
    }
    this.selectedIds = SelectionDomain.toggleSelection(this.selectedIds, id);
    this.refresh();
  },

  clearSelection() {
    this.selectedIds = SelectionDomain.clearSelection();
    this.refresh();
  },

  selectAll() {
    this.selectedIds = SelectionDomain.toggleSelectAll(this.selectedIds, FilterEngine.filteredData);
    this.refresh();
  },

  async confirmBulkDelete() {
    if (!this.selectedIds.length) return;
    
    if (confirm(`Supprimer définitivement les ${this.selectedIds.length} requêtes sélectionnées ?`)) {
      await DataManager.deleteBulk(this.selectedIds);
      this.selectedIds = [];
      this.refresh();
      UIComponents.showToast('Suppression effectuée.', 'success');
    }
  },

  updateBulkBar() {
    const bar = document.getElementById('bulk-bar');
    const countEl = document.getElementById('bulk-count');
    if (!bar || !countEl) return;

    const count = SelectionDomain.getBulkCount(this.selectedIds);
    if (count > 0) {
      countEl.textContent = count;
      bar.classList.add('active');
    } else {
      bar.classList.remove('active');
    }
  },

  async init() {
    console.log('🚀 Initialisation MDA BO Catalogue v2.0');

    // Vérifier si un mot de passe existe
    const hasPassword = await this.checkPasswordExists();

    if (!hasPassword) {
      // Premier démarrage - définir un mot de passe
      this.showFirstSetup();
    } else {
      // Afficher l'écran de connexion
      this.showLockScreen();
    }
  },

  /**
   * Vérifie si un mot de passe existe en base
   */
  async checkPasswordExists() {
    try {
      await DataManager.initDB();
      const storedHash = await DataManager.loadFromIndexedDB('password_hash');
      this.passwordHash = storedHash;
      return !!storedHash;
    } catch (error) {
      console.error('Erreur vérification mot de passe:', error);
      return false;
    }
  },

  /**
   * Affiche l'écran de premier démarrage
   */
  showFirstSetup() {
    const lockScreen = document.getElementById('lock-screen');
    if (!lockScreen) return;

    lockScreen.style.display = 'flex';
    document.getElementById('lock-title').textContent = 'Premier démarrage';
    document.getElementById('lock-subtitle').textContent = 'Définissez un mot de passe pour sécuriser vos données';
    document.getElementById('lock-btn').textContent = 'Créer';
    document.getElementById('lock-btn').disabled = false;
    document.getElementById('setup-demo-wrap').style.display = 'block';
    document.getElementById('lock-error').style.display = 'none';

    const input = document.getElementById('lock-password');
    input.value = '';
    input.focus();
  },

  /**
   * Affiche l'écran de verrouillage
   */
  showLockScreen() {
    const lockScreen = document.getElementById('lock-screen');
    if (!lockScreen) return;

    lockScreen.style.display = 'flex';
    document.getElementById('lock-title').textContent = 'Catalogue BO — MDA';
    document.getElementById('lock-subtitle').textContent = 'Entrez votre mot de passe pour déverrouiller';
    document.getElementById('lock-btn').textContent = 'Déverrouiller';
    document.getElementById('lock-btn').disabled = false;
    document.getElementById('setup-demo-wrap').style.display = 'none';
    document.getElementById('lock-error').style.display = 'none';

    const input = document.getElementById('lock-password');
    input.value = '';
    input.focus();
  },

  /**
   * Tente de se connecter
   */
  async attemptUnlock() {
    const password = document.getElementById('lock-password').value;
    const errorDiv = document.getElementById('lock-error');
    const submitBtn = document.getElementById('lock-btn');

    if (!password) {
      errorDiv.textContent = 'Veuillez entrer un mot de passe.';
      errorDiv.style.display = 'block';
      return;
    }

    // Désactiver le bouton pendant le traitement
    submitBtn.disabled = true;
    submitBtn.textContent = 'Vérification...';
    errorDiv.style.display = 'none';

    try {
      if (!this.passwordHash) {
        // Premier démarrage - créer le mot de passe
        await this.createPassword(password);
      } else {
        // Vérifier le mot de passe
        await this.verifyPassword(password);
      }
    } catch (error) {
      console.error('Erreur authentification:', error);
      errorDiv.textContent = 'Erreur technique. Veuillez réessayer.';
      errorDiv.style.display = 'block';
      submitBtn.disabled = false;
      submitBtn.textContent = this.passwordHash ? 'Déverrouiller' : 'Créer';
    }
  },

  /**
   * Crée un mot de passe (premier démarrage)
   */
  async createPassword(password) {
    const submitBtn = document.getElementById('lock-btn');
    const errorDiv = document.getElementById('lock-error');

    try {
      // Générer le hash
      const hash = await CryptoManager.hashPassword(password);

      // Sauvegarder le hash
      await DataManager.saveToIndexedDB('password_hash', hash);
      this.passwordHash = hash;

      // Générer et sauvegarder la clé de récupération
      const recoveryKey = 'REC-' + Utils.generateUUID().split('-')[0].toUpperCase() + '-' + Utils.generateUUID().split('-')[1].toUpperCase();
      const recData = await CryptoManager.encryptWithRecoveryKey(password, recoveryKey);
      await DataManager.saveToIndexedDB('recovery_data', recData);

      // Dériver la clé de chiffrement
      await CryptoManager.deriveKey(password);

      // Charger les données (cela créera les données de démo chiffrées)
      const loadDemo = document.getElementById('setup-load-demo')?.checked || false;
      await DataManager.initializeFirstTime(loadDemo);

      // Afficher la clé de récupération et déverrouiller
      showRecoveryKeyModal(recoveryKey, () => {
        this.unlock();
      });
    } catch (error) {
      console.error('Erreur création mot de passe:', error);
      errorDiv.textContent = 'Erreur lors de la création du mot de passe.';
      errorDiv.style.display = 'block';
      submitBtn.disabled = false;
      submitBtn.textContent = 'Créer';
    }
  },

  /**
   * Vérifie le mot de passe
   */
  async verifyPassword(password) {
    const submitBtn = document.getElementById('lock-btn');
    const errorDiv = document.getElementById('lock-error');

    try {
      // Vérifier le hash
      const hash = await CryptoManager.hashPassword(password);

      if (hash !== this.passwordHash) {
        errorDiv.textContent = 'Mot de passe incorrect.';
        errorDiv.style.display = 'block';
        submitBtn.disabled = false;
        submitBtn.textContent = 'Déverrouiller';
        document.getElementById('lock-password').value = '';
        document.getElementById('lock-password').focus();
        return;
      }

      // Dériver la clé de chiffrement
      await CryptoManager.deriveKey(password);

      // Charger les données existantes (connexion normale)
      await DataManager.loadAll();

      // Déverrouiller
      this.unlock();
    } catch (error) {
      console.error('Erreur vérification mot de passe:', error);
      errorDiv.textContent = 'Mot de passe incorrect ou données corrompues.';
      errorDiv.style.display = 'block';
      submitBtn.disabled = false;
      submitBtn.textContent = 'Déverrouiller';
    }
  },

  /**
   * Déverrouille l'application
   */
  unlock() {
    this.isAuthenticated = true;

    // Masquer l'écran de verrouillage
    document.getElementById('lock-screen').style.display = 'none';

    // Afficher l'application
    document.getElementById('app-container').style.display = 'block';

    // Initialiser l'interface
    this.refresh();

    // Initialiser la recherche
    FilterEngine.initSearch();

    // Initialiser les raccourcis clavier
    this.initKeyboardShortcuts();

    // Initialiser la synchronisation Excel locale (FSA)
    SyncManager.init();

    console.log('✅ Application déverrouillée');
  },

  /**
   * Verrouille l'application
   */
  lock() {
    if (!confirm('Verrouiller l\'application ? Les données non sauvegardées seront perdues.')) {
      return;
    }

    DataManager.lock();
    this.isAuthenticated = false;

    // Masquer l'application
    document.getElementById('app-container').style.display = 'none';

    // Afficher l'écran de verrouillage
    this.showLockScreen();

    console.log('🔒 Application verrouillée');
  },

  /**
   * Change le mot de passe
   */
  async changePassword() {
    const currentPasswordInput = document.getElementById('current-password');
    const newPasswordInput = document.getElementById('new-password');
    const confirmPasswordInput = document.getElementById('confirm-password');
    const errorDiv = document.getElementById('change-password-error');

    const currentPassword = currentPasswordInput.value.trim();
    const newPassword = newPasswordInput.value.trim();
    const confirmPassword = confirmPasswordInput.value.trim();

    // Validation
    errorDiv.style.display = 'none';

    if (!currentPassword || !newPassword || !confirmPassword) {
      errorDiv.textContent = 'Veuillez remplir tous les champs.';
      errorDiv.style.display = 'block';
      return;
    }

    if (newPassword !== confirmPassword) {
      errorDiv.textContent = 'Les nouveaux mots de passe ne correspondent pas.';
      errorDiv.style.display = 'block';
      return;
    }

    if (newPassword.length < 6) {
      errorDiv.textContent = 'Le nouveau mot de passe doit contenir au moins 6 caractères.';
      errorDiv.style.display = 'block';
      return;
    }

    if (currentPassword === newPassword) {
      errorDiv.textContent = 'Le nouveau mot de passe doit être différent de l\'ancien.';
      errorDiv.style.display = 'block';
      return;
    }

    try {
      // Vérifier le mot de passe actuel
      const currentHash = await CryptoManager.hashPassword(currentPassword);
      if (currentHash !== this.passwordHash) {
        errorDiv.textContent = 'Le mot de passe actuel est incorrect.';
        errorDiv.style.display = 'block';
        return;
      }

      // Afficher un indicateur de chargement
      errorDiv.style.display = 'none';
      const modal = document.getElementById('modal-change-password');
      const changeBtn = modal.querySelector('.btn-primary');
      changeBtn.disabled = true;
      changeBtn.textContent = 'Re-chiffrement en cours...';

      // Dériver la clé actuelle pour déchiffrer les données
      await CryptoManager.deriveKey(currentPassword);

      // Récupérer toutes les données déchiffrées
      const encryptedData = await DataManager.loadFromIndexedDB('catalogue_data');
      const encryptedConfig = await DataManager.loadFromIndexedDB('config');

      // Déchiffrer avec l'ancienne clé
      const decryptedData = encryptedData ? await CryptoManager.decrypt(encryptedData) : [];
      const decryptedConfig = encryptedConfig ? await CryptoManager.decrypt(encryptedConfig) : null;

      // Générer le nouveau hash
      const newHash = await CryptoManager.hashPassword(newPassword);

      // Réinitialiser le salt pour forcer la création d'un nouveau
      localStorage.removeItem('mda_salt');
      sessionStorage.removeItem('mda_salt');
      CryptoManager.salt = null;

      // Dériver la nouvelle clé
      await CryptoManager.deriveKey(newPassword);

      // Re-chiffrer toutes les données avec la nouvelle clé
      const newEncryptedData = await CryptoManager.encrypt(decryptedData);
      const newEncryptedConfig = decryptedConfig ? await CryptoManager.encrypt(decryptedConfig) : null;

      // Sauvegarder les données re-chiffrées et le nouveau hash
      await DataManager.saveToIndexedDB('catalogue_data', newEncryptedData);
      if (newEncryptedConfig) {
        await DataManager.saveToIndexedDB('config', newEncryptedConfig);
      }
      await DataManager.saveToIndexedDB('password_hash', newHash);

      // Regénérer la clé de récupération pour le nouveau mot de passe
      const newRecoveryKey = 'REC-' + Utils.generateUUID().split('-')[0].toUpperCase() + '-' + Utils.generateUUID().split('-')[1].toUpperCase();
      const newRecData = await CryptoManager.encryptWithRecoveryKey(newPassword, newRecoveryKey);
      await DataManager.saveToIndexedDB('recovery_data', newRecData);

      // Mettre à jour le hash en mémoire
      this.passwordHash = newHash;

      // Recharger les données en mémoire
      DataManager.data = decryptedData;
      if (decryptedConfig) {
        ConfigManager.config = decryptedConfig;
      }

      // Fermer le modal et afficher la nouvelle clé
      UIComponents.closeChangePasswordModal();
      
      showRecoveryKeyModal(newRecoveryKey, () => {
        UIComponents.showToast('Mot de passe changé avec succès ! 🔒', 'success');
      });

      console.log('✅ Mot de passe changé avec succès');
    } catch (error) {
      console.error('Erreur changement mot de passe:', error);
      errorDiv.textContent = 'Erreur lors du changement de mot de passe. Veuillez réessayer.';
      errorDiv.style.display = 'block';

      // Réactiver le bouton
      const modal = document.getElementById('modal-change-password');
      const changeBtn = modal.querySelector('.btn-primary');
      changeBtn.disabled = false;
      changeBtn.textContent = 'Changer le mot de passe';
    }
  },

  /**
   * Rafraîchit l'interface complète
   */
  refresh() {
    ViewRenderer.renderSidebar();
    ViewRenderer.renderStats();
    FilterEngine.populateFilters();
    FilterEngine.applyFilters();
    ViewRenderer.render();
    this.updateBulkBar();
  },

  /**
   * Initialise les raccourcis clavier
   */
  initKeyboardShortcuts() {
    document.addEventListener('keydown', (e) => {
      // Échap - Fermer les modales
      if (e.key === 'Escape') {
        UIComponents.closeModal();
        UIComponents.closeConfirm();
        UIComponents.closeDetail();
        UIComponents.closeChangePasswordModal();
      }

      // Ctrl/Cmd + N - Nouvelle requête
      if ((e.ctrlKey || e.metaKey) && e.key === 'n') {
        e.preventDefault();
        if (this.isAuthenticated) {
          UIComponents.openAddModal();
        }
      }

      // Ctrl/Cmd + L - Verrouiller
      if ((e.ctrlKey || e.metaKey) && e.key === 'l') {
        e.preventDefault();
        if (this.isAuthenticated) {
          this.lock();
        }
      }
    });
  },


  confirmFullReset() {
    const confirm1 = confirm("⚠️ ATTENTION : Cette action va supprimer INTÉGRALEMENT vos données, vos paramètres et votre mot de passe.\n\nSouhaitez-vous vraiment continuer ?");
    if (confirm1) {
      const confirm2 = confirm("DERNIÈRE CHANCE : Toutes les données chiffrées seront perdues définitivement si vous n'avez pas d'export. Confirmer la réinitialisation totale ?");
      if (confirm2) {
        DataManager.resetAllData();
      }
    }
  },
};

window.AppController = AppController;

// Initialisation au chargement
window.addEventListener('DOMContentLoaded', () => {
  AppController.init();
});

// ═══════════════════════════════════════════════════════════════
// FONCTIONS GLOBALES (compatibilité onclick HTML)
// ═══════════════════════════════════════════════════════════════
function toggleExportMenu(e) { UIComponents.toggleExportMenu(e); }
function closeExportMenu() { UIComponents.closeExportMenu(); }
function exportAll() { ExportHandler.exportJSON(); }
function exportExcel() { ExportHandler.exportExcelAdvanced(); }
function openAddModal() { UIComponents.openAddModal(); }
function filterByNav(key, btn) { FilterEngine.filterByNav(key, btn); }
function goRef() { UIComponents.goRef(); }
function goSettings() { UIComponents.goSettings(); }
function importData() { 
  const input = document.getElementById('import-input');
  input.onchange = handleImport;
  input.click(); 
}
function applyFilters() { FilterEngine.applyFilters(); ViewRenderer.render(); }
function setView(v) { FilterEngine.setView(v); }
function openDetail(id) { UIComponents.openDetail(id); }
function closeDetail(e) { UIComponents.closeDetail(e); }
function openEdit(id) { UIComponents.openEdit(id); }
function dupl(id) { UIComponents.duplicate(id); }
function confirmAct(msg, fn) { UIComponents.confirm(msg, fn); }
function closeConfirm() { UIComponents.closeConfirm(); }
function goBack() { UIComponents.goBack(); }
function scrollRef(id, btn) { UIComponents.scrollRef(id, btn); }
function switchTab(name, btn) { UIComponents.switchTab(name, btn); }
function saveRequete() { UIComponents.saveRequete(); }
function closeModal() { UIComponents.closeModal(); }
function openChangePasswordModal() { UIComponents.openChangePasswordModal(); }
function closeChangePasswordModal() { UIComponents.closeChangePasswordModal(); }
function changePassword() { AppController.changePassword(); }
function previewId() { ConfigManager.previewId(); }
function saveNumConfig() { ConfigManager.saveNumberingConfig(); }
function resetConfig() { ConfigManager.resetConfig(); }
function addUnivers() { ConfigManager.addUniverse(); }
function addDomaine() { ConfigManager.addDomain(); }
function addStatut() { ConfigManager.addStatus(); }
function addFrequence() { ConfigManager.addFrequency(); }
function addResponsable() { ConfigManager.addResponsible(); }

function toggleLockPassword() {
  const pwdInput = document.getElementById('lock-password');
  const btn = document.getElementById('lock-pwd-btn');
  const eyeOpen = `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>`;
  const eyeClosed = `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>`;

  if (pwdInput.type === 'password') {
    pwdInput.type = 'text';
    if(btn) btn.innerHTML = eyeClosed;
  } else {
    pwdInput.type = 'password';
    if(btn) btn.innerHTML = eyeOpen;
  }
}

async function attemptRecovery() {
  const input = document.getElementById('recovery-input').value.trim();
  const errorDiv = document.getElementById('recovery-error');
  if (!input) {
    errorDiv.textContent = 'Veuillez saisir votre clé.';
    errorDiv.style.display = 'block';
    return;
  }
  try {
    const encryptedData = await DataManager.loadFromIndexedDB('recovery_data');
    if (!encryptedData || !encryptedData.encryptedPassword || !encryptedData.recoverySalt) {
      errorDiv.textContent = 'Aucune donnée de récupération trouvée pour ce compte.';
      errorDiv.style.display = 'block';
      return;
    }
    const plainPwd = await CryptoManager.decryptWithRecoveryKey(encryptedData.encryptedPassword, encryptedData.recoverySalt, input);
    if (!plainPwd) {
      errorDiv.textContent = 'Clé invalide ou données corrompues.';
      errorDiv.style.display = 'block';
      return;
    }
    
    errorDiv.style.display = 'none';
    alert('VOTRE MOT DE PASSE A ÉTÉ DÉCHIFFRÉ :\\n\\n' + plainPwd + '\\n\\nVeuillez le noter puis retourner à la connexion.');
    window.location.reload();
  } catch (err) {
    errorDiv.textContent = 'Erreur technique lors de la récupération.';
    errorDiv.style.display = 'block';
  }
}

function showHardReset() {
  UIComponents.confirm(
    "Êtes-vous sûr de vouloir réinitialiser l'application ? Toutes vos données actuelles seront effacées.",
    () => {
      const request = indexedDB.deleteDatabase('MDA_BO_Catalogue');
      request.onsuccess = () => {
        localStorage.removeItem('mda_salt');
        sessionStorage.removeItem('mda_salt');
        window.location.reload();
      };
      request.onerror = () => {
        alert("Erreur lors de la réinitialisation.");
      };
    }
  );
  setTimeout(() => {
    const btnOk = document.getElementById('confirm-ok');
    if(btnOk) btnOk.textContent = "Réinitialiser l'application";
  }, 10);
}

function showForgotPassword() {
  const lockContainer = document.querySelector('.lock-container');
  lockContainer.innerHTML = `
    <div class="lock-logo" style="background:var(--blue)">🔑</div>
    <h1 id="lock-title">Récupération</h1>
    <p id="lock-subtitle" style="margin-bottom:16px;">Saisissez votre clé de récupération (fournie lors de la création).</p>
    <div style="margin-bottom:12px;">
      <input type="text" id="recovery-input" placeholder="REC-XXXX-XXXX" class="form-control" style="text-transform:uppercase; text-align:center; font-family:var(--font-mono); font-size:16px; letter-spacing:2px; padding:12px;">
    </div>
    <button type="button" class="btn-primary" style="width:100%; margin-bottom:12px; background:var(--blue)" onclick="attemptRecovery()">Récupérer le mot de passe</button>
    <div style="text-align:center;">
       <a href="#" onclick="window.location.reload()" style="font-size:13px; color:var(--gray-400);">Retour à la connexion</a>
    </div>
    <div id="recovery-error" style="display:none; margin-top:12px; padding:10px; background:var(--red-bg); color:var(--red); border-radius:var(--radius-sm); font-size:13px;"></div>
    <div style="margin-top:24px; padding-top:16px; border-top:1px solid var(--gray-100);">
       <a href="#" onclick="showHardReset()" style="font-size:12px; color:var(--red);">Clé perdue ? Réinitialiser l'application</a>
    </div>
  `;
}

let recoveryKeyCallback = null;
function showRecoveryKeyModal(key, callback) {
  document.getElementById('recovery-key-display').textContent = key;
  document.getElementById('modal-recovery-key').style.display = 'flex';
  recoveryKeyCallback = callback;
}
function closeRecoveryKeyModal() {
  document.getElementById('modal-recovery-key').style.display = 'none';
  if (recoveryKeyCallback) {
    recoveryKeyCallback();
    recoveryKeyCallback = null;
  }
}

function handleImport(e) {
  const file = e.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  
  if (file.name.endsWith('.xlsx')) {
    reader.onload = async (ev) => {
      try {
        const data = new Uint8Array(ev.target.result);
        const workbook = XLSX.read(data, { type: 'array' });
        
        let importedCount = 0;

        // Lecture Configuration
        if (workbook.SheetNames.includes("Configuration")) {
          const wsConfig = workbook.Sheets["Configuration"];
          const configJson = XLSX.utils.sheet_to_json(wsConfig, { header: 1 });
          
          let newConfig = {
            univers: [],
            domaines: [],
            statuts: [],
            frequences: [],
            responsables: []
          };

          for (let i = 1; i < configJson.length; i++) {
            const row = configJson[i];
            if (!row || row.length < 2) continue;
            const type = row[0];
            const val = row[1];
            const extra = row[2] || '';
            
            if (type === 'Univers') newConfig.univers.push({ name: val });
            if (type === 'Domaine') newConfig.domaines.push({ name: val, icon: extra, group: 'Sans groupe' });
            if (type === 'Statut') newConfig.statuts.push({ name: val, color: extra });
            if (type === 'Fréquence') newConfig.frequences.push({ name: val });
            if (type === 'Responsable') newConfig.responsables.push({ name: val, email: extra });
          }
          DataManager.config = DataManager.migrateConfig({ ...DataManager.config, ...newConfig });
        }

        // Lecture Catalogue
        if (workbook.SheetNames.includes("Catalogue BO")) {
          const wsCat = workbook.Sheets["Catalogue BO"];
          const catJson = XLSX.utils.sheet_to_json(wsCat, { header: 1 });
          
          const newData = [];
          for (let i = 1; i < catJson.length; i++) {
            const r = catJson[i];
            if (!r || r.length === 0) continue;
            newData.push({
              id: r[0] || DataManager.generateId(),
              nom: r[1] || '',
              domaine: r[2] || '',
              statut: r[3] || '',
              univers: r[4] || '',
              freq: r[5] || '',
              proprio: r[6] || '',
              date: r[7] || new Date().toISOString().split('T')[0],
              desc: r[8] || '',
              tags: r[9] ? String(r[9]).split(',').map(t => t.trim()).filter(Boolean) : [],
              limites: r[10] || ''
            });
          }
          // Fusion : met à jour les existants ou ajoute
          newData.forEach(newItem => {
            const idx = DataManager.data.findIndex(d => d.id === newItem.id);
            if (idx >= 0) DataManager.data[idx] = newItem;
            else DataManager.data.push(newItem);
          });
          importedCount = newData.length;
        } else {
          throw new Error('Onglet "Catalogue BO" introuvable dans le fichier Excel.');
        }

        await DataManager.saveData();
        await DataManager.saveConfig();
        AppController.refresh();
        UIComponents.showToast(`${importedCount} requêtes et config fusionnées depuis XLSX.`, 'success');
      } catch (error) {
        console.error('Erreur import XLSX:', error);
        UIComponents.showToast('Fichier Excel invalide ou corrompu.', 'error');
      }
    };
    reader.readAsArrayBuffer(file);
  } else {
    // Import JSON classique
    reader.onload = async (ev) => {
      try {
        const parsed = JSON.parse(ev.target.result);
        
        if (Array.isArray(parsed)) {
          DataManager.data = parsed;
        } else if (parsed.catalogue) {
          DataManager.data = parsed.catalogue;
          if (parsed.config) {
            DataManager.config = { ...DataManager.config, ...parsed.config };
          }
        } else {
          throw new Error('Format JSON invalide');
        }

        await DataManager.saveData();
        await DataManager.saveConfig();
        AppController.refresh();
        UIComponents.showToast(`${DataManager.data.length} requêtes importées.`, 'success');
      } catch (error) {
        console.error('Erreur import:', error);
        UIComponents.showToast('Fichier JSON invalide.', 'error');
      }
    };
    reader.readAsText(file);
  }
  e.target.value = '';
}

// Fermer le menu export au clic ailleurs
document.addEventListener('click', () => {
  UIComponents.closeExportMenu();
});

// Export global


} catch (e) {
    console.error("CRITICAL ERROR IN SCRIPT 2:", e);
    alert("Erreur critique lors du chargement du script : " + e.message);
}

window.Utils = Utils;
window.CryptoManager = CryptoManager;
window.DataManager = DataManager;
window.FilterEngine = FilterEngine;
window.ViewRenderer = ViewRenderer;
window.ExportHandler = ExportHandler;
window.ConfigManager = ConfigManager;
window.UIComponents = UIComponents;
window.SyncManager = SyncManager;
window.AppController = AppController;

