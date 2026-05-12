/**
 * Domaine metier: edition des parametres catalogue.
 * Isole la validation et la propagation des renommages.
 */
var ConfigDomain = {
  DEFAULT_DOMAIN_GROUP: 'Sans groupe',
  normalizeText(value) {
    return String(value || '').trim();
  },

  isDuplicateName(items, candidate, currentIndex) {
    const normalizedCandidate = this.normalizeText(candidate).toLowerCase();
    if (!normalizedCandidate) return false;
    return (Array.isArray(items) ? items : []).some((item, index) => {
      if (index === currentIndex) return false;
      const name = typeof item === 'string' ? item : item && item.name;
      return this.normalizeText(name).toLowerCase() === normalizedCandidate;
    });
  },

  renameInData(data, field, oldValue, newValue) {
    const rows = Array.isArray(data) ? data : [];
    if (!field || !oldValue || !newValue || oldValue === newValue) return;
    rows.forEach(row => {
      if (row && row[field] === oldValue) {
        row[field] = newValue;
      }
    });
  }
  ,
  normalizeDomainGroup(value) {
    return this.normalizeText(value) || this.DEFAULT_DOMAIN_GROUP;
  },

  ensureDomainGroups(config) {
    if (!config || !Array.isArray(config.domaines)) return config;
    config.domaines = config.domaines.map(domain => {
      if (!domain || typeof domain !== 'object') return domain;
      return {
        ...domain,
        group: this.normalizeDomainGroup(domain.group)
      };
    });
    return config;
  },

  groupDomainsByCategory(domaines) {
    const safeDomaines = Array.isArray(domaines) ? domaines : [];
    const grouped = {};
    safeDomaines.forEach(domain => {
      const key = this.normalizeDomainGroup(domain && domain.group);
      if (!grouped[key]) grouped[key] = [];
      grouped[key].push(domain);
    });
    return grouped;
  }
};

window.ConfigDomain = ConfigDomain;
