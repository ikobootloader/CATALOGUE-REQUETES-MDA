/**
 * Domaine metier: filtrage du catalogue.
 * Concentre les regles pures de recherche/filtrage hors orchestration UI.
 */
var FilterDomain = {
  applyFilters(data, criteria) {
    const safeData = Array.isArray(data) ? data : [];
    const normalizedCriteria = this.normalizeCriteria(criteria);
    return safeData.filter(requete => this.matchesAllCriteria(requete, normalizedCriteria));
  },

  normalizeCriteria(criteria) {
    const source = criteria || {};
    return {
      navFilter: source.navFilter || 'all',
      searchQuery: (source.searchQuery || '').toLowerCase(),
      universeFilter: source.universeFilter || '',
      freqFilter: source.freqFilter || ''
    };
  },

  matchesAllCriteria(requete, criteria) {
    return this.matchesNavFilter(requete, criteria.navFilter) &&
      this.matchesSearchQuery(requete, criteria.searchQuery) &&
      this.matchesUniverseFilter(requete, criteria.universeFilter) &&
      this.matchesFrequencyFilter(requete, criteria.freqFilter);
  },

  matchesNavFilter(requete, navFilter) {
    if (navFilter === 'all') return true;
    if (navFilter.startsWith('domaine:')) return requete.domaine === navFilter.slice(8);
    if (navFilter.startsWith('statut:')) return requete.statut === navFilter.slice(7);
    return true;
  },

  matchesSearchQuery(requete, searchQuery) {
    if (!searchQuery) return true;
    const searchableText = [
      requete.nom,
      requete.id,
      requete.univers,
      requete.desc,
      requete.proprio,
      ...(requete.tags || [])
    ].join(' ').toLowerCase();
    return searchableText.includes(searchQuery);
  },

  matchesUniverseFilter(requete, universeFilter) {
    if (!universeFilter) return true;
    return requete.univers === universeFilter;
  },

  matchesFrequencyFilter(requete, freqFilter) {
    if (!freqFilter) return true;
    return requete.freq === freqFilter;
  }
};

window.FilterDomain = FilterDomain;
