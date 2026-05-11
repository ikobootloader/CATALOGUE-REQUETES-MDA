/**
 * Domaine metier: preparation des options de filtres.
 * Retourne des donnees pr�tes a afficher, sans dependance DOM.
 */
var FilterOptionsDomain = {
  getUniverseOptions(data) {
    const safeData = Array.isArray(data) ? data : [];
    return [...new Set(safeData.map(r => r && r.univers).filter(Boolean))];
  },

  getFrequencyOptions(config) {
    if (!config || !Array.isArray(config.frequences)) return [];
    return config.frequences.filter(Boolean);
  }
};

window.FilterOptionsDomain = FilterOptionsDomain;

