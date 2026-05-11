/**
 * Domaine metier: gestion de la selection multiple.
 * Isole les regles de selection pour alleger l'orchestrateur.
 */
var SelectionDomain = {
  toggleSelection(selectedIds, id) {
    if (!id) return selectedIds;
    if (selectedIds.includes(id)) {
      return selectedIds.filter(currentId => currentId !== id);
    }
    return [...selectedIds, id];
  },

  clearSelection() {
    return [];
  },

  toggleSelectAll(selectedIds, filteredData) {
    const ids = Array.isArray(filteredData) ? filteredData.map(r => r.id).filter(Boolean) : [];
    if (ids.length > 0 && selectedIds.length === ids.length) {
      return [];
    }
    return ids;
  },

  getBulkCount(selectedIds) {
    return Array.isArray(selectedIds) ? selectedIds.length : 0;
  }
};

window.SelectionDomain = SelectionDomain;
