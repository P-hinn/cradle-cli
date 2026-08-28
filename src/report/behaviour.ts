/**
 * The report's client-side behaviour: filtering, sorting, and expanding a row.
 *
 * Deliberately plain: no framework, no build step, no external file. The report
 * must still be readable with JavaScript switched off, so everything here is an
 * enhancement — the tables render complete, and the controls are only wired up
 * once this runs.
 */
export const REPORT_JS = `
(function () {
  'use strict';

  function rowsOf(table) {
    return Array.prototype.slice.call(table.tBodies[0].rows).filter(function (row) {
      return !row.classList.contains('detail-row');
    });
  }

  function detailFor(row) {
    var next = row.nextElementSibling;
    return next && next.classList.contains('detail-row') ? next : null;
  }

  function applyFilters(panel, table) {
    var query = (panel.querySelector('[data-filter="text"]') || { value: '' }).value
      .trim()
      .toLowerCase();

    var checked = {};
    var anyFacet = false;
    Array.prototype.forEach.call(panel.querySelectorAll('[data-facet]'), function (input) {
      if (!input.checked) return;
      var facet = input.getAttribute('data-facet');
      (checked[facet] = checked[facet] || []).push(input.value);
      anyFacet = true;
    });

    var shown = 0;
    rowsOf(table).forEach(function (row) {
      var visible = query === '' || row.getAttribute('data-search').indexOf(query) !== -1;
      if (visible && anyFacet) {
        for (var facet in checked) {
          if (checked[facet].indexOf(row.getAttribute('data-' + facet)) === -1) {
            visible = false;
            break;
          }
        }
      }
      row.hidden = !visible;
      var detail = detailFor(row);
      // A collapsed detail row stays collapsed; a hidden parent always hides it.
      if (detail) detail.hidden = !visible || detail.getAttribute('data-open') !== 'true';
      if (visible) shown += 1;
    });

    var counter = panel.querySelector('[data-result-count]');
    if (counter) {
      var total = rowsOf(table).length;
      counter.textContent = shown === total
        ? String(total) + ' shown'
        : String(shown) + ' of ' + String(total) + ' shown';
    }
  }

  function sortBy(table, key, direction) {
    var body = table.tBodies[0];
    var pairs = rowsOf(table).map(function (row, index) {
      var raw = row.getAttribute('data-sort-' + key);
      var numeric = Number(raw);
      return {
        row: row,
        detail: detailFor(row),
        // Keep the original order as a tiebreak so sorting is stable.
        index: index,
        value: raw !== null && raw !== '' && !isNaN(numeric) ? numeric : String(raw || '').toLowerCase()
      };
    });

    pairs.sort(function (a, b) {
      if (a.value < b.value) return -1 * direction;
      if (a.value > b.value) return 1 * direction;
      return a.index - b.index;
    });

    pairs.forEach(function (pair) {
      body.appendChild(pair.row);
      if (pair.detail) body.appendChild(pair.detail);
    });
  }

  Array.prototype.forEach.call(document.querySelectorAll('[data-table]'), function (table) {
    var name = table.getAttribute('data-table');
    var panel = document.querySelector('[data-controls="' + name + '"]');

    if (panel) {
      panel.hidden = false;
      panel.addEventListener('input', function () { applyFilters(panel, table); });
      panel.addEventListener('change', function () { applyFilters(panel, table); });
      applyFilters(panel, table);
    }

    Array.prototype.forEach.call(table.querySelectorAll('th[data-sort]'), function (th) {
      th.classList.add('sortable');
      th.setAttribute('tabindex', '0');
      th.setAttribute('role', 'button');

      function activate() {
        var ascending = th.getAttribute('aria-sort') !== 'ascending';
        Array.prototype.forEach.call(table.querySelectorAll('th[data-sort]'), function (other) {
          other.removeAttribute('aria-sort');
        });
        th.setAttribute('aria-sort', ascending ? 'ascending' : 'descending');
        sortBy(table, th.getAttribute('data-sort'), ascending ? 1 : -1);
      }

      th.addEventListener('click', activate);
      th.addEventListener('keydown', function (event) {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          activate();
        }
      });
    });
  });

  Array.prototype.forEach.call(document.querySelectorAll('button.disclose'), function (button) {
    button.hidden = false;
    button.addEventListener('click', function () {
      var row = button.closest('tr');
      var detail = detailFor(row);
      if (!detail) return;
      var open = detail.getAttribute('data-open') === 'true';
      detail.setAttribute('data-open', open ? 'false' : 'true');
      detail.hidden = open;
      button.setAttribute('aria-expanded', open ? 'false' : 'true');
      button.textContent = open ? 'Details' : 'Hide';
    });
  });
})();
`
