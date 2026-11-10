// =========================================
// Scan Results page: tab + status filtering, summary cards, details dialog.
// Depends on tabs.js (fires "tabs:change").
// =========================================
(function () {
    "use strict";

    document.addEventListener("DOMContentLoaded", function () {
        var root = document.querySelector("[data-scan-page]");
        if (!root) return;

        var summaries = JSON.parse(root.dataset.summaries);
        var rows = Array.prototype.slice.call(root.querySelectorAll("tbody tr[data-type]"));
        var select = document.getElementById("status-filter");
        var tableWrap = document.getElementById("scan-table-wrap");
        var emptyBox = document.getElementById("scan-empty");
        var live = document.getElementById("scan-live");
        var currentTab = "all";

        // Table rows follow BOTH the tab and the status dropdown.
        function applyFilters() {
            var shown = 0;
            rows.forEach(function (row) {
                var typeOk = currentTab === "all" || row.dataset.type === currentTab;
                var statusOk = select.value === "all" || row.dataset.status === select.value;
                row.hidden = !(typeOk && statusOk);
                if (!row.hidden) shown += 1;
            });
            tableWrap.hidden = shown === 0;
            emptyBox.hidden = shown !== 0;
            live.textContent = "Showing " + shown + " of " + rows.length + " scans";
        }

        // Summary cards follow the tab only (design decision: ignore the status filter).
        function updateCards() {
            var data = summaries[currentTab] || summaries.all;
            root.querySelectorAll("[data-summary]").forEach(function (el) {
                el.textContent = data[el.dataset.summary];
            });
        }

        root.addEventListener("tabs:change", function (e) {
            currentTab = e.detail.filter || "all";
            updateCards();
            applyFilters();
        });
        select.addEventListener("change", applyFilters);

        document.getElementById("scan-reset").addEventListener("click", function () {
            select.value = "all";
            root.querySelector('[data-tab="all"]').click();
        });

        // ---- Details dialog -------------------------------------------------
        var dialog = document.getElementById("scan-dialog");
        var title = document.getElementById("scan-dialog-title");
        var body = document.getElementById("scan-dialog-body");

        root.addEventListener("click", function (e) {
            var trigger = e.target.closest("[data-detail]");
            if (!trigger) return;
            var tpl = document.getElementById(trigger.dataset.detail);
            if (!tpl) return;

            title.textContent = tpl.dataset.title || "Scan details";
            body.replaceChildren(tpl.content.cloneNode(true));
            if (typeof dialog.showModal === "function") dialog.showModal();
            else dialog.setAttribute("open", "");
        });

        dialog.querySelector("[data-close]").addEventListener("click", function () { dialog.close(); });
        // Click on the backdrop (the <dialog> element itself) closes it.
        dialog.addEventListener("click", function (e) {
            if (e.target === dialog) dialog.close();
        });

        applyFilters();
    });
})();
