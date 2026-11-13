// ========================================================
// PAGE 5: TRIVY VULNERABILITY SCAN INTERACTION SCRIPT
// ========================================================

document.addEventListener("DOMContentLoaded", function () {
    const tabDeps = document.getElementById("tab-deps");
    const tabContainer = document.getElementById("tab-container");
    const panelDeps = document.getElementById("panel-deps");
    const panelContainer = document.getElementById("panel-container");

    const searchInput = document.getElementById("vuln-search-input");
    const severityFilter = document.getElementById("vuln-severity-filter");
    const resetBtn = document.getElementById("reset-vuln-filter");
    const noMatchBox = document.getElementById("vuln-no-match");
    const tableWrap = panelDeps ? panelDeps.querySelector(".table-wrap") : null;
    const paginationInfo = document.getElementById("vuln-pagination-info");

    const modal = document.getElementById("vuln-modal");
    const modalClose = document.getElementById("vuln-modal-close");

    // Modal elements
    const modalPkg = document.getElementById("modal-pkg-name");
    const modalCve = document.getElementById("modal-cve");
    const modalInstalled = document.getElementById("modal-installed-ver");
    const modalFixed = document.getElementById("modal-fixed-ver");
    const modalSevWrap = document.getElementById("modal-severity-wrap");
    const modalDesc = document.getElementById("modal-description");
    const modalRemediation = document.getElementById("modal-remediation");
    const modalRefs = document.getElementById("modal-references");

    // Tab switching
    if (tabDeps && tabContainer) {
        tabDeps.addEventListener("click", function () {
            tabDeps.classList.add("active");
            tabDeps.setAttribute("aria-selected", "true");
            tabDeps.tabIndex = 0;

            tabContainer.classList.remove("active");
            tabContainer.setAttribute("aria-selected", "false");
            tabContainer.tabIndex = -1;

            if (panelDeps) panelDeps.hidden = false;
            if (panelContainer) panelContainer.hidden = true;
        });

        tabContainer.addEventListener("click", function () {
            tabContainer.classList.add("active");
            tabContainer.setAttribute("aria-selected", "true");
            tabContainer.tabIndex = 0;

            tabDeps.classList.remove("active");
            tabDeps.setAttribute("aria-selected", "false");
            tabDeps.tabIndex = -1;

            if (panelDeps) panelDeps.hidden = true;
            if (panelContainer) panelContainer.hidden = false;
        });
    }

    // Filter rows function
    function applyFilters() {
        if (!panelDeps) return;
        const query = (searchInput ? searchInput.value : "").trim().toLowerCase();
        const selectedSev = severityFilter ? severityFilter.value.toLowerCase() : "all";

        const rows = panelDeps.querySelectorAll("#vuln-table-body tr");
        let visibleCount = 0;

        rows.forEach(function (row) {
            const rowSev = row.getAttribute("data-severity") || "";
            const rowPkg = row.getAttribute("data-package") || "";
            const rowCve = row.getAttribute("data-cve") || "";

            const matchesSeverity = selectedSev === "all" || rowSev === selectedSev;
            const matchesQuery = !query || rowPkg.includes(query) || rowCve.includes(query);

            if (matchesSeverity && matchesQuery) {
                row.hidden = false;
                visibleCount++;
            } else {
                row.hidden = true;
            }
        });

        if (tableWrap) {
            tableWrap.hidden = visibleCount === 0;
        }
        if (noMatchBox) {
            noMatchBox.hidden = visibleCount > 0;
        }
        if (paginationInfo) {
            paginationInfo.textContent = `Showing ${visibleCount} of ${rows.length} findings`;
        }
    }

    if (searchInput) {
        searchInput.addEventListener("input", applyFilters);
    }
    if (severityFilter) {
        severityFilter.addEventListener("change", applyFilters);
    }
    if (resetBtn) {
        resetBtn.addEventListener("click", function () {
            if (searchInput) searchInput.value = "";
            if (severityFilter) severityFilter.value = "all";
            applyFilters();
        });
    }

    // View Modal Trigger
    document.addEventListener("click", function (e) {
        const btn = e.target.closest(".btn-view-vuln");
        if (!btn || !modal) return;

        try {
            const raw = btn.getAttribute("data-vuln");
            const data = JSON.parse(raw);

            if (modalPkg) modalPkg.textContent = data.package;
            if (modalCve) modalCve.textContent = data.cve || data.vuln_id || "N/A";
            if (modalInstalled) modalInstalled.textContent = data.version || "N/A";
            if (modalFixed) modalFixed.textContent = data.fixed_version || "No fix available";
            if (modalDesc) modalDesc.textContent = data.description || "No description provided.";
            if (modalRemediation) modalRemediation.textContent = data.remediation || "Review upstream security advisory.";

            if (modalSevWrap) {
                const sev = (data.severity || "info").toLowerCase();
                modalSevWrap.innerHTML = `<span class="sev sev--${sev}"><span class="sev__dot" aria-hidden="true"></span>${sev.toUpperCase()}</span>`;
            }

            if (modalRefs) {
                modalRefs.innerHTML = "";
                const refs = Array.isArray(data.references) ? data.references : [];
                if (refs.length === 0) {
                    modalRefs.innerHTML = "<li><span class='text-secondary'>No reference links available.</span></li>";
                } else {
                    refs.forEach(function (url) {
                        const li = document.createElement("li");
                        const a = document.createElement("a");
                        a.href = url;
                        a.target = "_blank";
                        a.rel = "noopener noreferrer";
                        a.textContent = url;
                        li.appendChild(a);
                        modalRefs.appendChild(li);
                    });
                }
            }

            modal.showModal();
        } catch (err) {
            console.error("Error displaying vulnerability details:", err);
        }
    });

    if (modalClose && modal) {
        modalClose.addEventListener("click", function () {
            modal.close();
        });
    }

    if (modal) {
        modal.addEventListener("click", function (e) {
            if (e.target === modal) {
                modal.close();
            }
        });
    }
});
