// ========================================================
// PAGE 6: SOFTWARE BILL OF MATERIALS (SBOM) INTERACTION SCRIPT
// ========================================================

document.addEventListener("DOMContentLoaded", function () {
    const searchInput = document.getElementById("sbom-search-input");
    const typeFilter = document.getElementById("sbom-type-filter");
    const licenseFilter = document.getElementById("sbom-license-filter");
    const resetBtn = document.getElementById("reset-sbom-filter");
    const noMatchBox = document.getElementById("sbom-no-match");
    const tableWrap = document.querySelector("#sbom-table") ? document.querySelector("#sbom-table").closest(".table-wrap") : null;
    const paginationInfo = document.getElementById("sbom-pagination-info");

    const modal = document.getElementById("component-modal");
    const modalClose = document.getElementById("comp-modal-close");

    // Modal elements
    const modalName = document.getElementById("comp-modal-name");
    const modalBadge = document.getElementById("comp-modal-badge");
    const modalVersion = document.getElementById("comp-modal-version");
    const modalLicense = document.getElementById("comp-modal-license");
    const modalPurl = document.getElementById("comp-modal-purl");
    const modalType = document.getElementById("comp-modal-type");
    const modalDesc = document.getElementById("comp-modal-desc");

    function applySbomFilters() {
        const query = (searchInput ? searchInput.value : "").trim().toLowerCase();
        const selectedType = typeFilter ? typeFilter.value : "all";
        const selectedLicense = licenseFilter ? licenseFilter.value : "all";

        const rows = document.querySelectorAll("#sbom-table-body tr");
        let visibleCount = 0;

        rows.forEach(function (row) {
            const name = row.getAttribute("data-name") || "";
            const depType = row.getAttribute("data-type") || "";
            const lic = row.getAttribute("data-license") || "";

            const matchesQuery = !query || name.includes(query);
            const matchesType = selectedType === "all" || depType === selectedType;
            const matchesLic = selectedLicense === "all" || lic === selectedLicense;

            if (matchesQuery && matchesType && matchesLic) {
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
            paginationInfo.textContent = `Showing ${visibleCount} of ${rows.length} components`;
        }
    }

    if (searchInput) {
        searchInput.addEventListener("input", applySbomFilters);
    }
    if (typeFilter) {
        typeFilter.addEventListener("change", applySbomFilters);
    }
    if (licenseFilter) {
        licenseFilter.addEventListener("change", applySbomFilters);
    }
    if (resetBtn) {
        resetBtn.addEventListener("click", function () {
            if (searchInput) searchInput.value = "";
            if (typeFilter) typeFilter.value = "all";
            if (licenseFilter) licenseFilter.value = "all";
            applySbomFilters();
        });
    }

    // Modal view
    document.addEventListener("click", function (e) {
        const btn = e.target.closest(".btn-view-component");
        if (!btn || !modal) return;

        try {
            const raw = btn.getAttribute("data-component");
            const comp = JSON.parse(raw);

            if (modalName) modalName.textContent = comp.name;
            if (modalVersion) modalVersion.textContent = comp.version || "N/A";
            if (modalLicense) modalLicense.textContent = comp.license || "Unknown";
            if (modalPurl) modalPurl.textContent = comp.purl || "N/A";
            if (modalType) modalType.textContent = `${comp.type} Dependency`;
            if (modalDesc) modalDesc.textContent = comp.description || "No package description available.";

            if (modalBadge) {
                const isDirect = comp.type === "Direct";
                modalBadge.className = `dep-badge dep-badge--${comp.type.toLowerCase()}`;
                modalBadge.textContent = comp.type;
            }

            modal.showModal();
        } catch (err) {
            console.error("Error displaying component modal:", err);
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
