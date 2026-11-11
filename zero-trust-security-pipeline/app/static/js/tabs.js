// =========================================
// Shared accessible tabs.
//
// Markup (see components/ui.html -> tab_list):
//   <div data-tabs>
//     <div role="tablist"> <button role="tab" aria-controls="panel-x" ...> </div>
//     <section role="tabpanel" id="panel-x"> ... </section>
//   </div>
//
// Keyboard: Left/Right (wraps), Home, End. Roving tabindex.
// Several tabs may point at one shared panel (Scan Results filters one table);
// otherwise each panel is shown only while its tab is selected.
// After a tab changes, a bubbling "tabs:change" event is fired with
// detail = { id, filter } so page scripts can react.
// =========================================
(function () {
    "use strict";

    function initTabs(root) {
        var tablist = root.querySelector('[role="tablist"]');
        if (!tablist) return;
        var tabs = Array.prototype.slice.call(tablist.querySelectorAll('[role="tab"]'));

        function panelOf(tab) {
            return document.getElementById(tab.getAttribute("aria-controls"));
        }

        function select(tab, moveFocus) {
            var selectedPanel = panelOf(tab);

            tabs.forEach(function (t) {
                var on = t === tab;
                t.setAttribute("aria-selected", on ? "true" : "false");
                t.tabIndex = on ? 0 : -1;
            });

            tabs.forEach(function (t) {
                var p = panelOf(t);
                if (p) p.hidden = p !== selectedPanel;
            });
            if (selectedPanel) {
                selectedPanel.hidden = false;
                selectedPanel.setAttribute("aria-labelledby", tab.id);
            }

            if (moveFocus) tab.focus();

            root.dispatchEvent(new CustomEvent("tabs:change", {
                bubbles: true,
                detail: { id: tab.dataset.tab, filter: tab.dataset.filter || null }
            }));
        }

        tabs.forEach(function (tab, i) {
            tab.addEventListener("click", function () { select(tab, false); });

            tab.addEventListener("keydown", function (e) {
                var next = null;
                if (e.key === "ArrowRight") next = tabs[(i + 1) % tabs.length];
                else if (e.key === "ArrowLeft") next = tabs[(i - 1 + tabs.length) % tabs.length];
                else if (e.key === "Home") next = tabs[0];
                else if (e.key === "End") next = tabs[tabs.length - 1];
                if (next) {
                    e.preventDefault();
                    select(next, true);
                }
            });
        });
    }

    document.addEventListener("DOMContentLoaded", function () {
        document.querySelectorAll("[data-tabs]").forEach(initTabs);
    });
})();
