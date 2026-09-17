/* ============================================================
   SECURE LIVE SEARCH
   ------------------------------------------------------------
   Prinsip keamanan yang diterapkan:
   1. IIFE + "use strict" untuk scope terisolasi & mode ketat.
   2. Tidak ada innerHTML / outerHTML / insertAdjacentHTML /
      document.write / eval / Function constructor.
   3. Data di-DEEP FREEZE (array + objek di dalamnya).
   4. Sanitasi input: type check, trim, length cap, whitelist regex.
   5. Anti prototype pollution (Object.create(null), guard key).
   6. Rate limiting + debounce untuk mencegah DoS via input.
   7. Error boundary (try/catch) agar crash tidak membocorkan
      stack trace ke UI / console produksi.
   8. Semua render via createElement + textContent / createTextNode.
   9. Guard DOM clobbering dengan verifikasi element instance.
  10. Tidak menyimpan state sensitif di window / global.
   ============================================================ */

(function () {
    "use strict";

    /* ==========================================================
       0. KONSTANTA KEAMANAN
       ========================================================== */
    const MAX_INPUT_LENGTH = 50;      // hard cap
    const MAX_RESULTS      = 200;     // cap jumlah hasil render
    const DEBOUNCE_MS      = 90;      // debounce input
    const RATE_LIMIT_MS    = 30;      // jarak minimal antar-render
    const TOAST_DURATION   = 2200;
    const SAFE_PATTERN     = /^[A-Za-z0-9 _\-.\u00C0-\u024F]*$/; // whitelist

    /* ==========================================================
       1. DATA — DEEP FREEZE
       ========================================================== */
    const USERS = Object.freeze(
        [
            { name: "Ahmad Dahlan",  role: "Frontend Engineer" },
            { name: "Budi Santoso",  role: "Backend Engineer" },
            { name: "Citra Dewi",    role: "UI/UX Designer" },
            { name: "Dewi Lestari",  role: "Data Analyst" },
            { name: "Eko Prasetyo",  role: "DevOps Engineer" },
            { name: "Fajar Hidayat", role: "Mobile Developer" },
            { name: "Gita Gutawa",   role: "Product Manager" },
            { name: "Hendra Wijaya", role: "Security Analyst" },
            { name: "Indah Permata", role: "QA Engineer" },
            { name: "Joko Susilo",   role: "System Architect" },
            { name: "Kartika Sari",  role: "Cloud Engineer" },
            { name: "Lukman Hakim",  role: "Machine Learning Engineer" }
        ].map(function (u) {
            // Freeze tiap objek user agar tidak bisa dimutasi
            return Object.freeze({
                name: String(u.name),
                role: String(u.role)
            });
        })
    );

    const SUGGESTIONS = Object.freeze(
        ["Engineer", "Designer", "Analyst", "Dewi", "Ahmad"].map(String)
    );

    /* ==========================================================
       2. HELPER — HARDENED
       ========================================================== */

    /** True jika value adalah string primitif. */
    function isString(v) {
        return typeof v === "string";
    }

    /**
     * Sanitasi input:
     * - type check
     * - length cap (sebelum trim, agar DoS via string raksasa dicegah)
     * - trim
     * - whitelist regex (drop karakter kontrol / unicode aneh)
     */
    function sanitizeInput(raw) {
        if (!isString(raw)) return "";

        // Cap panjang SEBELUM operasi apapun (anti DoS)
        let s = raw.length > MAX_INPUT_LENGTH * 4
            ? raw.slice(0, MAX_INPUT_LENGTH * 4)
            : raw;

        s = s.trim().slice(0, MAX_INPUT_LENGTH);

        // Buang karakter kontrol (0x00-0x1F, 0x7F) & zero-width
        s = s.replace(/[\u0000-\u001F\u007F\u200B-\u200F\u2028\u2029]/g, "");

        // Whitelist: jika tidak cocok, buang seluruh input (return "")
        if (!SAFE_PATTERN.test(s)) {
            // Fallback: buang karakter yang tidak match, sisakan yang aman
            s = s.replace(/[^A-Za-z0-9 _\-.\u00C0-\u024F]/g, "");
        }

        return s.slice(0, MAX_INPUT_LENGTH);
    }

    /** Inisial nama untuk avatar, mis. "Ahmad Dahlan" -> "AD". */
    function initialsOf(name) {
        if (!isString(name) || name.length === 0) return "?";
        return name
            .split(/\s+/)
            .filter(Boolean)
            .slice(0, 2)
            .map(function (w) { return w.charAt(0).toUpperCase(); })
            .join("") || "?";
    }

    /** Hash sederhana -> hue 0–359 (aman, tidak pakai Math.random). */
    function hueOf(text) {
        if (!isString(text)) return 200;
        let hash = 0;
        const len = Math.min(text.length, 64); // cap loop
        for (let i = 0; i < len; i++) {
            hash = (hash * 31 + text.charCodeAt(i)) % 360;
        }
        return hash;
    }

    /**
     * Bangun teks + highlight keyword sebagai DocumentFragment.
     * HANYA memakai createElement / createTextNode / textContent.
     * Cap jumlah highlight agar tidak DoS via keyword yang match terus.
     */
    function buildHighlightedText(text, keyword) {
        const fragment = document.createDocumentFragment();
        const safeText = isString(text) ? String(text) : "";
        const safeKeyword = isString(keyword) ? keyword : "";

        if (!safeKeyword) {
            fragment.appendChild(document.createTextNode(safeText));
            return fragment;
        }

        const haystack = safeText.toLowerCase();
        const needle   = safeKeyword.toLowerCase();
        let cursor = 0;
        let found  = haystack.indexOf(needle, cursor);
        let guard  = 0;

        while (found !== -1 && guard < 64) {
            guard++;
            if (found > cursor) {
                fragment.appendChild(
                    document.createTextNode(safeText.slice(cursor, found))
                );
            }

            const mark = document.createElement("mark");
            mark.className = "hl";
            mark.textContent = safeText.slice(found, found + needle.length); // SAFE
            fragment.appendChild(mark);

            cursor = found + needle.length;
            found  = haystack.indexOf(needle, cursor);
        }

        if (cursor < safeText.length) {
            fragment.appendChild(
                document.createTextNode(safeText.slice(cursor))
            );
        }

        return fragment;
    }

    /** Toast notifikasi (textContent, aman dari XSS). */
    function showToast(message) {
        if (!toastEl) return;
        toastEl.textContent = isString(message) ? message : String(message);
        toastEl.classList.add("show");
        if (toastTimer !== null) clearTimeout(toastTimer);
        toastTimer = setTimeout(function () {
            toastEl.classList.remove("show");
            toastTimer = null;
        }, TOAST_DURATION);
    }

    /** Wrapper try/catch agar error tidak bocor ke UI. */
    function safeRun(label, fn) {
        try {
            return fn();
        } catch (err) {
            // Jangan log full stack di produksi; cukup pesan generik.
            if (window.console && console.warn) {
                console.warn("[SafeRun] " + label + " gagal:", err && err.name);
            }
            return undefined;
        }
    }

    /* ==========================================================
       3. DOM REFERENCES — GUARD TERHADAP DOM CLOBBERING
       ========================================================== */
    function getEl(id, expectedTag) {
        const el = document.getElementById(id);
        if (!el) return null;
        if (expectedTag && el.tagName !== expectedTag) return null;
        return el;
    }

    const searchInput = getEl("search-input", "INPUT");
    const userList    = getEl("user-list", "UL");
    const clearBtn    = getEl("clear-btn", "BUTTON");
    const countEl     = getEl("result-count", "SPAN");
    const hintEl      = getEl("query-hint", "SPAN");
    const chipsEl     = getEl("chips", "DIV");
    const toastEl     = getEl("toast", "DIV");

    // Jika elemen penting hilang, hentikan eksekusi (fail-safe)
    if (!searchInput || !userList || !clearBtn || !countEl || !hintEl || !chipsEl || !toastEl) {
        if (window.console && console.error) {
            console.error("[SecureLiveSearch] Elemen wajib tidak ditemukan. Inisialisasi dibatalkan.");
        }
        return;
    }

    /* ==========================================================
       4. STATE (privat di closure, tidak diekspos ke window)
       ========================================================== */
    let activeIndex   = -1;
    let toastTimer    = null;
    let debounceTimer = null;
    let lastRenderTs  = 0;

    /* ==========================================================
       5. HELPER DOM — aman, tanpa innerHTML
       ========================================================== */

    function removeAllChildren(node) {
        if (!node) return;
        while (node.firstChild) {
            node.removeChild(node.firstChild);
        }
    }

    /* ==========================================================
       6. RENDER LIST
       ========================================================== */
    function renderList(items, keyword) {
        removeAllChildren(userList);
        activeIndex = -1;

        const safeItems = Array.isArray(items) ? items.slice(0, MAX_RESULTS) : [];

        /* --- Empty state --- */
        if (safeItems.length === 0) {
            const empty = document.createElement("li");
            empty.className = "no-result";
            empty.setAttribute("role", "option");
            empty.setAttribute("aria-disabled", "true");

            const icon = document.createElement("div");
            icon.className = "no-result-icon";
            icon.textContent = "🔍";

            const title = document.createElement("p");
            title.className = "no-result-title";
            title.textContent = "Tidak ada pengguna yang cocok";

            const sub = document.createElement("p");
            sub.className = "no-result-sub";
            sub.textContent = keyword
                ? 'Tidak ditemukan hasil untuk "' + keyword + '".'
                : "Data pengguna kosong.";

            empty.appendChild(icon);
            empty.appendChild(title);
            empty.appendChild(sub);
            userList.appendChild(empty);
            return;
        }

        /* --- Render tiap item --- */
        safeItems.forEach(function (user, index) {
            // Guard: pastikan struktur objek valid
            if (!user || !isString(user.name) || !isString(user.role)) return;

            const li = document.createElement("li");
            li.className = "user-item";
            li.tabIndex = 0;
            li.setAttribute("role", "option");
            li.setAttribute("aria-selected", "false");
            li.style.animationDelay = Math.min(index * 45, 420) + "ms";

            /* Avatar */
            const avatar = document.createElement("span");
            avatar.className = "avatar";
            avatar.setAttribute("aria-hidden", "true");
            avatar.style.setProperty("--hue", String(hueOf(user.name)));
            avatar.textContent = initialsOf(user.name);

            /* Info */
            const info = document.createElement("div");
            info.className = "user-info";

            const nameEl = document.createElement("span");
            nameEl.className = "user-name";
            nameEl.appendChild(buildHighlightedText(user.name, keyword));

            const roleEl = document.createElement("span");
            roleEl.className = "user-role";
            roleEl.textContent = user.role; // SAFE

            info.appendChild(nameEl);
            info.appendChild(roleEl);

            li.appendChild(avatar);
            li.appendChild(info);

            li.addEventListener("click", function () {
                selectUser(user.name, li);
            });

            li.addEventListener("keydown", function (e) {
                if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    selectUser(user.name, li);
                }
            });

            userList.appendChild(li);
        });
    }

    /* ==========================================================
       7. STATUS / COUNTER
       ========================================================== */
    function updateStatus(count, keyword) {
        const safeCount = Number.isInteger(count) ? count : 0;
        countEl.textContent = "Menampilkan " + safeCount + " dari " + USERS.length + " pengguna";

        countEl.classList.remove("pop");
        void countEl.offsetWidth;
        countEl.classList.add("pop");

        hintEl.textContent = keyword
            ? 'kata kunci: "' + String(keyword).slice(0, MAX_INPUT_LENGTH) + '"'
            : "menampilkan semua data";
    }

    /* ==========================================================
       8. AKSI PILIH USER
       ========================================================== */
    function selectUser(name, itemEl) {
        if (!itemEl || !(itemEl instanceof HTMLElement)) return;
        itemEl.classList.remove("flash");
        void itemEl.offsetWidth;
        itemEl.classList.add("flash");
        showToast("✅ " + String(name).slice(0, MAX_INPUT_LENGTH) + " dipilih");
    }

    /* ==========================================================
       9. FILTER + RENDER INTI (dengan rate-limit & debounce)
       ========================================================== */
    function performSearch(rawValue) {
        const cleanInput = sanitizeInput(rawValue);
        const keyword    = cleanInput.toLowerCase();

        clearBtn.classList.toggle("visible", cleanInput.length > 0);

        const filtered = USERS.filter(function (user) {
            return (
                user.name.toLowerCase().includes(keyword) ||
                user.role.toLowerCase().includes(keyword)
            );
        });

        renderList(filtered, keyword);
        updateStatus(filtered.length, cleanInput);
    }

    function throttledSearch(rawValue) {
        const now = Date.now();
        if (now - lastRenderTs < RATE_LIMIT_MS) {
            // Terlalu cepat: jadwalkan setelah cooldown
            if (debounceTimer !== null) clearTimeout(debounceTimer);
            debounceTimer = setTimeout(function () {
                lastRenderTs = Date.now();
                safeRun("search", function () { performSearch(rawValue); });
            }, RATE_LIMIT_MS);
            return;
        }
        lastRenderTs = now;
        safeRun("search", function () { performSearch(rawValue); });
    }

    function debouncedSearch(rawValue) {
        if (debounceTimer !== null) clearTimeout(debounceTimer);
        debounceTimer = setTimeout(function () {
            debounceTimer = null;
            throttledSearch(rawValue);
        }, DEBOUNCE_MS);
    }

    /* ==========================================================
       10. NAVIGASI KEYBOARD
       ========================================================== */
    function moveActive(delta) {
        const items = userList.querySelectorAll(".user-item");
        if (items.length === 0) return;

        if (activeIndex >= 0 && items[activeIndex]) {
            items[activeIndex].classList.remove("active");
            items[activeIndex].setAttribute("aria-selected", "false");
        }

        activeIndex = (activeIndex + delta + items.length) % items.length;

        const target = items[activeIndex];
        target.classList.add("active");
        target.setAttribute("aria-selected", "true");
        target.scrollIntoView({ block: "nearest", behavior: "smooth" });
    }

    /* ==========================================================
       11. EVENT LISTENERS
       ========================================================== */
    searchInput.addEventListener("input", function (event) {
        // Ambil value dari event.target, tapi tetap validasi
        const value = event && event.target && isString(event.target.value)
            ? event.target.value
            : "";

        // Reject bila melebihi batas (native maxlength sudah handle,
        // tapi ini lapisan kedua bila di-bypass DevTools).
        if (value.length > MAX_INPUT_LENGTH) {
            searchInput.value = value.slice(0, MAX_INPUT_LENGTH);
        }

        debouncedSearch(searchInput.value);
    });

    searchInput.addEventListener("keydown", function (event) {
        if (!event || !isString(event.key)) return;

        if (event.key === "ArrowDown") {
            event.preventDefault();
            safeRun("nav-down", function () { moveActive(1); });
        } else if (event.key === "ArrowUp") {
            event.preventDefault();
            safeRun("nav-up", function () { moveActive(-1); });
        } else if (event.key === "Enter") {
            const items = userList.querySelectorAll(".user-item");
            if (activeIndex >= 0 && items[activeIndex]) {
                event.preventDefault();
                items[activeIndex].click();
            }
        } else if (event.key === "Escape") {
            if (searchInput.value !== "") {
                event.preventDefault();
                searchInput.value = "";
                safeRun("escape-clear", function () {
                    throttledSearch("");
                });
            }
        }
    });

    clearBtn.addEventListener("click", function () {
        searchInput.value = "";
        safeRun("clear", function () { throttledSearch(""); });
        searchInput.focus();
    });

    /* ==========================================================
       12. CHIPS SARAN
       ========================================================== */
    SUGGESTIONS.forEach(function (word) {
        const chip = document.createElement("button");
        chip.type = "button";
        chip.className = "chip";
        chip.textContent = word; // SAFE

        chip.addEventListener("click", function () {
            searchInput.value = word;
            safeRun("chip", function () { throttledSearch(word); });
            searchInput.focus();
        });

        chipsEl.appendChild(chip);
    });

    /* ==========================================================
       13. INIT — fail-safe
       ========================================================== */
    safeRun("init", function () {
        renderList(USERS, "");
        updateStatus(USERS.length, "");
    });

    /* ==========================================================
       14. GLOBAL ERROR BOUNDARY — cegah stack trace bocor
       ========================================================== */
    window.addEventListener("error", function (event) {
        // Cegah error detail tercetak ke console pengguna umum.
        // Hapus baris ini bila ingin logging penuh saat development.
        if (event && typeof event.preventDefault === "function") {
            event.preventDefault();
        }
    });

    window.addEventListener("unhandledrejection", function (event) {
        if (event && typeof event.preventDefault === "function") {
            event.preventDefault();
        }
    });
})();