// Membekukan array data agar tidak dapat dimodifikasi oleh script pihak ketiga (Immutability)
const users = Object.freeze([
    "Ahmad Dahlan",
    "Budi Santoso",
    "Citra Dewi",
    "Dewi Lestari",
    "Eko Prasetyo",
    "Fajar Hidayat",
    "Gita Gutawa",
    "Hendra Wijaya"
]);

const searchInput = document.querySelector("#search-input");
const userList = document.querySelector("#user-list");

/**
 * Security Helper: Sanitasi input pengguna sebelum diproses
 * Memangkas spasi berlebih dan membatasi panjang karakter
 */
function sanitizeInput(rawInput) {
    if (typeof rawInput !== "string") return "";
    // Trim spasi dan batasi maks 50 karakter (mencegah ReDoS / DoS via input panjang)
    return rawInput.trim().slice(0, 50);
}

/**
 * Fungsi merender daftar dengan proteksi XSS (Strictly DOM API)
 */
function renderList(dataArray) {
    // 1. Pembersihan DOM secara aman tanpa innerHTML
    while (userList.firstChild) {
        userList.removeChild(userList.firstChild);
    }

    // 2. Handling data kosong
    if (dataArray.length === 0) {
        const noResultItem = document.createElement("li");
        noResultItem.textContent = "Tidak ada hasil ditemukan."; // Safe
        noResultItem.classList.add("no-result");
        userList.appendChild(noResultItem);
        return;
    }

    // 3. Render item aman
    dataArray.forEach((name) => {
        const li = document.createElement("li");
        li.textContent = name; // Safe dari serangan XSS payload
        userList.appendChild(li);
    });
}

// Event listener dengan pembacaan input aman
searchInput.addEventListener("input", (event) => {
    // Sanitasi masukan pengguna
    const cleanKeyword = sanitizeInput(event.target.value).toLowerCase();
    
    // Filter array
    const filteredUsers = users.filter((user) => 
        user.toLowerCase().includes(cleanKeyword)
    );

    // Re-render
    renderList(filteredUsers);
});

// Render awal
renderList(users);