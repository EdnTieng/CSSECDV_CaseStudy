document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".delete-user-btn").forEach(btn => {
    btn.addEventListener("click", async () => {
      const userId = btn.dataset.userId;
      if (!userId) return;
      if (!confirm("Are you sure you want to delete this user?")) return;

      try {
        const res = await fetch(`/admin/api/users/${userId}`, {
          method: "DELETE",
          headers: { "Content-Type": "application/json" }
        });

        if (res.ok) {
          btn.closest("tr")?.remove();
        } else {
          let msg;
          try {
            const json = await res.json();
            msg = json.error || JSON.stringify(json);
          } catch {
            msg = await res.text();
          }
          alert(`Delete failed for ID ${userId}: ${msg}`);
          console.error(`Delete failed for ID ${userId}:`, msg);
        }
      } catch (err) {
        console.error(`Network/error deleting ID ${userId}:`, err);
        alert(`Network/error deleting ID ${userId}: ${err.message}`);
      }
    });
  });
});
