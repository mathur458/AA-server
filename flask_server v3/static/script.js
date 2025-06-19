function togglePassword() {
    let x = document.getElementById("password");
    x.type = x.type === "password" ? "text" : "password";
}

document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById("addUserForm");
    if (form) {
        form.addEventListener("submit", async function (e) {
            e.preventDefault();
            const formData = new FormData(form);
            const res = await fetch("/add_user", {
                method: "POST",
                body: formData
            });
            const data = await res.json();
            document.getElementById("addUserMsg").innerText = data.message;
            if (data.status === 'success') location.reload();
        });
    }
});

function toggleModify(userId) {
    const modifyBox = document.getElementById('modify-box-' + userId);
    modifyBox.style.display = (modifyBox.style.display === 'none' || !modifyBox.style.display)
        ? 'block' : 'none';
}

function updateUser(userId) {
    const form = document.getElementById('modify-form-' + userId);
    const formData = new FormData(form);

    fetch(`/modify_user/${userId}`, {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            alert('✅ User updated successfully!');
            location.reload();
        } else {
            alert('❌ Error: ' + data.message);
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('⚠️ Something went wrong while updating user!');
    });
}

function deleteUser(userId) {
    if (!confirm("Are you sure you want to delete this user?")) return;

    fetch(`/delete_user/${userId}`, {
        method: 'POST'
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            alert('🗑️ User deleted successfully!');
            location.reload();
        } else {
            alert('❌ Error deleting user: ' + data.message);
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('⚠️ Something went wrong while deleting user!');
    });
}

