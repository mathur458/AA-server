document.addEventListener("DOMContentLoaded", function () {
    // --------- Login Activity Chart ---------
    const ctx = document.getElementById('loginChart')?.getContext('2d');
    const dateInput = document.getElementById('log-date');
    let chartInstance = null;

    if (dateInput && ctx) {
        dateInput.addEventListener('change', function () {
            fetch(`/api/peak_logins?date=${this.value}`)
                .then(res => res.json())
                .then(data => {
                    if (chartInstance) {
                        chartInstance.destroy();  // Destroy previous chart
                    }
                    chartInstance = new Chart(ctx, {
                        type: 'pie',
                        data: {
                            labels: data.labels,
                            datasets: [{
                                label: 'Login Distribution',
                                data: data.data,
                                backgroundColor: ['#ff6384', '#36a2eb', '#cc65fe', '#ffce56']
                            }]
                        }
                    });
                })
                .catch(err => alert("Chart Error: " + err.message));
        });
    }


    // --------- Delete User ---------
    document.querySelectorAll(".delete-btn").forEach(button => {
        button.addEventListener("click", () => {
            const userId = button.getAttribute("data-id");

            fetch(`/delete_user/${userId}`, { method: 'POST' })
                .then(res => res.json())
                .then(data => {
                    if (data.status === 'success') {
                        alert("🗑️ User deleted.");
                        location.reload();
                    } else {
                        alert("❌ Error: " + data.message);
                    }
                });
        });
    });
});

// --------- Add User ---------
function addUser() {
    const form = document.getElementById('add-user-form');
    const formData = new FormData(form);

    const data = {
        username: formData.get('username'),
        password: formData.get('password'),
        roles: formData.getAll('roles')
    };

    fetch('/add_user', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    })
    .then(response => {
        if (response.ok) {
            alert('✅ User added successfully!');
            location.reload();
        } else {
            return response.text().then(text => alert('❌ Error: ' + text));
        }
    })
    .catch(error => {
        console.error('Error adding user:', error);
        alert('❌ Something went wrong!');
    });
}

// --------- Toggle Modify Form ---------
function toggleModify(id) {
    const box = document.getElementById(`modify-box-${id}`);
    box.style.display = box.style.display === 'none' ? 'table-row' : 'none';
}

// --------- Update User Roles/Password ---------
function updateUser(id) {
    const form = document.getElementById(`modify-form-${id}`);
    const formData = new FormData(form);

    fetch(`/modify_user/${id}`, {
        method: 'POST',
        body: formData
    })
    .then(res => res.json())
    .then(data => {
        if (data.status === 'success') {
            alert('✅ User updated.');
            location.reload();
        } else {
            alert('❌ Error: ' + data.message);
        }
    })
    .catch(error => {
        alert('❌ Something went wrong: ' + error.message);
    });
}

function deleteUser(userId) {
    if (!confirm("Are you sure you want to delete this user?")) return;

    fetch(`/delete_user/${userId}`, {
        method: 'POST',
        headers: {
            'X-Requested-With': 'XMLHttpRequest'
        }
    })
    .then(async res => {
        const contentType = res.headers.get("content-type");
        if (!contentType || !contentType.includes("application/json")) {
            const html = await res.text();
            console.error("Expected JSON, got:", html);
            alert("Session expired or unauthorized. Please log in again.");
            location.href = '/login';
            return;
        }

        const data = await res.json();
        if (data.status === 'success') {
            alert("User deleted successfully.");
            location.reload();
        } else {
            alert("Error: " + data.message);
        }
    })
    .catch(err => {
        console.error("Delete request failed:", err);
        alert("Unexpected error occurred while deleting user.");
    });
}

function approveRequest(userId) {
    const form = document.querySelector(`.approve-form[data-id="${userId}"]`);
    const selectedRoles = [];

    form.querySelectorAll('input[name="roles"]:checked').forEach(cb => {
        selectedRoles.push(cb.value);
    });

    fetch(`/approve_request/${userId}`, {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest'  // ✅ helps Flask detect it's an AJAX call
    },
    body: JSON.stringify({ roles: selectedRoles })
    })
    .then(res => res.json())
    .then(data => {
        if (data.status === 'success') {
            alert("User approved!");
            location.reload();
        } else {
            alert("Error: " + data.message);
        }
    })
    .catch(err => console.error("Network error", err));

}

function rejectRequest(requestId) {
    if (confirm('Are you sure you want to reject this request?')) {
        fetch(`/reject_request/${requestId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        })
        .then(response => {
            if (response.ok) {
                location.reload();
            } else {
                alert('Failed to reject request. Code: ' + response.status);
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('Request failed.');
        });
    }
}
