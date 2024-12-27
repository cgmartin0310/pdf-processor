// static/js/dashboard.js

$(document).ready(function() {
    // Handle Edit Modal Population
    $('#editModal').on('show.bs.modal', function (event) {
        var button = $(event.relatedTarget);
        var referralId = button.data('id');
        var modal = $(this);

        // Show a loading indicator
        modal.find('#dynamicFields').html('<p>Loading...</p>');

        // Fetch referral data via AJAX
        $.ajax({
            url: `/get_referral/${referralId}`,
            method: 'GET',
            success: function(data) {
                var dynamicFields = '';

                // Record Type
                dynamicFields += `
                    <div class="form-group">
                        <label>Record Type</label>
                        <select class="form-control" name="record_type" required>
                            <option value="Referral" ${data.record_type === 'Referral' ? 'selected' : ''}>Referral</option>
                            <option value="Record Request" ${data.record_type === 'Record Request' ? 'selected' : ''}>Record Request</option>
                            <option value="Patient Intake" ${data.record_type === 'Patient Intake' ? 'selected' : ''}>Patient Intake</option>
                            <option value="Unknown" ${data.record_type === 'Unknown' ? 'selected' : ''}>Unknown</option>
                        </select>
                    </div>
                `;

                // Patient Details
                dynamicFields += '<h5>Patient Details</h5>';
                for (var key in data.patient_details) {
                    dynamicFields += `
                        <div class="form-group">
                            <label>${key}</label>
                            <input type="text" class="form-control" name="patient_${key}" value="${data.patient_details[key]}" required>
                        </div>
                    `;
                }

                // Record Details
                dynamicFields += '<h5>Record Details</h5>';
                for (var key in data.record_details) {
                    dynamicFields += `
                        <div class="form-group">
                            <label>${key}</label>
                            <input type="text" class="form-control" name="record_${key}" value="${data.record_details[key]}" required>
                        </div>
                    `;
                }

                modal.find('#dynamicFields').html(dynamicFields);
                modal.find('#editForm').attr('action', `/edit/${referralId}`);
            },
            error: function() {
                modal.find('#dynamicFields').html('<p class="text-danger">Failed to load referral data.</p>');
            }
        });
    });

    // Handle Edit Form Submission via AJAX
    $('#editForm').on('submit', function(event) {
        event.preventDefault(); // Prevent default form submission

        var form = $(this);
        var actionUrl = form.attr('action');
        var formData = form.serialize();

        $.ajax({
            url: actionUrl,
            method: 'POST',
            data: formData,
            success: function(response) {
                // Handle success (e.g., close modal, refresh table, show a success message)
                $('#editModal').modal('hide');
                location.reload(); // Simple approach; consider using AJAX to update the table dynamically
            },
            error: function() {
                // Handle error (e.g., show an error message)
                alert('Failed to update referral.');
            }
        });
    });

    // Handle Delete Modal Population
    $('#deleteModal').on('show.bs.modal', function (event) {
        var button = $(event.relatedTarget);
        var referralId = button.data('id');
        var form = $(this).find('#deleteForm');
        form.attr('action', `/delete/${referralId}`);
    });
});

