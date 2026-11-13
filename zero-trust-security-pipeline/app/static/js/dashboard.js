/**
 * Dashboard File Upload & Scan Handling
 * Supports drag-and-drop, multiple files, .txt, .zip, source code, configs,
 * individual file removal, progress indicator, and validation.
 */
document.addEventListener("DOMContentLoaded", function () {
    const dropzone = document.getElementById("upload-dropzone");
    const fileInput = document.getElementById("file-input");
    const browseBtn = document.getElementById("browse-btn");
    const filesContainer = document.getElementById("selected-files-container");
    const filesList = document.getElementById("selected-files-list");
    const uploadBtn = document.getElementById("upload-scan-btn");
    const uploadForm = document.getElementById("upload-form");
    const progressWrap = document.getElementById("upload-progress-wrap");
    const progressBar = document.getElementById("progress-bar-fill");
    const progressText = document.getElementById("progress-text");
    const progressPercent = document.getElementById("progress-percent");
    const uploadAlert = document.getElementById("upload-alert");

    if (!dropzone || !fileInput) return;

    let selectedFiles = [];

    // Trigger file chooser
    browseBtn.addEventListener("click", function (e) {
        e.preventDefault();
        fileInput.click();
    });

    dropzone.addEventListener("click", function (e) {
        if (e.target !== browseBtn && !e.target.closest("#selected-files-container")) {
            fileInput.click();
        }
    });

    // Drag-and-drop listeners
    ["dragenter", "dragover"].forEach(eventName => {
        dropzone.addEventListener(eventName, function (e) {
            e.preventDefault();
            e.stopPropagation();
            dropzone.classList.add("dragover");
        });
    });

    ["dragleave", "drop"].forEach(eventName => {
        dropzone.addEventListener(eventName, function (e) {
            e.preventDefault();
            e.stopPropagation();
            dropzone.classList.remove("dragover");
        });
    });

    dropzone.addEventListener("drop", function (e) {
        const dt = e.dataTransfer;
        const files = Array.from(dt.files);
        handleNewFiles(files);
    });

    fileInput.addEventListener("change", function () {
        const files = Array.from(fileInput.files);
        handleNewFiles(files);
    });

    function formatBytes(bytes) {
        if (bytes === 0) return "0 B";
        const k = 1024;
        const sizes = ["B", "KB", "MB", "GB"];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
    }

    function handleNewFiles(files) {
        if (!files || files.length === 0) return;
        showAlert("", ""); // Clear alert

        // Append files, avoiding duplicate filenames
        files.forEach(file => {
            const exists = selectedFiles.some(f => f.name === file.name && f.size === file.size);
            if (!exists) {
                selectedFiles.push(file);
            }
        });

        renderSelectedFiles();
    }

    function renderSelectedFiles() {
        if (selectedFiles.length === 0) {
            filesContainer.hidden = true;
            uploadBtn.disabled = true;
            filesList.innerHTML = "";
            return;
        }

        filesContainer.hidden = false;
        uploadBtn.disabled = false;
        filesList.innerHTML = "";

        selectedFiles.forEach((file, index) => {
            const li = document.createElement("li");
            li.className = "selected-file-item";

            const infoDiv = document.createElement("div");
            infoDiv.className = "file-info";

            const nameSpan = document.createElement("span");
            nameSpan.className = "file-name";
            nameSpan.textContent = file.name;

            const sizeSpan = document.createElement("span");
            sizeSpan.className = "file-size";
            sizeSpan.textContent = `(${formatBytes(file.size)})`;

            infoDiv.appendChild(nameSpan);
            infoDiv.appendChild(sizeSpan);

            const removeBtn = document.createElement("button");
            removeBtn.type = "button";
            removeBtn.className = "btn-remove-file";
            removeBtn.setAttribute("aria-label", `Remove ${file.name}`);
            removeBtn.innerHTML = `✕`;
            removeBtn.addEventListener("click", function (e) {
                e.stopPropagation();
                removeFile(index);
            });

            li.appendChild(infoDiv);
            li.appendChild(removeBtn);
            filesList.appendChild(li);
        });
    }

    function removeFile(index) {
        selectedFiles.splice(index, 1);
        renderSelectedFiles();
    }

    function showAlert(type, message) {
        if (!message) {
            uploadAlert.hidden = true;
            uploadAlert.textContent = "";
            uploadAlert.className = "notice";
            return;
        }
        uploadAlert.hidden = false;
        uploadAlert.className = `notice notice--${type}`;
        uploadAlert.textContent = message;
    }

    // Handle Upload & Scan submission
    uploadForm.addEventListener("submit", function (e) {
        e.preventDefault();

        if (selectedFiles.length === 0) {
            showAlert("warning", "Please select at least one file or project archive to scan.");
            return;
        }

        const formData = new FormData(uploadForm);
        formData.delete("files");
        selectedFiles.forEach(f => {
            formData.append("files", f);
        });

        // Show progress indicator
        uploadBtn.disabled = true;
        progressWrap.hidden = false;
        progressBar.style.width = "20%";
        progressPercent.textContent = "20%";
        progressText.textContent = "Uploading files to SecureBuild sandbox...";

        const xhr = new XMLHttpRequest();
        xhr.open("POST", uploadForm.action, true);
        xhr.setRequestHeader("X-Requested-With", "XMLHttpRequest");

        xhr.upload.onprogress = function (e) {
            if (e.lengthComputable) {
                const percent = Math.round((e.loaded / e.total) * 40);
                progressBar.style.width = percent + "%";
                progressPercent.textContent = percent + "%";
            }
        };

        xhr.onload = function () {
            progressBar.style.width = "85%";
            progressPercent.textContent = "85%";
            progressText.textContent = "Running security scanners & policy evaluation...";

            setTimeout(() => {
                try {
                    const res = JSON.parse(xhr.responseText);
                    if (xhr.status >= 200 && xhr.status < 300 && res.success) {
                        progressBar.style.width = "100%";
                        progressPercent.textContent = "100%";
                        progressText.textContent = "Scan completed! Loading pipeline execution...";
                        setTimeout(() => {
                            window.location.href = res.redirect_url || `/pipeline/${res.run_id}`;
                        }, 600);
                    } else {
                        progressWrap.hidden = true;
                        uploadBtn.disabled = false;
                        showAlert("blocked", res.error || res.message || "An error occurred during file scanning.");
                    }
                } catch (err) {
                    // Fallback redirect if non-JSON
                    window.location.reload();
                }
            }, 600);
        };

        xhr.onerror = function () {
            progressWrap.hidden = true;
            uploadBtn.disabled = false;
            showAlert("blocked", "Network error occurred while uploading. Please try again.");
        };

        xhr.send(formData);
    });
});
