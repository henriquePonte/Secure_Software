import os
import mimetypes

# CONFIG

ALLOWED_EXTENSIONS = {
    ".pdf",
    ".png", ".jpg", ".jpeg", ".gif", ".webp",
    ".txt", ".csv",
    ".doc", ".docx",
    ".xls", ".xlsx",
    ".ppt", ".pptx"
}

ALLOWED_MIME_TYPES = {
    "application/pdf",

    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",

    "text/plain",
    "text/csv",

    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",

    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",

    "application/vnd.ms-powerpoint",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation"
}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB


def is_allowed_file(filename, file_stream):
    # EXTENSION CHECK
    ext = os.path.splitext(filename)[1].lower()

    if ext not in ALLOWED_EXTENSIONS:
        return False, "Invalid file extension"

    # MIME TYPE CHECK
    mime_type, _ = mimetypes.guess_type(filename)

    if mime_type not in ALLOWED_MIME_TYPES:
        return False, "Invalid MIME type"

    # SIZE CHECK
    file_stream.seek(0, os.SEEK_END)
    size = file_stream.tell()
    file_stream.seek(0)

    if size > MAX_FILE_SIZE:
        return False, "File too large"

    return True, "OK"