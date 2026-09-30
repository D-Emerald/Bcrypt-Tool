# -*- coding: utf-8 -*-
"""
Dev Emerald

Bcrypt Quick Password Hashing Tool

A small utility for quickly generating bcrypt password hashes
and verifying passwords against existing hashes.
"""

import bcrypt
import tkinter as tk

from tkinter import ttk, messagebox
from pathlib import Path
from datetime import datetime


# ============================================================
# SETTINGS
# ============================================================

MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128
DEFAULT_COST = 12
MAX_LOG_ENTRIES = 200


# ============================================================
# BCRYPT BACKEND
# ============================================================

def validate_password(password):
    """
    Validate password length.

    Returns:
        tuple: (True, "") if valid
               (False, error message) if invalid
    """

    if len(password) < MIN_PASSWORD_LENGTH:
        return False, (
            f"Password must be at least "
            f"{MIN_PASSWORD_LENGTH} characters."
        )

    if len(password) > MAX_PASSWORD_LENGTH:
        return False, (
            f"Password cannot exceed "
            f"{MAX_PASSWORD_LENGTH} characters."
        )

    return True, ""


def hash_password(password, cost=DEFAULT_COST):
    """
    Generate a bcrypt password hash.

    bcrypt generates the salt automatically.
    """

    hashed_password = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt(rounds=cost)
    )

    return hashed_password.decode("utf-8")


def verify_password(password, hashed_password):
    """
    Verify a password against a bcrypt hash.
    """

    return bcrypt.checkpw(
        password.encode("utf-8"),
        hashed_password.encode("utf-8")
    )


# ============================================================
# ACTIVITY LOG
# ============================================================

activity_log = []


def add_log(message):
    """
    Add an event to the activity log.

    Maximum of 200 entries.
    """

    timestamp = datetime.now().strftime("%H:%M:%S")

    entry = f"{timestamp} | {message}"

    activity_log.append(entry)

    # Keep only the latest 200 entries
    if len(activity_log) > MAX_LOG_ENTRIES:
        activity_log.pop(0)

    update_log_display()


def update_log_display():
    """
    Refresh the activity log displayed in the GUI.
    """

    log_text.config(state="normal")
    log_text.delete("1.0", tk.END)

    for entry in activity_log:
        log_text.insert(tk.END, entry + "\n")

    log_text.config(state="disabled")

    log_count_label.config(
        text=f"Entries: {len(activity_log)} / {MAX_LOG_ENTRIES}"
    )


# ============================================================
# GUI FUNCTIONS
# ============================================================

def update_password_length(event=None):
    """
    Update the password length indicator.
    """

    password = password_entry.get()
    length = len(password)

    password_length_label.config(
        text=f"Length: {length} / {MAX_PASSWORD_LENGTH}"
    )


def toggle_password_visibility():
    """
    Show or hide the password.
    """

    if password_entry.cget("show") == "":
        password_entry.config(show="•")
        show_password_button.config(text="👁")
    else:
        password_entry.config(show="")
        show_password_button.config(text="🙈")


def generate_hash():
    """
    Generate a bcrypt hash from the password field.
    """

    password = password_entry.get()

    valid, error_message = validate_password(password)

    if not valid:
        status_label.config(
            text=f"⚠ {error_message}"
        )

        add_log("Hash generation failed | Invalid password length")

        messagebox.showwarning(
            "Invalid Password",
            error_message
        )

        return

    try:
        cost = int(cost_combobox.get())

        hashed = hash_password(
            password,
            cost
        )

        hash_entry.config(state="normal")
        hash_entry.delete(0, tk.END)
        hash_entry.insert(0, hashed)
        hash_entry.config(state="readonly")

        status_label.config(
            text="✓ Bcrypt hash generated"
        )

        add_log(
            f"Hash generated | Cost: {cost}"
        )

    except Exception as error:

        status_label.config(
            text="⚠ Hash generation failed"
        )

        add_log("Hash generation failed | Application error")

        messagebox.showerror(
            "Error",
            f"Unable to generate bcrypt hash.\n\n{error}"
        )


def copy_hash():
    """
    Copy the generated bcrypt hash to the clipboard.
    """

    hashed = hash_entry.get()

    if not hashed:
        status_label.config(
            text="⚠ No hash available to copy"
        )

        return

    root.clipboard_clear()
    root.clipboard_append(hashed)

    status_label.config(
        text="✓ Bcrypt hash copied to clipboard"
    )

    add_log("Hash copied")


def verify():
    """
    Verify the entered password against the generated hash.
    """

    password = verify_password_entry.get()
    hashed = hash_entry.get()

    if not password:
        status_label.config(
            text="⚠ Enter a password to verify"
        )

        add_log("Password verification failed | Empty password")

        return

    if not hashed:
        status_label.config(
            text="⚠ Generate or enter a bcrypt hash first"
        )

        add_log(
            "Password verification failed | No hash available"
        )

        return

    try:

        result = verify_password(
            password,
            hashed
        )

        if result:

            status_label.config(
                text="✓ Password matches"
            )

            add_log(
                "Password verification | Success"
            )

        else:

            status_label.config(
                text="✗ Password does not match"
            )

            add_log(
                "Password verification | Failed"
            )

    except ValueError:

        status_label.config(
            text="⚠ Invalid bcrypt hash"
        )

        add_log(
            "Password verification failed | Invalid bcrypt hash"
        )

    except Exception:

        status_label.config(
            text="⚠ Verification failed"
        )

        add_log(
            "Password verification failed | Application error"
        )


def clear_log():
    """
    Clear the activity log.
    """

    if not activity_log:
        return

    confirmation = messagebox.askyesno(
        "Clear Activity Log",
        "Clear all activity log entries?"
    )

    if confirmation:

        activity_log.clear()

        update_log_display()

        status_label.config(
            text="Activity log cleared"
        )


def export_log():
    """
    Export the activity log to the user's Downloads folder.
    """

    if not activity_log:

        status_label.config(
            text="⚠ Activity log is empty"
        )

        return

    downloads_folder = Path.home() / "Downloads"

    downloads_folder.mkdir(
        parents=True,
        exist_ok=True
    )

    timestamp = datetime.now().strftime(
        "%Y-%m-%d_%H%M%S"
    )

    filename = (
        f"bcrypt_activity_log_{timestamp}.txt"
    )

    file_path = downloads_folder / filename

    log_content = (
        "Bcrypt Quick Password Hashing Tool\n"
        "Activity Log\n"
        "========================================\n\n"
    )

    log_content += "\n".join(activity_log)

    log_content += (
        "\n\n"
        "========================================\n"
        f"Total entries: {len(activity_log)}\n"
    )

    try:

        file_path.write_text(
            log_content,
            encoding="utf-8"
        )

        status_label.config(
            text="✓ Activity log exported"
        )

        add_log("Activity log exported")

        messagebox.showinfo(
            "Log Exported",
            f"Activity log saved to:\n\n{file_path}"
        )

    except Exception as error:

        status_label.config(
            text="⚠ Log export failed"
        )

        messagebox.showerror(
            "Export Error",
            f"Unable to export activity log.\n\n{error}"
        )

def clear_password():
    """Clear the main password entry."""
    
    password_entry.delete(0, tk.END)
    
    update_password_length()
    
    status_label.config(
        text="Password field cleared"
    )


def copy_to_verify():
    """Copy the main password into the verification field."""
    
    password = password_entry.get()
    
    if not password:
        status_label.config(
            text="⚠ No password to copy"
        )
        return
    
    verify_password_entry.delete(0, tk.END)
    verify_password_entry.insert(0, password)
    
    status_label.config(
        text="✓ Password copied to verification field"
    )
    
    add_log("Password copied to verification field")


def clear_verify_password():
    """Clear the verification password entry."""
    
    verify_password_entry.delete(0, tk.END)
    
    status_label.config(
        text="Verification password cleared"
    )
    
def clear_all_fields():
    """Clear all password, verification, and hash fields."""

    # Clear main password
    password_entry.delete(0, tk.END)

    # Clear verification password
    verify_password_entry.delete(0, tk.END)

    # Clear bcrypt hash
    hash_entry.config(state="normal")
    hash_entry.delete(0, tk.END)
    hash_entry.config(state="readonly")

    # Reset password length
    update_password_length()

    # Reset cost factor
    cost_combobox.set(
        str(DEFAULT_COST)
    )

    # Reset status
    status_label.config(
        text="All fields cleared"
    )

    add_log("All fields cleared")
    
# ============================================================
# MAIN WINDOW
# ============================================================

root = tk.Tk()

root.title(
    "Bcrypt Quick Password Hashing Tool"
)

root.geometry("650x850")

root.minsize(
    600,
    750
)


# ============================================================
# STYLING
# ============================================================

style = ttk.Style()

try:
    style.theme_use("clam")
except tk.TclError:
    pass

style.configure(
    "Title.TLabel",
    font=("Segoe UI", 18, "bold")
)

style.configure(
    "Heading.TLabel",
    font=("Segoe UI", 11, "bold")
)

style.configure(
    "Normal.TLabel",
    font=("Segoe UI", 10)
)

style.configure(
    "Action.TButton",
    font=("Segoe UI", 10, "bold"),
    padding=8
)


# ============================================================
# MAIN CONTAINER
# ============================================================

main_frame = ttk.Frame(
    root,
    padding=20
)

main_frame.pack(
    fill="both",
    expand=True
)


# ============================================================
# TITLE
# ============================================================

title_label = ttk.Label(
    main_frame,
    text="🔐 Bcrypt Quick Password Hashing",
    style="Title.TLabel"
)

title_label.pack(
    pady=(0, 20)
)


# ============================================================
# PASSWORD
# ============================================================

password_label = ttk.Label(
    main_frame,
    text="Password",
    style="Heading.TLabel"
)

password_label.pack(
    anchor="w"
)


password_frame = ttk.Frame(
    main_frame
)

password_frame.pack(
    fill="x",
    pady=(5, 5)
)

password_controls = ttk.Frame(
    main_frame
)

password_controls.pack(
    fill="x",
    pady=(0, 5)
)


clear_password_button = ttk.Button(
    password_controls,
    text="Clear",
    command=clear_password
)

clear_password_button.pack(
    side="left"
)


copy_verify_button = ttk.Button(
    password_controls,
    text="Copy to Verify",
    command=copy_to_verify
)

copy_verify_button.pack(
    side="left",
    padx=(5, 0)
)


password_entry = ttk.Entry(
    password_frame,
    show="•"
)

password_entry.pack(
    side="left",
    fill="x",
    expand=True
)

show_password_button = ttk.Button(
    password_frame,
    text="👁",
    width=4,
    command=toggle_password_visibility
)

show_password_button.pack(
    side="left",
    padx=(5, 0)
)


password_entry.bind(
    "<KeyRelease>",
    update_password_length
)


password_length_label = ttk.Label(
    main_frame,
    text=f"Length: 0 / {MAX_PASSWORD_LENGTH}",
    style="Normal.TLabel"
)

password_length_label.pack(
    anchor="w",
    pady=(0, 15)
)


# ============================================================
# COST FACTOR
# ============================================================

cost_label = ttk.Label(
    main_frame,
    text="Cost Factor",
    style="Heading.TLabel"
)

cost_label.pack(
    anchor="w"
)


cost_combobox = ttk.Combobox(
    main_frame,
    values=["10", "11", "12", "13", "14"],
    state="readonly",
    width=10
)

cost_combobox.set(
    str(DEFAULT_COST)
)

cost_combobox.pack(
    anchor="w",
    pady=(5, 15)
)


# ============================================================
# GENERATE HASH BUTTON
# ============================================================

generate_button = ttk.Button(
    main_frame,
    text="Generate Bcrypt Hash",
    style="Action.TButton",
    command=generate_hash
)

generate_button.pack(
    fill="x",
    pady=(0, 20)
)


# ============================================================
# HASH OUTPUT
# ============================================================

hash_label = ttk.Label(
    main_frame,
    text="Bcrypt Hash",
    style="Heading.TLabel"
)

hash_label.pack(
    anchor="w"
)


hash_frame = ttk.Frame(
    main_frame
)

hash_frame.pack(
    fill="x",
    pady=(5, 15)
)


hash_entry = ttk.Entry(
    hash_frame,
    state="readonly"
)

hash_entry.pack(
    side="left",
    fill="x",
    expand=True
)


copy_button = ttk.Button(
    hash_frame,
    text="Copy",
    command=copy_hash
)

copy_button.pack(
    side="left",
    padx=(5, 0)
)


# ============================================================
# VERIFY PASSWORD
# ============================================================

verify_label = ttk.Label(
    main_frame,
    text="Verify Password",
    style="Heading.TLabel"
)

verify_label.pack(
    anchor="w"
)


verify_frame = ttk.Frame(
    main_frame
)

verify_frame.pack(
    fill="x",
    pady=(5, 5)
)


verify_password_entry = ttk.Entry(
    verify_frame,
    show="•"
)

verify_password_entry.pack(
    side="left",
    fill="x",
    expand=True
)


clear_verify_button = ttk.Button(
    verify_frame,
    text="Clear",
    command=clear_verify_password
)

clear_verify_button.pack(
    side="left",
    padx=(5, 0)
)


verify_button = ttk.Button(
    main_frame,
    text="Verify Password",
    style="Action.TButton",
    command=verify
)

verify_button.pack(
    fill="x",
    pady=(0, 15)
)


# ============================================================
# STATUS
# ============================================================

status_label = ttk.Label(
    main_frame,
    text="Status: Ready",
    style="Normal.TLabel"
)

status_label.pack(
    anchor="w",
    pady=(0, 15)
)


# ============================================================
# ACTIVITY LOG
# ============================================================

log_label = ttk.Label(
    main_frame,
    text="Activity Log",
    style="Heading.TLabel"
)

log_label.pack(
    anchor="w"
)


log_text = tk.Text(
    main_frame,
    height=8,
    wrap="none",
    state="disabled"
)

log_text.pack(
    fill="both",
    expand=True,
    pady=(5, 5)
)


# ============================================================
# LOG CONTROLS
# ============================================================

log_controls = ttk.Frame(
    main_frame
)

log_controls.pack(
    fill="x"
)


log_count_label = ttk.Label(
    log_controls,
    text="Entries: 0 / 200"
)

log_count_label.pack(
    side="left"
)


clear_all_button = ttk.Button(
    log_controls,
    text="Clear All Fields",
    command=clear_all_fields
)

clear_all_button.pack(
    side="right"
)


clear_log_button = ttk.Button(
    log_controls,
    text="Clear Log",
    command=clear_log
)

clear_log_button.pack(
    side="right",
    padx=(0, 5)
)


export_log_button = ttk.Button(
    log_controls,
    text="Export Log",
    command=export_log
)

export_log_button.pack(
    side="right",
    padx=(0, 5)
)


# ============================================================
# START APPLICATION
# ============================================================

root.mainloop()