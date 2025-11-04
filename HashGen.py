import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PIL import Image, ImageTk
import os
import requests
import json
import threading
import time
import customtkinter as ctk

VT_API_KEY = "21935ae42c6cb4bf6fb35541289e0de39b7b854d242eb1e3b1dcef7b393fc969"

SUPPORTED = ["md5", "sha1", "sha256", "sha512"]

def re_enable_vt_button():
    btn_vt.config(text="Check on VirusTotal", state=tk.NORMAL)

def compute_hash(file_path, algorithm="sha256", chunk_size=8192):
    hasher = hashlib.new(algorithm)
    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest()

def browse_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        entry_file.delete(0, tk.END)
        entry_file.insert(0, file_path)

def generate_hash():
    file_path = entry_file.get()
    algo = selected_algo.get()
    if not file_path:
        messagebox.showwarning("Warning", "Please select a file first!")
        return
    try:
        hash_value = compute_hash(file_path, algo)
        text_result.delete(1.0, tk.END)
        text_result.insert(tk.END, hash_value)
    except Exception as e:
        messagebox.showerror("Error", str(e))

def copy_to_clipboard():
    hash_value = text_result.get(1.0, tk.END).strip()
    if hash_value:
        root.clipboard_clear()
        root.clipboard_append(hash_value)
        messagebox.showinfo("Copied", "Hash copied to clipboard!")
    else:
        messagebox.showwarning("Warning", "No hash to copy!")

def update_vt_results(message):
    text_vt_result.config(state=tk.NORMAL)
    text_vt_result.delete(1.0, tk.END)
    text_vt_result.insert(tk.END, message)
    text_vt_result.config(state=tk.DISABLED)

def parse_vt_report(stats, file_hash):
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total = malicious + suspicious + harmless + undetected

    result_str = (
        f"--- VirusTotal Report --- (Scan Complete)\n\n"
        f"SHA-256: {file_hash}\n"
        f"Detections: {malicious} / {total}\n"
        f"Suspicious: {suspicious}\n"
        f"Harmless: {harmless}\n"
        f"Undetected: {undetected}\n\n"
        f"Result: {'MALICIOUS' if malicious > 0 else 'Likely Clean'}"
    )
    return result_str

def check_hash_on_vt(api_key, file_path):
    if not api_key or api_key == "api":
        root.after(0, update_vt_results, "Error: API Key is not set in the code.")
        root.after(0, re_enable_vt_button)
        return

    root.after(0, update_vt_results, "Calculating SHA-256 hash...")

    try:
        file_hash = compute_hash(file_path, "sha256")
        root.after(0, update_vt_results, f"Checking hash on VirusTotal...\n{file_hash}")

        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": api_key}
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
            result_str = parse_vt_report(stats, file_hash)
            root.after(0, update_vt_results, result_str)
            root.after(0, re_enable_vt_button)

        elif response.status_code == 404:
            root.after(
                0,
                update_vt_results,
                "File hash unknown. Uploading file for analysis...\nThis may take a moment.",
            )

            upload_url = "https://www.virustotal.com/api/v3/files"
            try:
                with open(file_path, "rb") as f:
                    files = {"file": (os.path.basename(file_path), f)}
                    upload_response = requests.post(
                        upload_url, headers=headers, files=files
                    )

                if upload_response.status_code != 200:
                    root.after(
                        0,
                        update_vt_results,
                        f"Error during upload: {upload_response.text}",
                    )
                    root.after(0, re_enable_vt_button)
                    return

                analysis_id = upload_response.json()["data"]["id"]
                analysis_url = (
                    f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                )
                root.after(
                    0,
                    update_vt_results,
                    "Upload complete. Scan is queued.\nPolling for results every 15s...",
                )

                while True:
                    analysis_response = requests.get(analysis_url, headers=headers)
                    if analysis_response.status_code != 200:
                        root.after(
                            0,
                            update_vt_results,
                            f"Error fetching report: {analysis_response.text}",
                        )
                        root.after(0, re_enable_vt_button)
                        return

                    data = analysis_response.json()
                    status = data["data"]["attributes"]["status"]

                    if status == "completed":
                        stats = data["data"]["attributes"]["stats"]
                        result_str = parse_vt_report(stats, file_hash)
                        root.after(0, update_vt_results, result_str)
                        root.after(0, re_enable_vt_button)
                        break
                    elif status == "queued" or status == "in-progress":
                        root.after(
                            0,
                            update_vt_results,
                            f"Scan status: {status}...\nWaiting 15 seconds.",
                        )
                        time.sleep(15)
                    else:
                        root.after(
                            0, update_vt_results, f"Unknown analysis status: {status}"
                        )
                        root.after(0, re_enable_vt_button)
                        break

            except Exception as e:
                root.after(
                    0,
                    update_vt_results,
                    f"File upload failed: {e}\n(Is file larger than 32MB?)",
                )
                root.after(0, re_enable_vt_button)

        elif response.status_code == 401:
            root.after(0, update_vt_results, "Error: Invalid VirusTotal API Key.")
            root.after(0, re_enable_vt_button)
        else:
            root.after(
                0, update_vt_results, f"Error: {response.status_code}\n{response.text}"
            )
            root.after(0, re_enable_vt_button)

    except Exception as e:
        root.after(0, update_vt_results, f"An error occurred:\n{str(e)}")
        root.after(0, re_enable_vt_button)

def start_vt_check_thread():
    file_path = entry_file.get()
    api_key = VT_API_KEY

    if not file_path:
        messagebox.showwarning("Warning", "Please select a file first!")
        return

    if not api_key or api_key == "api":
        messagebox.showwarning("Warning", "The API Key is not hardcoded in the script!")
        return

    btn_vt.config(text="Scanning...", state=tk.DISABLED)

    scan_thread = threading.Thread(
        target=check_hash_on_vt, args=(api_key, file_path), daemon=True
    )
    scan_thread.start()


root = tk.Tk()
root.title("Integr!ty Checker")
root.geometry("540x600")
root.resizable(False, False)
root.configure(bg="#f0f0f0")

base_dir = os.path.dirname(os.path.abspath(__file__))
icon_png = os.path.join(base_dir, "hashgen.ico")

if os.path.exists(icon_png):
    try:
        icon_img = Image.open(icon_png)
        icon_photo = ImageTk.PhotoImage(icon_img)
        root.iconphoto(True, icon_photo)
    except Exception as e:
        print("⚠️ Failed to load PNG icon:", e)
else:
    print("⚠️ Place hashgen.png in the same folder.")

style = ttk.Style()
style.configure("TButton", font=("Arial", 10, "bold"), padding=6)
style.map("TButton", foreground=[("active", "white")], background=[("active", "#0053a6")])

tk.Label(
    root, 
    text="🔐 Integr!ty checker", 
    font=("Arial", 18, "bold"), 
    bg="#f0f0f0"
).pack(pady=12)

frame_file = tk.Frame(
    root, 
    bg="#f0f0f0"
)
frame_file.pack(pady=8)

tk.Label(
    frame_file, 
    text="Select File:", 
    bg="#f0f0f0"
).pack(side=tk.LEFT, padx=5)

entry_file = tk.Entry(
    frame_file,
    relief="flat",
    highlightthickness=0.5,
    highlightbackground="#393E46",
    highlightcolor="#00ADB5",
    width=42
)
entry_file.pack(side=tk.LEFT, padx=10)

tk.Button(
    frame_file, text="Select", 
    command=browse_file, 
    bg="#0078D7", 
    fg="white",
    font=("Arial", 10)
).pack(side=tk.LEFT)

frame_algo = tk.Frame(
    root, 
    bg="#f0f0f0")
frame_algo.pack(pady=10)

tk.Label(
    frame_algo, 
    text="Algorithm:", 
    bg="#f0f0f0", 
    font=("Arial", 10, "bold")
).pack(side=tk.LEFT, padx=5)

selected_algo = tk.StringVar(value="sha256")

for algo in SUPPORTED:
    tk.Radiobutton(
        frame_algo,
        text=algo.upper(),
        variable=selected_algo,
        value=algo,
        bg="#f0f0f0",
        font=("Arial", 10),
).pack(side=tk.LEFT, padx=5)

tk.Button(
    root,
    text="Generate Hash",
    command=generate_hash,
    bg="#28a745",
    fg="white",
    width=18,
    font=("Arial", 10, "bold"),
).pack(pady=5)

tk.Label(
    root, 
    text="Hash Result:", 
    bg="#f0f0f0"
).pack()

text_result = tk.Text(
    root, 
    height=4, 
    width=60, 
    wrap=tk.WORD, 
    bd=0.5, 
    relief=tk.SOLID
)
text_result.pack(pady=5)

tk.Button(
    root,
    text="Copy to Clipboard",
    command=copy_to_clipboard,
    bg="#6c757d",
    fg="white",
    width=18,
    font=("Arial", 10, "bold"),
).pack(pady=5)

btn_vt = tk.Button(
    root,
    text="Check on VirusTotal",
    command=start_vt_check_thread,
    bg="#dc3545",
    fg="white",
    width=18,
    font=("Arial", 10, "bold"),
)
btn_vt.pack(pady=10)

tk.Label(root, text="VirusTotal Result:", bg="#f0f0f0").pack()
text_vt_result = tk.Text(
    root, 
    height=10, 
    width=60, 
    wrap=tk.WORD, 
    bd=0.5, 
    relief=tk.SOLID, 
    state=tk.DISABLED
)
text_vt_result.pack(pady=5)

tk.Label(
    root,
    text="Developed by Arosha Rashmika Fernando.",
    font=("Arial", 10, "italic"),
    fg="gray",
    bg="#f0f0f0",
).pack(side=tk.BOTTOM, pady=10)

root.mainloop()
