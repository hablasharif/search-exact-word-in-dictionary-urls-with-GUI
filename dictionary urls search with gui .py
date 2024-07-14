import pandas as pd
import re
import numpy as np
import tkinter as tk
from tkinter import messagebox
from concurrent.futures import ThreadPoolExecutor

# Function to extract and return only valid URLs
def extract_urls(text):
    # Regex pattern to match URLs
    url_pattern = r'https?://[^\s]+'
    return re.findall(url_pattern, text)

# Function to check if a cell contains any of the search words and extract URLs
def process_cell(cell, search_regex):
    if search_regex.search(cell):
        return extract_urls(cell)
    return []

# Function to process the DataFrame in parallel
def process_dataframe(df, search_regex):
    with ThreadPoolExecutor() as executor:
        results = list(executor.map(lambda cell: process_cell(cell, search_regex), df.values.flatten()))
    return set(url for sublist in results for url in sublist)

# Function to process the CSV file and search for words
def search_words_in_csv():
    search_words_input = entry_search_words.get("1.0", tk.END).strip()
    
    if not search_words_input:
        messagebox.showwarning("Input Error", "Please enter search words.")
        return

    search_words = search_words_input.split()

    # Combine the search words into a single regex pattern allowing for specified delimiters or word boundaries
    delimiters = r'[ //./-/_\s]'
    search_pattern = '|'.join([rf'((?<!\w){word}(?!\w)|{delimiters}{word}{delimiters})' for word in search_words])
    
    # Compile the search pattern for faster performance
    search_regex = re.compile(search_pattern, re.IGNORECASE)

    # Read the CSV file into a DataFrame
    try:
        df = pd.read_csv(csv_file_path, dtype=str).fillna('')
    except Exception as e:
        messagebox.showerror("File Error", f"Error reading CSV file: {e}")
        return

    # Process the DataFrame and collect matching URLs
    matching_urls = process_dataframe(df, search_regex)

    # Display matching URLs in the text widget
    text_result.delete("1.0", tk.END)
    if matching_urls:
        for url in matching_urls:
            text_result.insert(tk.END, url + "\n")
    else:
        text_result.insert(tk.END, "No matching lines found.")

# Function to validate input to allow only lowercase letters a-z and spaces
def validate_input(event):
    content = entry_search_words.get("1.0", tk.END)
    valid_content = "".join(c for c in content if c in "abcdefghijklmnopqrstuvwxyz ")
    if content != valid_content:
        entry_search_words.delete("1.0", tk.END)
        entry_search_words.insert("1.0", valid_content)

# Set the hardcoded CSV file path
csv_file_path = r"C:\Users\style\Downloads\Filtered URLs www.oed.com_ 447559 2024-07-12 Friday 05-13-AM.csv"

# Set up the GUI
root = tk.Tk()
root.title("URL Search Tool")
root.geometry("800x600")

frame = tk.Frame(root)
frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

label_search_words = tk.Label(frame, text="Search Words (space-separated):")
label_search_words.grid(row=0, column=0, sticky=tk.W, pady=5)

entry_search_words = tk.Text(frame, width=50, height=5)
entry_search_words.grid(row=0, column=1, columnspan=2, padx=5, pady=5, sticky="nsew")
entry_search_words.bind("<KeyRelease>", validate_input)

button_search = tk.Button(frame, text="Search", command=search_words_in_csv)
button_search.grid(row=1, column=1, pady=5, sticky="ew")

text_result = tk.Text(frame, wrap=tk.WORD)
text_result.grid(row=2, column=0, columnspan=3, padx=10, pady=10, sticky="nsew")

# Make the widgets responsive
frame.columnconfigure(0, weight=1)
frame.columnconfigure(1, weight=1)
frame.columnconfigure(2, weight=1)
frame.rowconfigure(2, weight=1)

# Run the application
root.mainloop()
