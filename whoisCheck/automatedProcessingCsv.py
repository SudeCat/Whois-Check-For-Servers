import os
import datetime
import requests
import zipfile
import pandas as pd
import mysql.connector
import time


def download_and_extract_csv(url):
    response = requests.get(url)
    data = response.json()

    file_url = data['result']['fileUrl']
    zip_response = requests.get(file_url)

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    zip_filename = f'downloaded_{timestamp}.zip'

    with open(zip_filename, 'wb') as f:
        f.write(zip_response.content)

    csv_file = None
    with zipfile.ZipFile(zip_filename, 'r') as zip_ref:
        for file in zip_ref.namelist():
            if file.endswith('.csv'):
                csv_file = zip_ref.extract(file)

    os.remove(zip_filename)

    return csv_file


def create_database_if_not_exists(db_name, user, password, host='localhost'):
    conn = mysql.connector.connect(
        host=host,
        user=user,
        password=password
    )
    cursor = conn.cursor()
    cursor.execute(f"CREATE DATABASE IF NOT EXISTS {db_name}")
    cursor.close()
    conn.close()


def table_exists(cursor, table_name):
    cursor.execute(f"SHOW TABLES LIKE '{table_name}'")
    result = cursor.fetchone()
    return result is not None


def add_columns_if_not_exist(cursor, table_name, new_columns):
    cursor.execute(f"SHOW COLUMNS FROM {table_name}")
    existing_columns = [column[0] for column in cursor.fetchall()]

    for column_name, column_type in new_columns.items():
        if column_name not in existing_columns:
            cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")
            print(f"Column {column_name} added to {table_name} table.")


def process_csv(csv_filepath, db_name, user, password, host='localhost'):
    df = pd.read_csv(csv_filepath, skiprows=1)

    column_name = 'Auction End'
    if (column_name not in df.columns) or (df[column_name].isnull().all()):
        raise KeyError(f"Column '{column_name}' not found in CSV file.")

    table_name = "auction_2024"
    print(f"Table name set to: {table_name}")

    create_database_if_not_exists(db_name, user, password, host)
    conn = mysql.connector.connect(
        host=host,
        user=user,
        password=password,
        database=db_name
    )
    cursor = conn.cursor()

    new_columns = {
        'status': 'VARCHAR(255)',
        'added_time': 'DATETIME',
        'updated_time': 'DATETIME'
    }

    if not table_exists(cursor, table_name):
        cursor.execute(f"""
            CREATE TABLE {table_name} (
                id INT AUTO_INCREMENT PRIMARY KEY UNIQUE,
                Domain VARCHAR(255) NOT NULL UNIQUE,
                TLD VARCHAR(255) NOT NULL,
                Type VARCHAR(255) NOT NULL,
                `Auction End` VARCHAR(255) NOT NULL,
                status VARCHAR(255),
                added_time DATETIME,
                updated_time DATETIME
            )
        """)
        print(f"Table {table_name} created in database {db_name}.")
    else:
        add_columns_if_not_exist(cursor, table_name, new_columns)

    current_time = datetime.datetime.now()

    for index, row in df.iterrows():
        domain_name = row['Domain'].lower()
        tld = row['TLD']
        type = row['Type']
        auction_end = row['Auction End']
        status = None
        added_time = current_time
        updated_time = None

        try:
            cursor.execute(f"""
                INSERT INTO {table_name} 
                (Domain, TLD, Type, `Auction End`, status, added_time, updated_time)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE 
                TLD=VALUES(TLD), 
                Type=VALUES(Type), 
                `Auction End`=VALUES(`Auction End`),
                status=VALUES(status),
                added_time=VALUES(added_time),
                updated_time=VALUES(updated_time)
            """, (domain_name, tld, type, auction_end, status, added_time, updated_time))
        except mysql.connector.Error as err:
            print(f"Error: {err}")
            continue

    conn.commit()
    cursor.close()
    conn.close()

    os.remove(csv_filepath)


start_time = time.time()

url = ""
csv_file = download_and_extract_csv(url)

user = ''
password = ''
host = ''
db_name = ''

process_csv(csv_file, db_name, user, password, host)

end_time = time.time()

elapsed_time = end_time - start_time
print(f"Total execution time: {elapsed_time:.2f} seconds")
