#!/data/data/com.termux/files/usr/bin/python3
import csv
import psycopg2
import os

DB_CONFIG = {
    'dbname': 'maple_community',
    'user': 'maple_user',
    'password': 'maple123',   # 改成你的密码
    'host': 'localhost'
}

CSV_FILE = 'lichess_db_puzzle.csv'
BATCH_SIZE = 500
CHECKPOINT_FILE = 'import_checkpoint.txt'

def get_last_line():
    if os.path.exists(CHECKPOINT_FILE):
        with open(CHECKPOINT_FILE, 'r') as f:
            return int(f.read().strip())
    return 0

def save_checkpoint(line_num):
    with open(CHECKPOINT_FILE, 'w') as f:
        f.write(str(line_num))

def main():
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()
    
    start_line = get_last_line()
    print(f"从第 {start_line} 行开始导入")
    
    batch = []
    line_count = 0
    total_imported = start_line
    
    with open(CSV_FILE, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        # 跳过已导入的行
        for _ in range(start_line):
            next(reader)
            line_count += 1
        
        for row in reader:
            fen = row['FEN']
            moves = row['Moves']
            rating = int(row['Rating']) if row['Rating'] else 1500
            themes = row['Themes'].split(',') if row['Themes'] else []
            batch.append((fen, moves, rating, themes))
            line_count += 1
            
            if len(batch) >= BATCH_SIZE:
                cur.executemany(
                    "INSERT INTO puzzles (fen, moves, rating, themes) VALUES (%s, %s, %s, %s)",
                    batch
                )
                conn.commit()
                total_imported += len(batch)
                batch = []
                save_checkpoint(line_count)
                print(f"已导入 {total_imported} 行...")
    
    if batch:
        cur.executemany("INSERT INTO puzzles (fen, moves, rating, themes) VALUES (%s, %s, %s, %s)", batch)
        conn.commit()
        total_imported += len(batch)
        save_checkpoint(line_count)
    
    print(f"导入完成！共 {total_imported} 条谜题。")
    os.remove(CHECKPOINT_FILE)
    cur.close()
    conn.close()

if __name__ == '__main__':
    main()
