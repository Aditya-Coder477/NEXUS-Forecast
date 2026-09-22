with open('src/dashboard/static/js/app.js', 'r', encoding='utf-8') as f:
    lines = f.readlines()

print(f"Total lines: {len(lines)}")
for idx, line in enumerate(lines):
    line_num = idx + 1
    if ':+d' in line:
        print(f"Line {line_num}: contains :+d -> {line.strip()}")
    if 'var(--semantic-benign)};' in line:
        print(f"Line {line_num}: malformed template literal -> {line.strip()}")
    if '${' in line:
        # Check if matching } exists on the line
        start = 0
        while True:
            pos = line.find('${', start)
            if pos == -1:
                break
            end = line.find('}', pos)
            if end == -1:
                print(f"Line {line_num}: multi-line or unclosed ${{...}} -> {line.strip()}")
                break
            expr = line[pos+2:end]
            if ';' in expr:
                print(f"Line {line_num}: semicolon inside expression ${{...}} -> {line.strip()}")
            start = end + 1
