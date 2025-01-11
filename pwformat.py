import sys
import json


style = """
th,
td {
  border: 1px solid rgb(160 160 160);
  padding: 8px 10px;
}
tt.big {
  font-size: 18px;
}
td.big {
  font-size: 19px;
}
"""

def load_raw(file_name):
    with open(file_name, "r") as f:
            j = json.load(f)

    return j


def load_stdin():
    return json.load(sys.stdin)


def write_header():
    print("<!DOCTYPE html>")
    print("<html>")
    print("<head>")
    print(f"<style>{style}</style>")
    print("</head>")
    print("<body>")
    print("<table>")
    print("<tr>")
    print("<th>Anwendung</th>")
    print("<th>Info und Passwort</th>")
    print("</tr>")


def write_footer():
    print("</table>")
    print("</body>")
    print("</html>")


def write_data(data):
    d = {}
    for i in data:
        d[i['Key']] = i['Text']

    k = list(d.keys())
    k.sort()
    
    for i in k:
        print("<tr>")
        print(f'<td class="big">{i}</td>')
        t = d[i]
        t = t.replace('\n', "</br>")
        t = t.replace(' ', "&nbsp")
        print(f'<td><tt class="big">{t}</tt></td>')
        print("</tr>")


def main():
    if len(sys.argv) >= 2:
        j = load_raw(sys.argv[1])
    else:
        j = load_stdin()

    write_header()
    write_data(j)
    write_footer()


main()