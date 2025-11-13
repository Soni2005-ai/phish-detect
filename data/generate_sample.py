import csv, random, os

legit = [
    "https://google.com",
    "https://github.com",
    "https://wikipedia.org",
    "https://amazon.in"
]

phish_templates = [
    "http://{}-secure-login.com/{}",
    "http://verify-{}-account.com/{}",
    "http://paypal-{}-update.com/{}"
]

words = ["login","user","verify","account","bank","secure"]

rows = []

for u in legit:
    rows.append([u, 0])

for _ in range(100):
    tpl = random.choice(phish_templates)
    rows.append([tpl.format(random.choice(words), random.choice(words)), 1])

os.makedirs("data", exist_ok=True)
with open("data/phishing_sample.csv","w",newline="") as f:
    w = csv.writer(f)
    w.writerow(["url","label"])
    w.writerows(rows)

print("Generated data/phishing_sample.csv")
