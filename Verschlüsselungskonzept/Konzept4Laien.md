# Das Verschlüsselungskonzept von Shinpai-AI — locker erklärt

> **Wer das hier lesen sollte:** Du, wenn du wissen willst, was Shinpai-AI mit deinen Daten macht und warum du uns vertrauen kannst — ohne Kryptographie-Studium.
>
> **Wichtigster Satz zuerst:** **Im Alltag musst du dir keine Sorgen machen.** Die ganze Verschlüsselungs-Mathematik läuft lautlos im Hintergrund, wie die Elektronik in deinem Auto. Du prägst dir **einmalig** bei der Registrierung einen **Tresorschlüssel** (~10 Minuten) und legst ihn zu deinen wichtigen Dokumenten. Solange du dein Passwort und deine 2FA hast, kannst du jederzeit einen neuen Schlüssel prägen lassen — der alte wird ungültig. Das nimmt jeden Druck. Wir stupsen dich einmal im Jahr nur kurz an: *"Weißt du eigentlich noch, wo dein Tresorschlüssel liegt?"*
>
> **Schwester-Dokumente:**
> - `Konzept-Laien.md` — erste Laien-Version (V1)
> - `Konzept-LaienV2.md` — zweite Laien-Version (Glaswand-Tonfall)
> - `Konzept-LaienV3.md` — dritte Laien-Version (Superkraft-Framing)
> - `Konzept-LaienV4.md` — vierte Laien-Version (Logik vor Autorität, Super-Dietrich)
> - `Konzept-LaienV5.md` — fünfte Laien-Version (Hand-Holding bei 2FA, analoge Handlungsanweisungen)
> - `Konzept-LaienV6.md` — sechste Laien-Version (Ritual statt Verbotsliste, fünfter Gegner Wohnzimmer, Postbote primär)
> - `Konzept-LaienV7.md` — siebte Laien-Version (Passwort-Satz-Methode, "Was-wäre-wenn" mit Sicherheitsnetzen früh)
> - `Konzept.md` — Vollversion mit allen technischen Details für Security-Prüfer
>
> **Stand:** 2026-04-26 (Update: Passwort-Negativregel + Alltags-Beispiel)
> **Basis:** `Konzept-LaienV7.md`, Komplett-Refactoring der Leitmetapher: **Führerschein → Tresorschlüssel mit Erneuerbarkeits-Klausel**. Solange Passwort und 2FA bekannt sind, kann der Tresorschlüssel jederzeit neu geprägt werden — der alte verliert seine Gültigkeit. Das nimmt der Metapher die Endgültigkeits-Angst, ohne die Kraft zu verlieren. Angenehm fürsorglich formuliert: *"Das ist dein Tresorschlüssel — genauso mächtig, aber ersetzbar solange Passwort und 2FA da sind."*
>
> **Mini-Update 2026-04-26 (NotebookLM-3-Feedback, nur Punkt 4):** Satz-Methode (Kapitel 10) um eine **dritte rote Regel** ergänzt — keine Filmzitate, Songtexte, Sprichwörter, Bibelverse, weil moderne Hacker-Wörterbücher mit Filmskripten und Songtexten gefüttert sind. Anleitung lenkt jetzt explizit auf den **eigenen banalen Alltag** statt Popkultur, plus zweites Beispiel: *"Mein blauer Teppich hat drei Kaffeeflecken vom letzten Dienstag."* → `MbThdKvlD.`. Drei weitere NotebookLM-3-Punkte (Mietvertrag-Framing, Mathematik-Streichung, Email-Reset-Umbau) bewusst **nicht** übernommen.

---

## Inhaltsverzeichnis

### Teil 1 — Worum's geht
1. [Die Kurzfassung — drei Sätze](#1-kurzfassung)
2. [Worum geht's überhaupt?](#2-worum-gehts)
3. [Die zwei Versprechen, die wir dir geben](#3-die-zwei-versprechen)
4. [Die fünf Gegner — und deine Superkraft gegen jeden](#4-die-fuenf-gegner)

### Teil 2 — Wie das funktioniert
5. [Kryptographie in Alltagssprache](#5-kryptographie-alltag)
6. [Der Super-Dietrich — Sicherheitstechnik für eine Zukunft, die noch nicht da ist](#6-super-dietrich)
7. [Die drei Sicherheits-Schichten](#7-schichten)
8. [Der Salzstreuer](#8-salzstreuer)
9. [Zwei-Faktor-Authentifizierung](#9-zweifaktor)
10. [Dein Tresorschlüssel — 10 Minuten jetzt, 10 Sekunden pro Jahr](#10-fuehrerschein)
11. [Die acht Hausregeln (chilliger gefasst)](#11-hausregeln)

### Teil 3 — Technischer Anhang (für Nerds)
A. [Abkürzungsverzeichnis](#a-abkürzungen)
B. [Algorithmen im Detail mit Parametern](#b-algorithmen)
C. [Die Schlüssel-Kaskade (KEK → DEK → Daten)](#c-kaskade)
D. [NIST-Standards und Code-Referenzen](#d-standards)

---

# TEIL 1 — WORUM'S GEHT

---

## 1. Die Kurzfassung — drei Sätze <a id="1-kurzfassung"></a>

Falls du keine Zeit hast, den Rest zu lesen — das Wichtigste:

1. **Wir sind blinde Postboten.** Wir haben nur den Fingerabdruck deines Passworts, nie das Passwort selbst — und ohne das echte Passwort sind deine Daten für uns Zufallszahlen. Das ist **physikalisch unmöglich**, kein Versprechen.
2. **Die strengsten Kontrolleure der Welt haben unsere Tresore zertifiziert** — dieselben, die auch Banken und Krankenhäuser prüfen. Und sie bestätigen nicht nur, dass das Schloss unknackbar ist, sondern auch, dass **wir selbst gar keinen Schlüssel dafür besitzen.**
3. **Du brauchst einmalig 10 Minuten bei der Registrierung — für deinen Tresorschlüssel.** Danach läuft alles automatisch. Einmal im Jahr fragen wir dich liebevoll: *"Weißt du eigentlich noch, wo dein Tresorschlüssel liegt?"* — zwei Sekunden Nicken, fertig. Und solltest du ihn mal verlegen: solange Passwort und 2FA da sind, prägst du dir einfach einen neuen.

Wenn du dich für das "Warum" und "Wie" interessierst — lies weiter. Wenn nicht, reicht das oben.

---

## 2. Worum geht's überhaupt? <a id="2-worum-gehts"></a>

Ein Server speichert **Daten**. Benutzernamen, Passwörter, Chatnachrichten, Profilbilder. Sobald diese Daten auf einer Festplatte liegen, kann sie theoretisch jemand lesen — **außer** man verschlüsselt sie.

**Verschlüsseln** heißt: Die Daten werden mit einem mathematischen Verfahren so durcheinander gewürfelt, dass sie aussehen wie Zufallszahlen. Nur wer den **Schlüssel** hat, kann die Daten zurückwürfeln (entschlüsseln).

Bei Shinpai-AI gilt die einfache Grundregel:

> **Die Server sind blinde Postboten.** Sie transportieren verschlüsselte Päckchen. Sie haben keinen Schimmer, was drin ist.

Drei praktische Konsequenzen:

1. **Wer die Festplatte klaut, hat Datenmüll.** Ohne Schlüssel sind die Bytes wertlos.
2. **Wer den Server hackt, sieht nur Verschlüsseltes.** Angreifer müssten jedes Schloss einzeln knacken — praktisch unmöglich.
3. **Selbst der Betreiber (Owner) kann nicht alles lesen.** Deine persönlichen Inhalte bleiben auch vor ihm verschlossen.

---

## 3. Die zwei Versprechen, die wir dir geben <a id="3-die-zwei-versprechen"></a>

Bevor wir erklären **wie** das funktioniert, geben wir dir zwei Versprechen. Wenn du von dieser Doku nichts anderes mitnimmst — nimm diese beiden Sätze mit:

### Versprechen 1: Wir sind blinde Postboten — und das ist physikalisch unmöglich zu ändern

Bei Shinpai-AI speichert der Server **niemals** dein Passwort. Stattdessen nur den **Fingerabdruck** davon — so wie ein Bankautomat nicht deine Unterschrift speichert, sondern nur prüft ob sie zu einer bestimmten Form passt.

Das hat eine mechanische Konsequenz: Wir können **nachprüfen**, ob du dein Passwort richtig eingegeben hast. Aber wir können das Passwort **nicht wiederherstellen**. Und ohne das echte Passwort können wir deine Daten **nicht entschlüsseln** — auch wenn wir wollten.

Das nennt sich **Zero-Knowledge-Architektur** (wörtlich: "Null-Wissen"). Dasselbe Prinzip wie bei Bitwarden, ProtonMail, Signal. Praktisch heißt das:

- Wenn wir "nur kurz debuggen wollen" — können wir nicht, weil wir keinen Schlüssel haben.
- Wenn Behörden eine Anfrage stellen — wir können denen nichts ausliefern, weil wir nichts haben.
- Wenn du uns selbst bittest, dir deine vergessenen Daten zu retten — wir können nicht, selbst wenn wir wollten.

**Das ist keine Firmen-Regel**, die wir irgendwann brechen könnten. **Das ist die Mathematik selbst**, die uns die Tür zuschließt.

### Versprechen 2: Du musst der Logik vertrauen, nicht uns

Der wichtigste Punkt ist: **Du musst niemandem glauben.** Weder uns, noch einer Behörde, noch einem Siegel. Die Logik selbst trägt das Versprechen.

Stell dir den Postboten nochmal vor. Er trägt verschlossene Päckchen durch die Stadt. Er hat keinen Generalschlüssel — den haben nur die Empfänger. Wenn jemand fragt: *"Können wir dem Postboten vertrauen?"*, ist das die falsche Frage. Die richtige Frage lautet: *"Hat der Postbote überhaupt die Möglichkeit, die Päckchen zu öffnen?"* Antwort: **Nein. Mathematisch ausgeschlossen.**

Genau so funktioniert unser Server. Er bekommt nur Päckchen, kennt aber keinen Schlüssel. Selbst wenn der Server-Betreiber morgens aufstehen und plötzlich böse werden würde — er hätte keinen Hebel, deine Daten zu lesen. **Das ist keine Eigenschaft unseres Charakters, sondern unserer Architektur.**

#### Und wo kommt der TÜV ins Spiel?

Nicht als Beweis, sondern als nachgelagerte Bestätigung für skeptische Augen. Falls du sagst: *"Schöne Theorie, aber stimmt das wirklich so?"* — dann gibt es da draußen unabhängige Prüfer, die das verifiziert haben:

- **NIST** und **IRTF** — die Standardisierungsgremien, die jahrelang an unseren Krypto-Bauteilen geprüft haben, bevor sie offizielle Standards wurden
- **Schweizer Banken**, **Krankenhäuser** und **Messenger wie Signal** — sie nutzen dieselben Bauteile, weil sie keine andere Wahl haben, wenn sie das gleiche Versprechen geben wollen

Aber das ist Beifang. **Der eigentliche Beweis liegt in der Mathematik selbst** — und die ist für jeden Schüler nach zwei Jahren Linearer Algebra nachvollziehbar. Falls du tiefer schauen willst, ist der Weg ab Anhang D offen.

> **Der Punkt:** Es geht nicht darum, ob wir "die Guten" sind. Es geht darum, dass die Architektur selbst dir verspricht: **Selbst wenn wir die Bösen wären, könnten wir dir nichts antun.** Das ist eine andere Qualität von Versprechen.

---

## 4. Die fünf Gegner — und deine Superkraft gegen jeden <a id="4-die-fuenf-gegner"></a>

Verschlüsselung ist immer gegen **konkrete Angreifer** gebaut. Unsere fünf — und wichtig: **zu jedem Angreifer hast du eine eingebaute Superkraft**, die ihn neutralisiert.

### Gegner 1: Der Festplatten-Dieb

**Szenario:** Jemand klaut den Server oder die Festplatte, schließt sie an anderen Computer an.

**Deine Superkraft:** Wenn der Server **aus** ist, sind alle Schlüssel weg — sie waren nur im Arbeitsspeicher, der ist beim Ausschalten leer. Die Dateien auf der Platte sind unlesbarer Müll.

**Was du dafür tun musst:** Nichts. Das läuft automatisch.

### Gegner 2: Der Online-Hacker

**Szenario:** Angreifer findet eine Sicherheitslücke in der Software, bekommt Zugriff auf die Datenbank.

**Deine Superkraft:** Die Datenbank enthält nur **verschlüsselte Päckchen**, nicht die Inhalte. Selbst voller Datenbank-Zugriff ist wertlos ohne die User-Schlüssel.

**Was du dafür tun musst:** Nichts. Das läuft automatisch.

### Gegner 3: Der Owner selbst

**Szenario:** Der Server-Betreiber wird neugierig oder von Behörden unter Druck gesetzt.

**Deine Superkraft:** Die Inhalte sind mit **User-Schlüsseln** verschlüsselt, die der Owner nicht hat und nicht bekommen kann. Dein Passwort verlässt nie deinen Browser.

**Was du dafür tun musst:** Nichts. Das läuft automatisch.

### Gegner 4: Das Leben selbst — Social Engineering, Phishing, Panik-Mache

Das ist der tückischste Angreifer. Nicht der geniale Hacker oder die böse Behörde — sondern **manipulierte Menschen**, die dein Gehirn direkt angreifen, nicht unsere Technik.

Die ehrliche Wahrheit: Hier kann die beste Kryptographie nichts mehr tun, wenn du in Panik auf den falschen Knopf drückst. **Deshalb bauen wir dir hier keine technischen Airbags — sondern eine psychologische Rüstung**, die du zu Hause anlegen kannst. Drei einfache Regeln, die in jeder Bedrohung funktionieren.

---

#### 🛡️ Die goldene Regel: Die 10-Sekunden-Atempause

**Merk dir nur diesen einen Satz:**

> **Shinpai-AI wird dich niemals — unter keinen Umständen — zu sofortigen Handlungen drängen.**
>
> **Wenn etwas extrem eilt und du nur noch Sekunden Zeit hast — ist es zu 100% ein Betrug.**

Das ist der ultimative Phishing-Killer. Warum? Weil alle modernen Angriffe darauf basieren, deinen Verstand kurzzuschließen. Sie erzeugen künstliche Panik:

- **Pop-ups:** *"Dein System ist infiziert! Rufen Sie SOFORT den Microsoft-Support!"*
- **SMS um 3 Uhr morgens:** *"Ihr Konto wird in 3 Minuten gelöscht, wenn Sie nicht jetzt bestätigen!"*
- **Gefälschte Mails:** *"Dringend! Letzte Warnung! Jetzt klicken!"*

In diesem Moment der Panik schaltet dein Gehirn auf **Kampf oder Flucht** — und der Teil, der rational denkt, wird überstimmt. Die beste Technik nützt nichts, wenn du zitternd auf den Knopf drückst.

**Deshalb:** Wenn jemand Druck aufbaut — **atme 10 Sekunden durch**. Diese 10 Sekunden reichen, um zu erkennen: *Das kann nicht wahr sein. Shinpai-AI drängt nie.*

---

#### 🛡️ Die zweite Regel: Leg auf. Schließ das Fenster. Geh weg.

Wir geben dir die **offizielle Erlaubnis zur absoluten Passivität**.

Egal ob am Telefon, per Mail, per SMS oder auf dem Bildschirm — wenn jemand dir extremen Druck macht, **reagiere nicht**. Leg auf. Schließ das Fenster. Schalt das Gerät aus, wenn nötig.

**Wir bauen niemals Druck auf. Niemand bei Shinpai-AI wird dich je zu etwas nötigen.** Jeder, der es tut, ist nicht Shinpai-AI.

---

#### 🛡️ Die dritte Regel: Vertraue nur dem, was in der App passiert

Wichtige Warnungen zu deinem Konto siehst du **ausschließlich dann**, wenn du selbst unsere App geöffnet hast. Nicht per SMS, nicht per Mail, nicht als Pop-up, nicht als Anruf.

**Alles, was dich über andere Wege erreicht, kannst du blind ignorieren.**

Das reduziert deine geistige Last enorm. Du musst nicht hunderte Betrugsmaschen erkennen lernen. Du musst dir nur diese einfache Wahrheit merken:

> **Wenn der Druck außerhalb der App passiert — ist es falsch.**
>
> **Wenn der Druck innerhalb der App passiert — ist es auch falsch. Wir drängen nie.**

---

### Zusammenfassung deiner 3 Rüstungs-Regeln gegen Gegner 4:

1. **10-Sekunden-Atempause bei Druck** — Shinpai-AI drängt nie.
2. **Leg auf, schließ weg, geh raus** — du hast die Erlaubnis zur Passivität.
3. **Vertraue nur der App** — alles andere ist nicht Shinpai-AI.

Diese drei Sätze sind deine komplette Phishing-Immunität. Prägenhaft, einfach, funktioniert sogar wenn du gerade unter Schock stehst.

---

### Gegner 5: Die Realität deines Wohnzimmers

**Szenario:** Du hast die digitale Festung. Aber dein Tresorschlüssel liegt jetzt auf Papier in deiner Wohnung. Mitbewohner werfen einen Blick in offene Schubladen. Ein Einbrecher räumt Schreibtische ab. Ein Wasserschaden weicht alles auf. **Das Internet ist sicher — die physische Welt ist es nicht automatisch mit.**

**Deine Superkraft:** Ein paar einfache Aufbewahrungs-Routinen, die jeder Mensch ohne Sicherheitsausbildung umsetzen kann. Kein Tresor nötig, kein Drama, nur überlegt platzieren.

#### So lagerst du das Papier sinnvoll

- **Bei den anderen wichtigen Dokumenten.** Geburtsurkunde, Versicherungspolicen, Mietvertrag, Sparbuch — diesen Stapel hat fast jeder, niemand wühlt darin freiwillig herum, und du findest die Mappe immer wieder. Genau dorthin gehört dein Tresorschlüssel-Papier.
- **Im Aktenordner "Persönliche Unterlagen".** Wenn du sowieso so einen Ordner führst, einfach hinten ein Trennblatt rein, Zettel davor.
- **Nicht offen sichtbar.** Nicht an die Pinnwand, nicht unter die Tastatur, nicht auf den Schreibtisch.
- **Plus die kleine Verteilung gegen Totalverlust:** Den Backup-Codes-Zettel an einen zweiten Ort — bei einer Vertrauensperson, im Bankschließfach oder bei den Eltern. So überlebt dein Zugang auch einen Wohnungsbrand. Für die meisten Menschen ist das Overkill, aber wenn du paranoid bist, ist es die saubere Linie.

#### Was du dafür tun musst

Einmal nachdenken, wo deine wichtigen Dokumente liegen, und den Tresorschlüssel dazu legen. Das ist alles. Keine Sicherheitstür, kein Spezial-Beutel, kein Code. Eine ruhige Mappe an einem ruhigen Ort.

---

## ⚡ Und dann bleibt noch eine letzte Sache: Dein Tresorschlüssel

Es gibt noch ein paar **ganz normale Alltagspannen** — das Handy fällt ins Wasser, du vergisst ein Passwort, dein WG-Kumpel tippt was ein. Für all das hast du **einen Tresorschlüssel**, den du einmalig bei der Registrierung prägst. Kapitel 10 erklärt das im Detail — aber hier die Kurzfassung:

> **Wer den Tresorschlüssel hat, kommt immer wieder rein.**
>
> **Der Tresorschlüssel ist ein Stück Papier** (Seed-Phrase + Backup-Codes), das du einmal bei der Registrierung notierst und zu deinen wichtigen Dokumenten legst.
>
> **Und das Schöne daran:** Solange du dein Passwort und deine 2FA hast, kannst du jederzeit einen neuen Schlüssel prägen lassen — der alte verliert seine Gültigkeit. Verlegt? Kein Problem, neu prägen.

**Das ist keine Drohung, sondern eine Superkraft.** Du hast den einzigen Schlüssel zu deinen Daten. Niemand — kein Angreifer, keine Behörde, nicht mal wir — kann dich bevormunden. *Du bist der alleinige Chef über deinen Tresor.*

Der Preis dafür: **10 Minuten einmalige Konzentration bei der Registrierung**. Danach öffnest du täglich deinen Tresor — wir stupsen dich einmal im Jahr kurz an: *"Weißt du noch, wo dein Tresorschlüssel liegt?"* Zwei Sekunden Nicken. Fertig.

---

# TEIL 2 — WIE DAS FUNKTIONIERT

---

## 5. Kryptographie in Alltagssprache <a id="5-kryptographie-alltag"></a>

### Symmetrische Verschlüsselung — das Vorhängeschloss

**Bild:** Ein Vorhänge-Schloss. Ein Schlüssel schließt auf, derselbe schließt zu. Wer den Schlüssel hat, hat alles.

**Vorteile:**
- **Sehr schnell** — Gigabytes pro Sekunde
- **Sehr sicher** bei ausreichender Schlüssel-Länge

**Problem:** Wie kriegt der Empfänger den Schlüssel? Übers Internet schicken geht nicht — jeder Mitlauscher hätte ihn auch.

**Lösung bei uns:** Entweder direkt aus einem Passwort berechnen (im gleichen Kopf), oder via Briefkasten-Verfahren (siehe unten) durchs Internet schicken.

*(Name und Details: Anhang B.1)*

### Asymmetrische Verschlüsselung — der Briefkasten

**Bild:** Ein Briefkasten mit **zwei** Schlüsseln:
- Der **öffentliche** Schlüssel schließt nur zu — wie der Einwurf-Schlitz. Darf jeder haben.
- Der **private** Schlüssel schließt auf — nur der Besitzer hat ihn.

Alice postet ihren öffentlichen Schlüssel. Bob verschlüsselt damit eine Nachricht. Nur Alice kann sie lesen.

**Vorteile:**
- Der öffentliche Schlüssel kann **offen herumgezeigt** werden
- Perfekt fürs Internet

**Nachteile:**
- **Viel langsamer** als das Vorhängeschloss
- Deshalb nur für **kleine Pakete** wie Schlüssel-Austausch, nie für große Daten

*(Name und Details: Anhang B.4 und B.5)*

### Hash-Funktionen — der Fleischwolf

**Bild:** Ein Fleischwolf. Oben rein — egal ob Kuchenrezept oder Elefant. Unten immer: ein 64-Zeichen-Fingerabdruck gleicher Länge.

**Eigenschaften:**
- **Einbahnstraße** — vom Fingerabdruck nie zurück zum Original
- **Deterministisch** — gleiches rein, gleiches raus
- **Ultra-sensibel** — ein Komma Unterschied im Rezept, komplett anderer Fingerabdruck

**Wofür wir das nutzen:**
- Passwort-Fingerabdruck statt Klartext-Passwort speichern
- Dateien auf Manipulation prüfen
- Digitale Unterschriften

*(Name und Details: Anhang B.2)*

### Passwort-Verstärker — der Tresor mit Zeitverzögerung

**Problem:** Ein Passwort wie `HundKatze123` ist zu kurz und zu wenig zufällig, um direkt als Schlüssel zu dienen.

**Lösung — Bild:** Ein **Tresor mit eingebauter Zeitverzögerung**. Jeder Versuch, ihn zu öffnen, dauert absichtlich **1 Sekunde** — egal ob der Schlüssel stimmt oder nicht.

**Warum das brutal wirkt:** Angreifer probieren Millionen Passwörter durch. Wenn jeder Versuch nur Milliardstel-Sekunden dauert, sind sie in Stunden durch. Wenn jeder Versuch 1 Sekunde dauert, sind sie in **Jahrhunderten** durch. Aus "in ein paar Stunden geknackt" wird "in 31 Jahren vielleicht geknackt".

Zusätzlich frisst jeder Versuch **viel Arbeitsspeicher**. Hacker-Farmen haben wenig davon — das strangelt sie wirtschaftlich.

Der Witz ist: Wir drehen den Spieß um. Die Gier und die Hardware-Grenzen der Angreifer arbeiten jetzt **gegen sie**.

*(Name und Parameter: Anhang B.3)*

---

## 6. Der Super-Dietrich — Sicherheitstechnik für eine Zukunft, die noch nicht da ist <a id="6-super-dietrich"></a>

### Das Bild

Stell dir vor: Experten gehen davon aus, dass in etwa **15 Jahren** jemand einen **Super-Dietrich** erfindet. Ein Werkzeug, das heutige Schlösser öffnen kann — ohne den Schlüssel zu kennen. Nicht magisch, einfach eine neue Art von Mathematik, an der weltweit geforscht wird.

**Die gute Nachricht:** Es gibt diesen Super-Dietrich noch nicht. Aber wir bauen schon heute so, dass er uns nichts anhaben kann.

### Wie wir das machen: Tresore ohne Schlüsselloch

Die einfache Lösung: **Wir bauen für deine wichtigen Sachen Tresore ein, die gar kein Schlüsselloch mehr haben — zumindest keins, an dem der Super-Dietrich ansetzen könnte.** Stattdessen benutzen wir eine völlig andere Art von Verschluss. Eine, die nach einer anderen Mathematik funktioniert, mit der auch der Super-Dietrich nichts anfangen kann.

Wenn er also irgendwann kommt, findet er bei uns nur glatte Stahlwürfel — nichts, wo er ansetzen könnte.

### Warum schon heute?

Weil jemand, der deine heutigen Nachrichten sammelt (das passiert, wir können's nicht verhindern), sie in 15 Jahren mit dem Super-Dietrich lesen könnte — **falls** wir heute alte Schlösser benutzen würden.

Benutzen wir aber die neuen, schlüssellochlosen Tresore, sind deine heutigen Daten **auch in 20 Jahren** sicher. Kein Katz-und-Maus-Spiel mit einer unsichtbaren Zukunft.

### Was konkret dahintersteckt

Die neue Art Verschluss heißt **Post-Quantum-Kryptographie** — die Mathematik für die Zeit nach dem Super-Dietrich (der in der Fachwelt Quantencomputer heißt). 2024 hat die NIST nach **8 Jahren weltweiter Prüfung** zwei dieser neuen Verfahren zertifiziert. Die tragen jetzt das **TÜV-Siegel** für die Zukunft. Wir haben sie sofort eingebaut.

**Bedeutet für dich:**
- Daten, die du heute verschlüsselst, bleiben **auch in 20 Jahren** sicher
- Kein Migrations-Schock, wenn der Super-Dietrich irgendwann da ist
- Kein "später bereuen"

*(Welche Verfahren genau: Anhang B.4, B.5 und D)*

### Eine Einschränkung am Rande

Nicht alle unsere Schlösser sind gefährdet. Das **Vorhängeschloss** (symmetrische Verschlüsselung) kann dem Super-Dietrich kaum was anhaben — ein dickeres Schloss reicht schon. Nur der **Briefkasten** (asymmetrisch) braucht komplett neue Mathematik. Und die haben wir eingebaut.

---

## 7. Die drei Sicherheits-Schichten <a id="7-schichten"></a>

Stell dir ein **Schiff mit Frachtraum** vor. Drei Ebenen.

### Schicht 1 — Die Kapitänskajüte (Server-Master)

- **Wer hat den Schlüssel?** Nur der Betreiber des Servers. Leitet ihn aus **Passwort + 2FA + Computer-Fingerabdruck** ab.
- **Was schützt sie?** Die ganze Festplatte. Server aus = alles unlesbar.
- **Wie aufschließen?** Betreiber loggt sich nach Server-Start ein. Erst dann fließen Daten.
- **Festplatte auf anderen Computer kopiert?** Müll. Computer-Fingerabdruck passt nicht.

### Schicht 2 — Die Mannschafts-Schließfächer (User)

Normales Login: Name + Passwort + 2FA. **Dein Passwort verlässt niemals deinen Browser.** Der Server bekommt nur den Fingerabdruck — er kann prüfen ob du stimmst, aber nicht, was in deinem Schließfach liegt.

Der Schlüssel für deine Inhalte wird **lokal** in deinem Browser aus deinem Passwort berechnet. Der Server sieht nur verschlüsselte Päckchen. Gleiches Prinzip wie bei Bitwarden oder ProtonMail.

**Was das für den Betreiber heißt:** Selbst wenn er Schicht 1 geöffnet hat — die Inhalte deines Schließfachs bleiben für ihn verschlüsselter Müll. Er hat dein Passwort nicht, er kann dein Schließfach nicht aufschließen.

*(Wie Session-Tokens, Datenschlüssel und Ablauf im Detail technisch verzahnt sind: Anhang C)*

### Schicht 3 — Die Räume, Tische und Channels (Gruppen-Schlüssel)

- **Wer hat den Schlüssel?** Alle Mitglieder des Raums. Bekommen ihn beim Beitritt.
- **Wie wird er verteilt?** Über das Briefkasten-Prinzip (Kapitel 5): mit dem öffentlichen Schlüssel des neuen Mitglieds verschlüsselt übergeben — nur er mit seinem privaten Schlüssel kann auspacken.
- **Was schützt sie?** Alle Nachrichten im Raum. Server sieht nur Päckchen.

*(Wie die Schichten technisch verzahnt sind: Anhang C)*

---

## 8. Der Salzstreuer <a id="8-salzstreuer"></a>

Ein besonderes Feature im Sicherheits-Tab: der **Salzstreuer-Button**.

### Was er tut — in einem Satz

**Ein Knopf, der dein Schloss auf Knopfdruck noch sicherer macht — selbst falls jemand alte Daten von dir gestohlen hat.**

### Wozu das gut ist

Sicherheits-Systeme haben eine unangenehme Eigenschaft: Wenn jemand heute eine Kopie deines Tresors klaut und im Keller zwei Jahre dran rechnet, könnte er irgendwann dein Passwort knacken. Drück du ab und zu auf den Salzstreuer, ist seine Rechenarbeit vergebens — **alles was danach passiert ist, kann er nicht mehr lesen**.

Kurz: Ein freiwilliger Zusatz-Airbag für Paranoide und Vorsichtige. Wenn du den Knopf nie drückst, ist auch nichts unsicher — er macht's nur noch sicherer.

### Die Regeln

- **Höchstens 1× pro 24 Stunden** — damit nicht Bots ihn endlos auslösen
- **Nur sichtbar, wenn 2FA aktiv ist** — ist ein sensibler Hebel
- **Passwort + 2FA nötig beim Klicken** — zur Echtheits-Prüfung

### Die humorvollen Wartemeldungen

Wenn du innerhalb 24 h nochmal klickst, bekommst du eine lustige Meldung statt eines nüchternen Fehlers:

- **Kneipe:** *"Ruhig, Kompaniechef. Mehr Salz gibt's erst mit dem nächsten Tequila — morgen."*
- **ShinNexus:** *"Das Salz ist heilig, Padawan. Verwende es sparsam — morgen wieder."*
- **ShinPing:** *"Zu viel Salz macht krank. Das Körnchen von heute muss reichen."*
- **Shidow:** *"Der Schatten ist noch salzig genug. Operation ausgesetzt — bis morgen."*

Wir finden: Knallharte Sicherheit darf auch Humor haben. Das macht das System menschlicher.

---

## 9. Zwei-Faktor-Authentifizierung — das Zweier-Schloss <a id="9-zweifaktor"></a>

### Das Prinzip

**Ein Faktor reicht nicht.** Passwörter werden gephisht, erraten, geklaut. Deshalb: **zwei** unabhängige Beweise.

| Typ | Beispiel | Problem wenn allein |
|---|---|---|
| **Etwas, das du weißt** | Passwort, PIN | Phishbar |
| **Etwas, das du hast** | Handy, Hardware-Token | Klaubar, verlierbar |
| **Etwas, das du bist** | Fingerabdruck, Gesicht | Wenn einmal kompromittiert, nie änderbar |

Bei uns: **Passwort** (wissen) + **6-stelliger Code aus deiner Authenticator-App** (haben = Handy).

### Einrichtung (einmalig, ~3 Minuten — du kannst nichts falsch machen)

**Schritt 1 — Die App holen (1 Minute).**
Lade dir eine App wie **Aegis** (Android) oder **Raivo** (iPhone) herunter — das sind deine digitalen Schlüsselbünde. Sie funktionieren von ganz allein, du musst dort nichts einstellen, nichts verstehen. Einfach installieren und die App einmal öffnen. *Du kannst dabei nichts kaputt machen.*

**Schritt 2 — QR-Code scannen (30 Sekunden).**
Bei uns klickst du auf "2FA aktivieren". Wir zeigen dir einen QR-Code am Bildschirm. In deiner Authenticator-App tippst du auf "+" und hältst das Handy vor den Bildschirm. Zack — der QR-Code wird erkannt, fertig.

**Schritt 3 — Einmal bestätigen (30 Sekunden).**
Die App zeigt dir ab jetzt alle 30 Sekunden einen **6-stelligen Code**. Tippe den aktuellen Code einmal bei uns ein — zur Bestätigung, dass alles geklappt hat. Fertig.

**Schritt 4 — Backup-Codes sichern (1 Minute).**
Direkt danach zeigen wir dir **10 Backup-Codes**. Das ist dein Airbag, falls dein Handy mal streikt. Die kommen in den Tresorschlüssel — Details in Kapitel 10. *Nicht überspringen, aber kein Stress: wir erklären dir gleich, wie du sie sicher ablegst.*

**Wenn irgendwas hakt:** Schließ das Fenster, starte neu, versuch's nochmal. Es gibt **nichts, was du durch Ausprobieren kaputt machen kannst**. Das System hat dich in der Hand, nicht umgekehrt.

### Jedes Login

1. Passwort + aktuellen 6-stelligen Code eingeben.
2. Server prüft beides.
3. Passt → drin.

### Warum das sicher ist

- Das Geheimnis, aus dem die Codes gerechnet werden, verlässt **nie** dein Handy
- Ein Angreifer sieht nur 6-stellige Codes, die 30 Sekunden gelten. Geklaut nach 30 Sek = wertlos

*(Wie das mathematisch läuft: Anhang B.6)*

---

## 10. Dein Tresorschlüssel — 10 Minuten jetzt, 10 Sekunden pro Jahr <a id="10-fuehrerschein"></a>

Dieses Kapitel ist **wichtig, aber kein Alarm**. Lies es in Ruhe durch. Am Ende hast du verstanden, warum wir dich zu etwas einladen, das dich **unangreifbar** macht — nicht ängstlich.

### Die eine Frage vorweg: Warum überhaupt ein Tresorschlüssel?

Weil deine Daten **ausschließlich dir** gehören — und nicht uns. Das ist keine Marketing-Phrase, sondern architektonische Realität. Wir haben technisch keinen Nachschlüssel zu deinen Daten. **Selbst wenn wir wollten, könnten wir dich nicht bevormunden.**

Das ist genau das Feature, wegen dem du Shinpai-AI überhaupt nutzt. **Kein Konzern, keine Behörde, nicht mal der Betreiber** kann an deine Inhalte. Das ist deine Superkraft.

Und wie bei jeder Superkraft: du brauchst ein bisschen Einweisung, damit du sie richtig nutzt. Das ist dein **Tresorschlüssel**.

### Das Wichtigste zuerst — der Tresorschlüssel ist ersetzbar

Bevor wir in die Details gehen, eine angenehme Klarstellung, die jede Angst rausnimmt:

> **Dein Tresorschlüssel ist mächtig, aber er ist kein einmaliges Artefakt, das du nie wieder bekommst.**
>
> **Solange du Passwort und 2FA hast, kannst du jederzeit einen neuen prägen lassen.** Der alte wird mit einem Knopfdruck ungültig — wie bei einem modernen Hotel, wo das Zimmerschloss bei Schlüsselverlust einfach neu codiert wird.

Das heißt für dich:

- **Verlegt?** Neu prägen. Zwei Klicks, dreißig Sekunden.
- **Mitbewohner hat ihn versehentlich weggeworfen?** Neu prägen, sobald du es merkst.
- **Wasserschaden in der Mappe?** Neu prägen.
- **Unsicher, ob du noch weißt wo er liegt?** Neu prägen, bevor du nachschaust.

Der Tresorschlüssel ist **nur dann unwiederbringlich**, wenn du gleichzeitig auch Passwort und 2FA verlierst. Genau für diesen seltenen Fall bauen wir die drei Sicherheitsnetze, die unten kommen. Aber im Alltag bist du nie nur einen Stolperstein vom Totalverlust entfernt.

### Was du damit bekommst

**Grenzenlose Freiheit in der digitalen Welt.**

- Niemand kann deine Daten gegen deinen Willen lesen.
- Niemand kann deinen Account sperren lassen, außer du selbst.
- Niemand kann dich per Reset-Knopf aussperren.
- Kein Geheimdienst, kein Betreiber-Mitarbeiter, kein Hacker mit Datenbank-Zugriff.

Du bist der **alleinige Chef** über deinen Tresor. Das gibt es in der digitalen Welt sonst kaum irgendwo.

### Was passiert eigentlich, wenn etwas schiefgeht?

Bevor wir die drei Papiere durchgehen, beantworten wir die Frage, die jeder vernünftige Mensch an dieser Stelle stellt: *"Was, wenn ich diese Papiere mal verlege oder mein ahnungsloser Mitbewohner sie versehentlich in den Papiermüll wirft?"*

**Du bist nicht allein. Wir haben dafür drei Sicherheitsnetze gebaut, die ineinander greifen:**

- **Netz 1 — Du hast immer einen Backup-Pfad.** Selbst wenn du dein Passwort vergisst: deine 12 Seed-Wörter sind ein zweiter Weg zum Datenschlüssel. Selbst wenn dein Handy mit der 2FA-App ins Wasser fällt: deine Backup-Codes auf Papier sind ein dritter Weg.
- **Netz 2 — Die 7-Tage-Bedenkzeit.** Falls jemand "Passwort vergessen" klickt, passiert **keine sofortige Löschung**. Stattdessen bekommst du eine Warnmail und hast **eine Woche Zeit**, dich mit dem alten Passwort einzuloggen und alles abzubrechen. Das ist wie deine Bank, die eine ungewöhnliche Auslandsüberweisung erst mal blockiert und nachfragt.
- **Netz 3 — Die räumliche Verteilung.** Wenn du paranoid bist, kannst du Seed und Backup-Codes an zwei verschiedenen Orten lagern. Dann überlebt dein Zugang sogar einen Wohnungsbrand. (Details bei Papier 2.)

**Erst wenn alle drei Netze gleichzeitig reißen** — du verlierst Passwort, Seed und Backup-Codes auf einmal **und** verpasst die Warnmail eine Woche lang **und** hast keinen Zweitstandort — sind die Daten weg.

Das ist der Preis für absolute Privatsphäre. Aber es ist nicht ein Stolperstein, sondern eine Reihenschaltung mit ineinandergreifenden Bremsen. Beim normalen Stolpern fängt dich was ab.

### Was der Tresorschlüssel ist

Drei Stücke Papier. Das ist alles.

#### Papier 1: Die Seed-Phrase (12 Wörter)

Bei der Registrierung zeigen wir dir **12 Wörter** aus einer festen Wörterliste. Diese 12 Wörter sind dein **zweiter Weg** zum Datenschlüssel — unabhängig vom Passwort.

**✏️ Das Einrichtungs-Ritual (3 Minuten — und du bist offiziell dein eigener Chef):**

1. **Nimm einen Kugelschreiber und einen Zettel.** Kein Bleistift (verblasst mit den Jahren), kein Filzstift (verläuft bei Feuchtigkeit). Kugelschreiber-Tinte hält ein Menschenleben.
2. **Schreibe die 12 Wörter nacheinander ab.** Groß, leserlich, nummeriert von 1 bis 12. Kein Stress, du hast Zeit.
3. **Lies einmal laut nach, einmal still gegen.** Eine Minute Sorgfalt jetzt erspart dir später jede mögliche Sucherei. Dieses Blatt Papier ist dein Rettungsanker.
4. **Leg es zu den anderen wichtigen Dokumenten.** Reisepass, Geburtsurkunde, Versicherungs-Mappe. Ein Ort, den du immer wiederfindest — und an den du sonst nur selten ranmusst.

#### 🌟 Die Logik deiner Superkraft — warum bestimmte Aufbewahrungen passen und andere nicht

Du hast jetzt etwas, das niemand sonst hat: einen Schlüssel zu deinen Daten, der nirgendwo digital existiert. Damit das so bleibt, muss er **außerhalb der digitalen Welt** wohnen. Daraus ergibt sich von alleine, was passt und was nicht:

- **Tinte und Papier sind unsichtbar für Hacker.** Das ist deine eigentliche Stärke. Solange dein Schlüssel auf Papier lebt, kann ihn niemand übers Internet erreichen.
- **Ein Foto vom Bildschirm wäre wieder digital** — selbst wenn du es "nur kurz" machst, landet es in der Galerie, oft in der Cloud, manchmal auf einem alten Handy. Das nimmt dir die Superkraft.
- **Notizen-Apps, Textdateien, Cloud-Speicher** sind alle digital — auch sie würden den Schlüssel zurück ins Internet holen.
- **Passwort-Manager** sind grundsätzlich gut, aber für deinen Tresorschlüssel das falsche Werkzeug: dann lägen zwei kritische Geheimnisse im selben Korb.
- **Mit niemandem teilen.** Auch nicht mit uns — wir fragen niemals danach. Jeder, der danach fragt, ist Betrug.

Das ist keine Verbotsliste, sondern die natürliche Konsequenz deiner Wahl. **Dein Geheimnis funktioniert nur, solange es offline bleibt.**

**Kein Drucker? Sogar besser.** Ein handschriftlich abgeschriebener Zettel ist sicherer als ein Ausdruck — du machst ihn genau einmal, und kein Drucker-Cache hat die Wörter je gesehen.

Wenn du mal dein Passwort vergisst: Seed eingeben → neues Passwort setzen → alles wieder da.

#### Papier 2: Die 2FA-Backup-Codes (10 Stück)

Bei der 2FA-Einrichtung bekommst du **10 Einmal-Codes**. Wenn dein Handy mal verloren geht oder ins Wasser fällt, nutzt du einen davon, loggst dich ein, richtest einen neuen Authenticator auf dem neuen Handy ein. Fertig.

**Das gleiche Ritual wie bei der Seed-Phrase:** Kugelschreiber, Zettel, ab in die Mappe der wichtigen Dokumente. Auch hier gilt die gleiche Logik — sobald die Codes digital existieren, sind sie wieder im Internet erreichbar. Wenn du keinen Drucker hast: die ersten 3 Codes reichen als Absicherung, die schreibst du in zwei Minuten ab.

**Tipp für die Verteilung gegen Totalverlust:** Du kannst die Backup-Codes auch räumlich von der Seed-Phrase trennen — die Seed bei dir in der Wohnung, die Codes bei einer Vertrauensperson oder im Bankschließfach. So überleben deine Daten auch einen Wohnungsbrand. Ist Overkill für die meisten, aber wenn du ganz auf Nummer sicher gehen willst, ist es die saubere Linie.

#### Papier 3: Dein Passwort (in deinem Kopf oder im Passwort-Manager)

Das benutzt du jeden Tag. Es ist der **Hauptschlüssel**. Papier 1 und 2 sind nur da, falls du Papier 3 mal vergisst oder dein Handy streikt.

**🔑 So baust du ein wirklich starkes Passwort — die Satz-Methode**

Der Tresor mit Zeitverzögerung aus Kapitel 5 ist nur dann eine Festung, wenn dein Passwort eine bestimmte Mindest-Stärke erreicht. Sonst öffnet ein Wörterbuch-Angreifer trotz aller Mathematik in Stunden, was dich für immer schützen sollte.

Die drei einfachen Regeln, an denen sich jede Hacker-Farm die Zähne ausbeißt:

1. **Mindestens 12 Zeichen.** Erst ab dieser Länge beißt sich eine Hacker-Farm an unserem Zeit-Tresor wirklich aus. Kürzer = das Schloss aus Plastik, egal wie dick die Tresorwand ist.
2. **Kein einzelnes Wort, keine Tastatur-Reihe, kein Geburtstag.** "Schalke04", "qwerty123" oder "Anna1985" stehen alle in jedem Hacker-Wörterbuch auf den ersten paar tausend Plätzen — auch mit unserer Verzögerung in zwei Stunden geknackt.
3. **🚫 Keine Zitate aus Filmen, Büchern, Songtexten, Sprichwörtern oder Bibelversen — auch nicht in Anfangsbuchstaben.** Hacker füttern ihre Algorithmen heute mit ganzen Filmskripten, Wikipedia-Artikeln und Songtexten. Die Zeitverzögerung im Tresor nützt nichts, wenn dein Satz schon in deren Liste auf Platz drei Millionen steht — das System testet die Phrase als zusammenhängenden Hash, nicht Wort für Wort, und der Tresor öffnet sich sofort.

**Die Satz-Methode (kostet 20 Sekunden, hält ein Leben lang):**

Denk dir einen absurden Satz aus, den nur du kennst — am besten mit einem winzigen, banalen Bild aus deinem **eigenen Alltag**: etwas, das nur in deinem Wohnzimmer, deiner Küche oder auf deinem Schreibtisch existiert. Schau dich buchstäblich um. Ein Fleck auf dem Teppich, der Goldfisch im Glas, die Marotte deiner Katze — solche Sätze stehen in keinem Hacker-Wörterbuch der Welt, weil sie zu banal und zu individuell sind. Nimm dann die Anfangsbuchstaben jedes Wortes, behalte Satzzeichen und Zahlen.

Beispiele:

- *"Mein Goldfisch Erwin frisst um 7 Uhr nur grüne Erbsen!"* → `MGEfu7Unge!`
- *"Mein blauer Teppich hat drei Kaffeeflecken vom letzten Dienstag."* → `MbThdKvlD.`
- *"3 Pinguine tanzen im Sommer auf meinem Dach mit Sonnenbrille."* → `3PtiSamDmS.`
- *"Hauptsache der Kaffee ist heiß, sonst werd ich grantig — jeden Morgen."* → `HdKih,swig-jM.`

Solche Passwörter sind:

- Mathematisch genauso sicher wie zufälliger Buchstabensalat
- Aber **viel leichter zu merken**, weil ein Bild dahinter steckt
- Und sie tauchen in keinem Wörterbuch auf, weil der Satz nur in deinem Kopf existiert

**Wichtig:** Niemals dasselbe Passwort wie auf anderen Diensten. Dieses hier gehört nur uns — der Hauptschlüssel zu deinem Tresor.

### Die 10 Minuten bei der Registrierung — Schritt für Schritt

Genau diese 10 Minuten machen dich für immer unabhängig. Einmalig — und sollte etwas schiefgehen, prägst du jederzeit einen neuen Schlüssel. **Leg dir Kugelschreiber und einen leeren Zettel bereit, bevor du loslegst** — das ist alles, was du brauchst.

1. **Minute 1–3:** Account erstellen, Passwort wählen, 2FA mit deiner Authenticator-App verbinden (siehe Kapitel 9).
2. **Minute 4–6:** Seed-Phrase mit Kugelschreiber abschreiben (wir zeigen sie dir dafür einmal am Bildschirm). Wort für Wort, nummeriert, einmal laut nachlesen. In die Unterlagen-Mappe legen.
3. **Minute 7–9:** Backup-Codes mit Kugelschreiber abschreiben. Gleiche Mappe.
4. **Minute 10:** Kurz durchatmen. Du bist jetzt offiziell dein eigener Chef.

Nur Kugelschreiber, Zettel, Mappe — fertig. **Du hast deinen Tresorschlüssel. Ab jetzt steht dein Tresor immer für dich offen.**

### 🌱 Der Jahres-Check — 10 Sekunden auf dem Sofa

Hier ist die eine kleine Erinnerung, die dich sicher hält, ohne zu nerven.

**Einmal im Jahr** — an einem ruhigen Moment — fragt dich die App beim Login nebenbei:

> *"Hey, nur kurz für dich selbst: Weißt du eigentlich noch, wo dein Tresorschlüssel liegt?"*
> *[ Ja — die rote Mappe im Arbeitszimmer ] [ Ich schau gleich mal nach ] [ Später daran denken ]*

**Kein Zwang, niemand schaut hin, keine Konsequenz wenn du "Später" drückst.** Es ist ein **Mental-Check** — zwei Sekunden Bestätigung, dass du den Ort noch im Kopf hast.

Der Punkt dahinter: Dein Papier-Backup liegt in 5 Jahren vielleicht noch in derselben Mappe. Oder es ist beim Umzug versehentlich weggeworfen worden. Oder in einen anderen Schrank gewandert. **Dieser kleine Jahres-Impuls hilft dir, den Ort mental zu verifizieren**, bevor du ihn wirklich brauchst.

**So wird aus "vergrabener Schatz, den man in Panik sucht" eine "Routine-Ortskontrolle"** — ganz ruhig, ganz unbedrohlich.

> **Der Vergleich mit einem echten Tresorschlüssel:** Wer einen Bankschließfach-Schlüssel hat, weiß genau wo er ist — sonst kommt er nicht mehr ans Schließfach. Bei dir liegt der Tresorschlüssel jahrelang ungenutzt im Schrank, weil das Passwort die Tür sowieso öffnet. Deshalb nutzen wir diesen winzigen Jahres-Impuls als mentale Erinnerungsbrücke. Nicht mehr, nicht weniger.

### Die 7-Tage-Gnadenfrist — dein Zusatz-Airbag

Selbst wenn du mal in Panik gerätst und denkst "Oh Gott, mein Passwort ist weg!" — wir haben eine eingebaute Sicherheits-Pause.

Wenn jemand "Passwort vergessen" klickt (du oder ein Angreifer), passiert **keine sofortige Löschung**. Stattdessen startet eine **7-Tage-Frist**:

1. Du bekommst eine Warn-Mail: *"Achtung — wenn du das durchziehst und die Seed nicht mehr findest, sind die Daten weg. 7 Tage zum Überlegen."*
2. In diesen 7 Tagen kannst du dich **jederzeit mit dem alten Passwort einloggen** und den Prozess abbrechen.
3. Wenn du die Seed hast → neues Passwort setzen, alles wieder da.
4. Wenn du nach 7 Tagen nichts tust und keine Seed hast → Account wird gelöscht.

**Das ist wie deine Bank**, die eine ungewöhnliche Auslandsüberweisung blockiert und erst mal bei dir nachfragt. Du hast Zeit, zu reagieren.

### Der Mail-Zugang — ein praktischer Tipp

Weil die 7-Tage-Warnmail per Email kommt: stell sicher, dass du deinen Email-Zugang auf **mehr als nur einem Gerät** hast (Laptop + Handy, oder Laptop + Tablet). Dann bekommst du die Mail auch, wenn ein Gerät mal ausfällt.

Und wenn du dein Passwort hast plus Seed und Backup-Codes in der Mappe: dann brauchst du die Warnmail nicht mal mehr. Du loggst dich direkt ein.

### Die ehrliche Info — aber diesmal ohne Drohung

Wenn du alle drei Papiere gleichzeitig verlierst (Seed weg, Backup-Codes weg, Passwort vergessen), können wir dir technisch nicht helfen. Das ist der **Preis deiner absoluten Privatsphäre** — nicht eine Falle, sondern das Feature, für das du uns gewählt hast.

Aber ehrlich: Zwischen der Erst-Einrichtung und dem Jahres-Check ist der einzige Aufwand, den du je mit Shinpai-AI haben wirst, verteilt auf **10 Minuten jetzt + 10 Sekunden pro Jahr**. Das ist weniger als die meisten Menschen in **einer** Woche an Admin-Kram machen. Ein Tresorschlüssel, einmal geprägt, gilt solange du willst — und falls er mal verloren geht, prägst du dir einfach einen neuen, solange Passwort und 2FA da sind.

**Das ist unser Deal mit dir:** Wir bauen die Mathematik so wasserdicht, wie es die Welt hergibt. Du prägst dir einmal den Schlüssel, und nickst ihn einmal pro Jahr kurz ab. Dann steht dein Tresor immer für dich offen — du sicher, wir blind — für immer.

---

## 11. Die acht Hausregeln (chilliger gefasst) <a id="11-hausregeln"></a>

Diese Regeln bauen wir selbst ein — damit wir **uns selbst** auf Kurs halten. Sie gelten für unser Entwickler-Team, nicht für dich als User.

### Regel 1: Wenn Sicherheit hakt, **keine** Notlösung

Wenn ein sicherer Mechanismus mal ausfällt, darf er **nicht** durch einen älteren, schwächeren ersetzt werden. Das wäre eine Hintertür.

### Regel 2: Server entsperrt sich nach Neustart **nie** selbst

Nach jedem Reboot muss der Betreiber sich persönlich einloggen. Das stellt sicher, dass der Master-Schlüssel immer nur im Arbeitsspeicher lebt und nie dauerhaft auf der Platte.

### Regel 3: Parameter sind festgenagelt — kein "schneller Modus"

Die Sicherheits-Parameter sind im Code hart verdrahtet, nicht per Config einstellbar. Ein "schwacher Modus für schwache Hardware" wäre genau die Lücke, die ein Angreifer sucht.

### Regel 4: Das Salz gehört ins Backup

Die Salz-Datei ist Teil der Schlüssel-Berechnung. Fehlt sie → Tresor nicht mehr entschlüsselbar, auch mit korrektem Passwort. **Wichtig für Betreiber-Backups.**

### Regel 5: Salzstreuer nur mit 2FA

Security-sensitive Hebel sind ohne zweiten Faktor eine Einladung. Deshalb Button nur sichtbar bei aktivem 2FA.

### Regel 6: Der Betreiber kann User-Inhalte **nicht** lesen

Das ist die Zero-Knowledge-Garantie. Gleichwertig mit **Versprechen 1**.

### Regel 7: Keine Krypto-Eigenerfindungen

Alle Bauteile sind TÜV-geprüft und weltweit standardisiert. Gleichwertig mit **Versprechen 2**.

### Regel 8: "Mach das mal schnell" — **Nein**

Wenn jemand drängt, eine Regel aufzuweichen ("nur kurz", "nur dieses eine Mal", "für den Support"), ist die Antwort immer Nein. Sicherheit kennt keine Abkürzungen.

**Das gilt auch für dich, User:** Wenn jemand dich drängt, "nur schnell" dein Passwort einzugeben, deinen Code weiterzugeben, die Seed "zur Sicherheit" zu teilen — **ist es immer Betrug**. Auch wenn die Person scheinbar zu Shinpai-AI gehört. Wir fragen dich nie nach diesen Dingen (siehe Kapitel 4, Regel 1).

---

# TEIL 3 — TECHNISCHER ANHANG (für Nerds und Security-Prüfer)

---

## A. Abkürzungsverzeichnis <a id="a-abkürzungen"></a>

### Kryptographie-Grundbegriffe

| Abkürzung | Ausgeschrieben | Was es bedeutet |
|---|---|---|
| **PQ** | **P**ost-**Q**uantum | "Nach-Quanten-sicher" — funktioniert auch dann noch, wenn Quantencomputer gebaut werden. |
| **KDF** | **K**ey **D**erivation **F**unction | "Schlüssel-Ableitungs-Funktion" — macht aus einem Passwort einen echten Verschlüsselungs-Schlüssel. |
| **MAC** | **M**essage **A**uthentication **C**ode | "Nachrichten-Echtheits-Code" — beweist, dass eine Nachricht nicht verändert wurde. |
| **AEAD** | **A**uthenticated **E**ncryption with **A**ssociated **D**ata | "Authentifizierte Verschlüsselung" — verschlüsselt **und** stellt Echtheit sicher, alles in einem. |
| **IV / Nonce** | **I**nitialization **V**ector / "Number used once" | Eine Einmal-Zufallszahl, die mit jedem Verschlüsselungs-Vorgang mitgegeben wird, damit zweimal derselbe Klartext nie identisch verschlüsselt aussieht. |

### Die Schlüssel

| Abkürzung | Ausgeschrieben | Was es bedeutet |
|---|---|---|
| **KEK** | **K**ey **E**ncryption **K**ey | "Schlüssel-zum-Verschlüsseln-anderer-Schlüssel". Der oberste, aus dem Passwort abgeleitete Key. Verschlüsselt nur weitere Schlüssel, nie direkt Daten. |
| **DEK** | **D**ata **E**ncryption **K**ey | "Daten-Verschlüsselungs-Schlüssel". Der echte Arbeits-Schlüssel, mit dem die tatsächlichen Nutzer-Daten ver- und entschlüsselt werden. |

### Algorithmen

| Abkürzung | Ausgeschrieben | Was es bedeutet |
|---|---|---|
| **AES** | **A**dvanced **E**ncryption **S**tandard | Der Welt-Standard für symmetrische Verschlüsselung seit 2001. |
| **GCM** | **G**alois/**C**ounter **M**ode | Betriebsart von AES, die nicht nur verschlüsselt, sondern auch gleich die Echtheit prüft (AEAD-fähig). |
| **AES-256-GCM** | = AES mit 256-bit Schlüssel im GCM-Modus | Unsere Standard-Symmetrik. |
| **SHA** | **S**ecure **H**ash **A**lgorithm | "Sichere Quersummen-Berechnung". Macht aus beliebigen Daten einen festen Fingerabdruck. |
| **SHA-256** | = SHA mit 256-bit Ausgabe | Ein 64-Zeichen langer Fingerabdruck. |
| **Argon2** | (Kein Akronym — Eigenname) | Der Gewinner der Password Hashing Competition 2015. Extra langsam und speicherhungrig designed. |
| **Argon2id** | Argon2 **id**entity-Variante | Hybrid aus Argon2**i** (Seiten-Kanal-sicher) + Argon2**d** (GPU-resistent). Empfohlene Standard-Variante. |
| **ML-KEM** | **M**odule-**L**attice-based **K**ey **E**ncapsulation **M**echanism | "Gitter-basierter Schlüssel-Einkapselungs-Mechanismus". PQ-sicherer Schlüssel-Austausch. |
| **ML-KEM-768** | ML-KEM in der "768-Bit-Härte"-Variante | Sicherheits-Level ≈ AES-192. |
| **ML-DSA** | **M**odule-**L**attice-based **D**igital **S**ignature **A**lgorithm | "Gitter-basierter digitaler Signatur-Algorithmus". PQ-sichere Unterschrift. |
| **ML-DSA-65** | ML-DSA in der "65"-Sicherheits-Variante | Sicherheits-Level ≈ AES-192. |
| **Kyber** | (Älterer Name für ML-KEM) | Projektname vor der NIST-Standardisierung. Identisch mit ML-KEM. |
| **Dilithium** | (Älterer Name für ML-DSA) | Projektname vor der NIST-Standardisierung. Identisch mit ML-DSA. |

### Authentifizierung

| Abkürzung | Ausgeschrieben | Was es bedeutet |
|---|---|---|
| **2FA** | **2**-**F**aktor-**A**uthentifizierung | Zwei unabhängige Beweise der Identität. |
| **TOTP** | **T**ime-based **O**ne-**T**ime **P**assword | "Zeit-basiertes Einmal-Passwort". Der 6-stellige Code, der alle 30 Sekunden in der Authenticator-App wechselt. |
| **OTP** | **O**ne-**T**ime **P**assword | Oberbegriff. TOTP ist die zeit-basierte Unterart. |
| **HOTP** | **H**MAC-based **O**ne-**T**ime **P**assword | Zähler-basierte Variante (wechselt bei Knopfdruck). Nutzen wir nicht. |
| **HMAC** | **H**ash-based **M**essage **A**uthentication **C**ode | Spezielle MAC-Art, die einen Hash-Algorithmus nutzt. Baustein für TOTP. |

### Standardisierung

| Abkürzung | Ausgeschrieben | Was es bedeutet |
|---|---|---|
| **NIST** | **N**ational **I**nstitute of **S**tandards and **T**echnology | US-Behörde, die Krypto-Standards festlegt. |
| **FIPS** | **F**ederal **I**nformation **P**rocessing **S**tandards | Die Standards selbst. FIPS-203 = ML-KEM. FIPS-204 = ML-DSA. FIPS-197 = AES. |

### Identität und Session

| Abkürzung | Ausgeschrieben | Was es bedeutet |
|---|---|---|
| **API** | **A**pplication **P**rogramming **I**nterface | "Programmierschnittstelle". |
| **Token** | (kein Akronym) | Ein zufälliger String, der als Eintrittsbeleg dient. |
| **Bearer-Token** | "Inhaber-Token" | Art von Token, bei dem wer ihn hat, ihn nutzen darf. |
| **Session** | "Sitzung" | Der Zeitraum zwischen Login und Logout. |
| **Seed-Phrase** | "Saatgut-Wortreihe" | Die 12 oder 24 Wörter, aus denen kryptographische Schlüssel deterministisch wieder herstellbar sind (wie bei Bitcoin-Wallets). |
| **Vault** | "Tresor" | Ein lokal verschlüsselter Datenspeicher. |
| **Igni** | (Eigenname, lat. "ignis" = Feuer) | Die optionale Datei, die nach Owner-Login den Master-Key maschinen-gebunden zwischenspeichert. |

### Systemumgebung

| Abkürzung | Ausgeschrieben | Was es bedeutet |
|---|---|---|
| **RAM** | **R**andom **A**ccess **M**emory | Arbeitsspeicher. Schlüssel leben hier, nicht auf Platte. |
| **machine-id** | — | Ein eindeutiger Computer-Fingerabdruck. |
| **CFFI** | **C** **F**oreign **F**unction **I**nterface | Mechanismus, mit dem Python auf C-Bibliotheken zugreift. |

---

## B. Algorithmen im Detail <a id="b-algorithmen"></a>

### B.1 AES-256-GCM — Standard-Symmetrik

**Vollständig:** Advanced Encryption Standard, 256-bit Schlüssel, Galois/Counter Mode.

**Was macht er?**
- Nimmt Klartext + 256-bit Schlüssel + 96-bit Nonce → gibt Ciphertext + 128-bit Tag zurück.
- Ciphertext = verschlüsseltes Ergebnis. Tag = Echtheits-Prüfsumme.

**Warum "GCM"?**
GCM ist AEAD-fähig (Authenticated Encryption with Associated Data). Verschlüsselung und Manipulations-Erkennung in einem Durchgang. Alternative Modi (CBC, CTR) können das nicht.

**Warum 256-bit?**
128-bit AES gilt noch als sicher, aber Grover's Algorithmus halbiert die effektive Sicherheit auf einem Quantencomputer. 256-bit AES → 128-bit Quanten-Sicherheit.

**Bei uns:** Alle Daten-at-Rest werden mit AES-256-GCM verschlüsselt. Schlüssel ist der DEK.

### B.2 SHA-256 — Standard-Fingerabdruck

**Vollständig:** Secure Hash Algorithm, 2nd generation, 256-bit output.

**Was macht er?**
Nimmt beliebig lange Daten → gibt genau 32 Byte (64 Hex-Zeichen) Fingerabdruck raus.

**Einsatz bei uns:**
- Code-Hash für Bitcoin-Anker (das Monument)
- Integritäts-Prüfungen von Dateien und Releases
- Start.sh-Delta-Erkennung (SHA1 für requirements.txt)
- **NICHT mehr** für Passwort-Hashing (dafür jetzt Argon2id)

### B.3 Argon2id — Password-KDF

**Vollständig:** Argon2 Identity-Variant (Hybrid aus Argon2i und Argon2d).

**Was macht er?**
Nimmt Passwort + Salz + Parameter → gibt 32-Byte-Key raus. Rechnet absichtlich lang (~1 Sekunde) und braucht 128 MB RAM.

**Warum das wichtig ist:**

Ein einziger SHA-256-Durchlauf braucht auf einer modernen GPU ~1 Nanosekunde. Eine mittelgroße Farm rechnet 1 Milliarde Passwörter pro Sekunde durch. Argon2id ist 1.000.000× langsamer. Dieselbe Farm schafft 1 Passwort pro Sekunde.

Zusätzlich kostet jeder Versuch 128 MB RAM. GPUs haben wenig teures RAM → strangelt die Farm-Ökonomie.

**Fixe Parameter (nicht verhandelbar im Code):**

| Parameter | Wert | Begründung |
|---|---|---|
| Algorithmus | `Argon2id` | Hybrid aus Argon2i (side-channel-sicher) + Argon2d (GPU-hart) |
| Speicher | **128 MB** | Bitwarden-Standard, genug um GPU-Farmen zu strangulieren |
| Zeit (Iterationen) | **3** | ~1 s auf normaler CPU |
| Parallelität | **4 Threads** | Standard für moderne CPUs |
| Hash-Länge | **32 Byte** | = Schlüssel-Größe für AES-256 |

**Lib:** `argon2-cffi` (CFFI-Binding zur Referenz-Implementation).

### B.4 ML-KEM-768 — PQ-Key-Wrap

**Vollständig:** Module-Lattice Key Encapsulation Mechanism, Parameter-Set "768".

**Was macht er?**

Ein Schlüssel-Einkapselungs-Mechanismus. Drei Operationen:

```
KeyGen()                      → (PublicKey, PrivateKey)
Encapsulate(PublicKey)        → (SharedSecret, Ciphertext)
Decapsulate(Ciphertext, PrivateKey) → SharedSecret
```

**Ablauf (Alice → Bob):**
1. Bob erzeugt Keypair. Public veröffentlicht, Private bleibt geheim.
2. Alice ruft Encapsulate(PubKey_Bob) → bekommt (SharedSecret_A, Ciphertext).
3. Alice schickt Ciphertext (öffentlich) an Bob.
4. Bob ruft Decapsulate(Ciphertext, PrivKey_Bob) → bekommt SharedSecret_B.
5. SharedSecret_A == SharedSecret_B. Beide haben jetzt denselben Schlüssel, ohne dass er je übers Netz lief.

**Warum "768"?**
- ML-KEM-512: ≈ AES-128 Sicherheit
- **ML-KEM-768**: ≈ AES-192 Sicherheit, **unser Standard**
- ML-KEM-1024: ≈ AES-256 Sicherheit

**Schlüssel-Größen ML-KEM-768:**
- Public Key: 1.184 Byte
- Private Key: 2.400 Byte
- Ciphertext: 1.088 Byte
- Shared Secret: 32 Byte

**Warum PQ-sicher?**
Zugrundeliegende Mathematik: "Module Learning With Errors" (M-LWE). Für klassische und Quanten-Computer gleichermaßen schwer.

**Bei uns:** Der DEK wird mit ML-KEM-768 gewrappt.

### B.5 ML-DSA-65 — PQ-Signatur

**Vollständig:** Module-Lattice Digital Signature Algorithm, Parameter-Set "65".

**Drei Operationen:**

```
KeyGen()                 → (PublicKey, PrivateKey)
Sign(Message, PrivKey)   → Signature
Verify(Message, Signature, PubKey) → True/False
```

**Warum "65"?**
- ML-DSA-44: ≈ AES-128
- **ML-DSA-65**: ≈ AES-192, **unser Standard**
- ML-DSA-87: ≈ AES-256

**Schlüssel-Größen ML-DSA-65:**
- Public Key: 1.952 Byte
- Private Key: 4.032 Byte
- Signature: 3.309 Byte

**Einsatz bei uns:**
- Bitcoin-Anker (Code-Version wird signiert)
- Soul-Hashes bei Shidow-Agenten
- Trade-Pakete (Export-Signatur, Import-Verifikation)

### B.6 TOTP — 30-Sekunden-Code

**Vollständig:** Time-based One-Time Password (RFC 6238).

**Formel (vereinfacht):**
```
Code = HMAC-SHA1(Seed, floor(unix_time / 30))   [auf 6 Stellen gekürzt]
```

Server und Authenticator-App kennen beide den Seed (bei Einrichtung über QR-Code übergeben). Beide rechnen denselben Code aus → Match = gültig.

**Unser Label-Format:**
```
Issuer  = "Kneipe" / "ShinNexus" / "ShinPing" / "Shidow"
Account = Username (z.B. "hasi")
```

---

## C. Die Schlüssel-Kaskade (KEK → DEK → Daten) <a id="c-kaskade"></a>

Der Kern der Schicht-1-Architektur. Dreistufig, jede Stufe hat eine klare Aufgabe.

### Die drei Ebenen

```
  ┌─────────────────┐
  │  VAULT-DATEN    │  ← Identität, Users, Einstellungen, Profile
  │  (AES-256-GCM)  │
  └────────▲────────┘
           │ entschlüsselt mit
  ┌────────┴────────┐
  │      DEK        │  ← Data Encryption Key (256-bit, einmalig erzeugt, unveränderlich)
  │  (ML-KEM-Wrap)  │
  └────────▲────────┘
           │ entwrappt mit
  ┌────────┴────────┐
  │ ML-KEM-PrivKey  │  ← Privater PQ-Schlüssel
  │  (AES-256-GCM)  │
  └────────▲────────┘
           │ entschlüsselt mit
  ┌────────┴────────┐
  │      KEK        │  ← Key Encryption Key (nur aus PW + Salz + machine-id ableitbar)
  │   (Argon2id)    │
  └────────▲────────┘
           │ abgeleitet aus
  ┌────────┴────────┐
  │ Owner-Passwort  │  ← im Kopf des Owners
  │    + machine-id │  ← im Betriebssystem
  │    + .salt      │  ← Datei im Vault-Ordner
  └─────────────────┘
```

### Die einzelnen Dateien

Im Vault-Ordner liegen:

| Datei | Inhalt | Schlüssel |
|---|---|---|
| `.salt` | 16 Byte Zufall (unverschlüsselt!) | — (ist ein Salz, kein Secret) |
| `kem_priv.vault` | ML-KEM-Private-Key | AES-GCM(KEK) |
| `kem_priv.seed.vault` | ML-KEM-Private-Key, zweite Kopie | AES-GCM(Seed-Key) — Recovery-Pfad |
| `dek.wrap.vault` | DEK, eingekapselt | ML-KEM-768 Encapsulation |
| `identity.vault` | Owner-Identität | AES-GCM(DEK) |
| `users.vault` | User-Datenbank | AES-GCM(DEK) |

### Der Entschlüsselungs-Ablauf (beim Owner-Login)

Einmal beim Login:
1. Owner gibt Passwort ein.
2. Server liest `.salt` und `machine-id`.
3. **KEK ableiten:** `KEK = Argon2id(password + .salt + machine-id)` — dauert ~1 Sekunde.
4. **ML-KEM-Private entschlüsseln:** `privkey = AES-GCM-Decrypt(kem_priv.vault, KEK)`.
5. **DEK entwrappen:** `DEK = ML-KEM-Decapsulate(dek.wrap.vault, privkey)`.
6. **DEK bleibt im RAM**, solange der Server läuft.

Danach für jede Vault-Datei:
- `klartext = AES-GCM-Decrypt(datei.vault, DEK)`

### Warum die Trennung KEK ↔ DEK?

**Der alte Ansatz** (vor 2026-04-16): Ein einziger Master-Key aus `SHA256(PW + machine-id)`, direkt zum Verschlüsseln aller Dateien.

**Zwei Probleme:**
1. **Owner-Passwort-Änderung = Katastrophen-Risiko.** Alle Vault-Dateien müssen neu verschlüsselt werden. Strom-Ausfall mitten im Re-Encrypt → halb alter, halb neuer Vault → kaputt.
2. **Nicht PQ-nativ.** Nirgendwo asymmetrische Crypto.

**Der neue Ansatz:**
1. **PW-Change = atomisch.** Nur **eine** Datei (`kem_priv.vault`) neu verschlüsseln. DEK bleibt gleich, Vault-Dateien unberührt.
2. **PQ-nativ.** ML-KEM-768 ist der einzige asymmetrische Wrap, nach NIST-FIPS-203 offiziell PQ-sicher.

### Owner-Passwort-Wechsel — atomar

```
1. KEK_alt = Argon2id(PW_alt + .salt + machine-id)
2. privkey = AES-GCM-Decrypt(kem_priv.vault, KEK_alt)
3. KEK_neu = Argon2id(PW_neu + .salt + machine-id)
4. AES-GCM-Encrypt(privkey, KEK_neu) → kem_priv.vault (überschreibt)
5. Fertig.
```

### Recovery-Seed-Integration

- `kem_priv.seed.vault` — mit Seed-abgeleitetem-Key verschlüsselt
- Bei Seed-Recovery: ML-KEM-Private über Seed-Pfad holen → DEK entwrappen → neuen PW-KEK ableiten → `kem_priv.vault` neu schreiben
- Zwei unabhängige Pfade zum DEK: PW oder Seed. Jeder reicht.

---

## D. NIST-Standards und Code-Referenzen <a id="d-standards"></a>

### NIST / FIPS-Standards (die "TÜV-Siegel")

| Zweck | Algorithmus | Standard (TÜV-Siegel) |
|---|---|---|
| Symmetrische Verschlüsselung | AES-256-GCM | FIPS-197 + NIST-SP-800-38D |
| Hash | SHA-256 | FIPS-180-4 |
| Passwort-KDF | Argon2id | RFC 9106 (IRTF) |
| PQ Key-Wrap | ML-KEM-768 | FIPS-203 |
| PQ Signatur | ML-DSA-65 | FIPS-204 |
| 2FA | TOTP | RFC 6238 |

### Python-Bibliotheken

- **`argon2-cffi`** — Argon2id Bindings (C-Referenz-Impl, nicht reines Python)
- **`cryptography`** — AES-GCM, SHA-256, HMAC (OpenSSL-backed)
- **`oqs`** (liboqs-python) — ML-KEM, ML-DSA (NIST PQ-Standards, Open-Source-Impl)
- **`pyotp`** — TOTP/HOTP

Alle vier sind auf allen drei Zielplattformen (Linux, Windows, Android) installiert und getestet. Die Windows-Build-Pipeline baut `liboqs` aus C-Source selbst, weil der `pip install`-Pfad auf Windows kaputt ist.

### Code-Referenzen

| Komponente | Datei | Was |
|---|---|---|
| PQ-Schlüsselpaar erzeugen | `ShinNexus.py` `_ensure_keypair()` | ML-DSA-65 + ML-KEM-768 via `oqs`-Bibliothek |
| Vault-Unlock | `ShinNexus.py` `vault_unlock()` | KEK-Ableitung + Kaskade |
| Symmetrische Verschlüsselung | `ShinNexus.py` `vault_encrypt/decrypt` | AES-256-GCM |
| TOTP Verify | alle Programme (`pyotp`) | RFC 6238 |
| Login-Endpunkte | `ShinNexus.py /api/auth/login`, `Kneipe server.py` | PW-Hash-Check + Token-Issue |

---

*Erstellt: 2026-04-23*
*Basis: `Konzept-LaienV4.md` + NotebookLM-Feedback V5 (Podcast "Verschlüsselung ohne Panik für absolute Laien")*
*Drei Kern-Änderungen gegenüber V4:*
*1. **Hand-Holding bei 2FA-Einrichtung (Kapitel 9):** App-Installation als "digitaler Schlüsselbund, du kannst nichts kaputt machen"-Ton, 4 benannte Schritte mit Fehlertoleranz statt trockener Liste. Nennt konkret Aegis (Android) + Raivo (iPhone).*
*2. **Analoge Handlungsanweisungen im Führerschein (Kapitel 10):** Positive Anleitung "Kugelschreiber + Zettel" statt Negativ-Warnungen. Expliziter Hinweis: **"Auch ein Foto ist ein digitales Dokument"** — der häufigste DAU-Fehler adressiert. Kein-Drucker-Lösung gleich mit eingebaut (handschriftlich ist sogar sicherer als Ausdruck).*
*3. **Technischer Mittelteil radikal gekürzt:** Session-Token-Erklärung aus Kapitel 7 komplett raus (in Anhang C verwiesen). Salzstreuer-Kapitel 8 auf einen Satz Kernnutzen reduziert: "Ein Knopf, der dein Schloss noch sicherer macht, selbst falls jemand alte Daten gestohlen hat." Details bleiben im Anhang, Laien-Teil wird leichter verdaulich.*
