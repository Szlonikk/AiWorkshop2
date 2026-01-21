import re
import unicodedata
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from rdflib import Graph, URIRef, Literal, Namespace
from rdflib.namespace import RDF, RDFS, OWL, DCTERMS, SKOS

WIKIDATA_SPARQL_ENDPOINT = "https://query.wikidata.org/sparql"
HEADERS = {"User-Agent": "WikidataIdentifiersCollector/1.0 (example@example.com)"}

WD = Namespace("http://www.wikidata.org/entity/")
WDT = Namespace("http://www.wikidata.org/prop/direct/")
SCHEMA = Namespace("http://schema.org/")
FOAF = Namespace("http://xmlns.com/foaf/0.1/")


# ---------------- Text helpers ----------------

def _strip_accents(s: str) -> str:
    nfkd = unicodedata.normalize("NFKD", s)
    return "".join(ch for ch in nfkd if not unicodedata.combining(ch))

def norm_name(s: str) -> str:
    return _strip_accents(s).casefold().strip()


# ---------------- HTTP / RDF discovery ----------------

def url_works(url: str) -> bool:
    try:
        resp = requests.get(url, headers=HEADERS, timeout=15, allow_redirects=True)
        return 200 <= resp.status_code < 300
    except requests.RequestException:
        return False

def try_direct_rdf(url: str):
    lower = url.lower()
    if lower.endswith(".rdf"):
        return url if url_works(url) else None
    rdf_url = url + ".rdf"
    if url_works(rdf_url):
        return rdf_url
    return None

def find_rdf_links_in_html(url: str):
    rdf_links = set()
    try:
        resp = requests.get(url, headers=HEADERS, timeout=30, allow_redirects=True)
        if not (200 <= resp.status_code < 300):
            return []
        soup = BeautifulSoup(resp.text, "html.parser")

        for a in soup.find_all("a", href=True):
            full = urljoin(url, a["href"])
            if full.lower().endswith(".rdf"):
                rdf_links.add(full)

        for link in soup.find_all("link", href=True):
            full = urljoin(url, link["href"])
            if full.lower().endswith(".rdf"):
                rdf_links.add(full)
    except requests.RequestException:
        return []

    return list(rdf_links)

def check_identifier_url(url: str):
    try:
        resp = requests.get(url, headers=HEADERS, timeout=20, allow_redirects=True)
    except requests.RequestException:
        return False, url, []

    if not (200 <= resp.status_code < 300):
        return False, resp.url, []

    final_url = resp.url
    rdf_list = []

    rdf_direct = try_direct_rdf(final_url)
    if rdf_direct:
        rdf_list.append(rdf_direct)

    rdf_list.extend(find_rdf_links_in_html(final_url))
    return True, final_url, list(set(rdf_list))

def fetch_rdf_text(rdf_url: str):
    try:
        resp = requests.get(rdf_url, headers=HEADERS, timeout=40, allow_redirects=True)
        if not (200 <= resp.status_code < 300):
            return None
        return resp.text
    except requests.RequestException:
        return None

def guess_rdf_format(rdf_url: str, rdf_text: str) -> str:
    if rdf_url.lower().endswith(".rdf"):
        return "xml"
    if "<rdf:RDF" in rdf_text or "xmlns:rdf" in rdf_text:
        return "xml"
    return "turtle"


# ---------------- Wikidata data (SPARQL) ----------------

def wdqs_get_json(query: str) -> dict:
    resp = requests.get(
        WIKIDATA_SPARQL_ENDPOINT,
        params={"query": query, "format": "json"},
        headers=HEADERS,
        timeout=60,
    )
    resp.raise_for_status()
    return resp.json()

def get_people_employed_by_q189441(limit: int = 10) -> list[tuple[str, str]]:
    """
    Zwraca listę (qid, label) dla osób (Q5) które mają employer (P108) = Q189441.
    """
    query = f"""
    SELECT ?person ?personLabel WHERE {{
      ?person wdt:P31 wd:Q5 ;
              wdt:P108 wd:Q189441 .
      SERVICE wikibase:label {{ bd:serviceParam wikibase:language "pl,en". }}
    }}
    ORDER BY ?personLabel
    LIMIT {limit}
    """
    data = wdqs_get_json(query)

    out = []
    for b in data["results"]["bindings"]:
        person_uri = b["person"]["value"]  # np. http://www.wikidata.org/entity/Q123
        qid = person_uri.rsplit("/", 1)[-1]
        label = b.get("personLabel", {}).get("value", qid)
        out.append((qid, label))
    return out

def get_identifier_urls(qid: str):
    query = f"""
    SELECT ?propertyLabel ?id ?url WHERE {{
      wd:{qid} ?propStatement ?statement .
      ?property wikibase:claim ?propStatement ;
                wikibase:propertyType wikibase:ExternalId .
      ?statement ?ps ?id .
      ?property wikibase:statementProperty ?ps .

      OPTIONAL {{ ?property wdt:P1630 ?formatterUrl . }}

      BIND(
        IF(
          BOUND(?formatterUrl),
          IRI(REPLACE(STR(?formatterUrl), "\\\\$1", STR(?id))),
          IRI(STR(?id))
        ) AS ?url
      )

      SERVICE wikibase:label {{ bd:serviceParam wikibase:language "en". }}
    }}
    """
    data = wdqs_get_json(query)

    out = []
    for b in data["results"]["bindings"]:
        out.append((b["propertyLabel"]["value"], b["id"]["value"], b["url"]["value"]))
    return out

def get_entity_names_from_wikidata(qid: str) -> set[str]:
    query = f"""
    SELECT ?name WHERE {{
      {{
        wd:{qid} rdfs:label ?name .
      }}
      UNION
      {{
        wd:{qid} skos:altLabel ?name .
      }}
    }}
    """
    data = wdqs_get_json(query)

    names = set()
    for b in data["results"]["bindings"]:
        names.add(b["name"]["value"])
    return names


# ---------------- Deterministic mapping (NO scoring) ----------------

LABEL_PROPS = {RDFS.label, SCHEMA.name, FOAF.name}

def looks_like_matches_identifier(uri: str, identifier: str) -> bool:
    safe = re.escape(identifier)
    return re.search(rf"(^|[\/#=:]){safe}($|[\/#?&])", uri, re.IGNORECASE) is not None

def looks_related_to_url(uri: str, final_url: str) -> bool:
    return bool(final_url) and (uri.startswith(final_url) or final_url.startswith(uri))

def nodes_matching_names(g: Graph, names_norm: set[str]) -> set:
    out = set()
    for s, p, o in g.triples((None, None, None)):
        if p in LABEL_PROPS and isinstance(o, Literal):
            if norm_name(str(o)) in names_norm:
                out.add(s)
    return out

def nodes_matching_identifier_or_url(g: Graph, identifier: str, final_url: str) -> set:
    out = set()
    for s, p, o in g.triples((None, None, None)):
        for node in (s, o):
            if isinstance(node, URIRef):
                u = str(node)
                if identifier and looks_like_matches_identifier(u, identifier):
                    out.add(node)
                elif final_url and looks_related_to_url(u, final_url):
                    out.add(node)
    return out

def rewrite_graph_replace_nodes(src: Graph, qid: str, to_replace: set) -> Graph:
    q = WD[qid]
    out = Graph()
    out.namespace_manager.bind("wd", WD)
    out.namespace_manager.bind("wdt", WDT)
    out.namespace_manager.bind("owl", OWL)
    out.namespace_manager.bind("rdfs", RDFS)
    out.namespace_manager.bind("schema", SCHEMA)
    out.namespace_manager.bind("foaf", FOAF)
    out.namespace_manager.bind("dcterms", DCTERMS)

    for s, p, o in src:
        ns = q if s in to_replace else s
        no = q if o in to_replace else o
        out.add((ns, p, no))

    return out


# ---------------- Per-person runner ----------------

def process_qid(qid: str) -> str:
    """
    Uruchamia pipeline dla jednego QID i zapisuje osobny TTL.
    Zwraca ścieżkę do pliku wynikowego.
    """
    wd_entity = WD[qid]

    wd_names = get_entity_names_from_wikidata(qid)
    names_norm = {norm_name(n) for n in wd_names}

    identifiers = get_identifier_urls(qid)
    print(f"\n\n########## {qid} ##########")
    print(f"Znaleziono {len(identifiers)} identyfikatorów dla {qid}.\n")

    merged = Graph()
    merged.namespace_manager.bind("wd", WD)
    merged.namespace_manager.bind("wdt", WDT)
    merged.namespace_manager.bind("owl", OWL)
    merged.namespace_manager.bind("rdfs", RDFS)
    merged.namespace_manager.bind("schema", SCHEMA)
    merged.namespace_manager.bind("foaf", FOAF)
    merged.namespace_manager.bind("dcterms", DCTERMS)

    imported_total = 0

    for prop_label, identifier, url in identifiers:
        alive, final_url, rdf_urls = check_identifier_url(url)

        print("======================================")
        print(f"Właściwość:  {prop_label}")
        print(f"ID:          {identifier}")
        print(f"URL oryg:    {url}")
        print(f"URL finalny: {final_url}")

        if not alive:
            print("STATUS: ERROR Strona nie działa\n")
            continue

        if not rdf_urls:
            print("RDF: brak\n")
            continue

        for rdf_url in rdf_urls:
            rdf_text = fetch_rdf_text(rdf_url)
            if not rdf_text:
                print("   RDF:", rdf_url, "-> nie udało się pobrać")
                continue

            fmt = guess_rdf_format(rdf_url, rdf_text)

            src = Graph()
            try:
                src.parse(data=rdf_text, format=fmt)
            except Exception:
                try:
                    src.parse(data=rdf_text, format="turtle" if fmt == "xml" else "xml")
                except Exception as e:
                    print(f"   RDF: {rdf_url} -> parse error: {e}")
                    continue

            # podmiany na wd:{qid}
            by_name = nodes_matching_names(src, names_norm)
            by_id_or_url = nodes_matching_identifier_or_url(src, identifier=identifier, final_url=final_url)

            to_replace = set()
            to_replace |= by_name
            to_replace |= by_id_or_url

            if not to_replace:
                print(f"   RDF: {rdf_url} -> brak dopasowań (ani nazwa, ani ID/URL), pomijam")
                continue

            rewritten = rewrite_graph_replace_nodes(src, qid=qid, to_replace=to_replace)

            # Prosta proweniencja
            merged.add((wd_entity, OWL.sameAs, URIRef(final_url)))
            merged.add((wd_entity, OWL.sameAs, URIRef(rdf_url)))
            merged.add((wd_entity, DCTERMS.source, URIRef(rdf_url)))

            merged += rewritten
            imported_total += len(rewritten)

            print(f"   RDF: {rdf_url}")
            print(f"      matched_by_name:      {len(by_name)}")
            print(f"      matched_by_id_or_url: {len(by_id_or_url)}")
            print(f"      replaced_nodes_total: {len(to_replace)}")
            print(f"      added_triples:        {len(rewritten)}")

        print()

    out_path = f"wikidata_kg_{qid}_merged_no_scoring.ttl"
    merged.serialize(destination=out_path, format="turtle")

    print("======================================")
    print(f"{qid}: Zmergowano trójek (po rewrite): {imported_total}")
    print(f"{qid}: Zapisano graf do: {out_path}")

    return out_path


# ---------------- Main ----------------

def main():
    people = get_people_employed_by_q189441(limit=20)
    print(f"Pobrano {len(people)} osób do przetworzenia (LIMIT 10).")
    for qid, label in people:
        print(f"- {qid} | {label}")

    for qid, label in people:
        try:
            process_qid(qid)
        except Exception as e:
            print(f"\n!!! ERROR dla {qid} ({label}): {e}\n")


if __name__ == "__main__":
    main()
