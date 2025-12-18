import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from rdflib import Graph, URIRef, BNode, Namespace
from rdflib.namespace import RDF, RDFS, OWL, DCTERMS

WIKIDATA_SPARQL_ENDPOINT = "https://query.wikidata.org/sparql"
HEADERS = {"User-Agent": "WikidataIdentifiersChecker/1.0 (example@example.com)"}

WD = Namespace("http://www.wikidata.org/entity/")
WDT = Namespace("http://www.wikidata.org/prop/direct/")
SCHEMA = Namespace("http://schema.org/")
FOAF = Namespace("http://xmlns.com/foaf/0.1/")


# ---------------- HTTP helpers ----------------

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


def fetch_rdf_text(rdf_url: str) -> str | None:
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


# ---------------- Wikidata identifiers (SPARQL) ----------------

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
    resp = requests.get(
        WIKIDATA_SPARQL_ENDPOINT,
        params={"query": query, "format": "json"},
        headers=HEADERS,
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()

    out = []
    for b in data["results"]["bindings"]:
        out.append((b["propertyLabel"]["value"], b["id"]["value"], b["url"]["value"]))
    return out


# ---------------- Semantically safer RDF mapping ----------------

DOCUMENT_LIKE_TYPES = {
    FOAF.Document,
    SCHEMA.WebPage,
    SCHEMA.Article,
    SCHEMA.CreativeWork,   # czasem to też obiekt, ale często opis strony/dokumentu
    DCTERMS.BibliographicResource,
}

ENTITY_LIKE_TYPES = {
    FOAF.Person,
    FOAF.Organization,
    SCHEMA.Person,
    SCHEMA.Organization,
    SCHEMA.Place,
    SCHEMA.MusicGroup,
    SCHEMA.Book,
    SCHEMA.Movie,
    SCHEMA.CreativeWork,
}

LABEL_PROPS = {RDFS.label, SCHEMA.name, FOAF.name}


def looks_like_matches_identifier(uri: str, identifier: str) -> bool:
    # “bezpieczne” dopasowanie segmentu identyfikatora
    safe = re.escape(identifier)
    return re.search(rf"(^|[\/#=:]){safe}($|[\/#?&])", uri, re.IGNORECASE) is not None


def looks_related_to_url(uri: str, final_url: str) -> bool:
    # prosta heurystyka: wspólny prefiks host/path
    # (bez parsowania URL — celowo prosto)
    return final_url and (uri.startswith(final_url) or final_url.startswith(uri))


def has_label(g: Graph, node) -> bool:
    for p in LABEL_PROPS:
        if (node, p, None) in g:
            return True
    return False


def count_subject_degree(g: Graph, node) -> int:
    # ile trójek ma node jako subject
    return sum(1 for _ in g.triples((node, None, None)))


def get_types(g: Graph, node) -> set[URIRef]:
    return {t for t in g.objects(node, RDF.type) if isinstance(t, URIRef)}


def score_candidate(g: Graph, node, identifier: str, final_url: str) -> float:
    if isinstance(node, BNode):
        # blank node raczej nie jest globalnym “głównym zasobem”
        base = -2.0
    else:
        base = 2.0

    degree = count_subject_degree(g, node)
    score = base + min(degree, 50) * 0.2  # limit, żeby nie dominowało

    types = get_types(g, node)
    if types & ENTITY_LIKE_TYPES:
        score += 2.0
    if types & DOCUMENT_LIKE_TYPES:
        score -= 3.0

    if has_label(g, node):
        score += 1.5

    if isinstance(node, URIRef):
        s = str(node)
        if identifier and looks_like_matches_identifier(s, identifier):
            score += 2.0
        if looks_related_to_url(s, final_url):
            score += 1.0

    return score


def pick_main_subject(g: Graph, identifier: str, final_url: str):
    # bierzemy tylko te węzły, które gdziekolwiek występują jako subject
    subjects = set(s for s, _, _ in g.triples((None, None, None)))

    # filtr: tylko subjecty, które mają jakiś “opis” (>=1 triple)
    candidates = [s for s in subjects if count_subject_degree(g, s) > 0]

    if not candidates:
        return None

    scored = [(score_candidate(g, s, identifier, final_url), s) for s in candidates]
    scored.sort(key=lambda x: x[0], reverse=True)
    return scored[0][1]


def collect_sameas_cluster(g: Graph, seed):
    """
    Zbiera seed + wszystko połączone przez owl:sameAs / schema:sameAs (w obie strony).
    """
    sameas_props = {OWL.sameAs, SCHEMA.sameAs}
    cluster = set([seed])
    queue = [seed]

    while queue:
        cur = queue.pop()
        for p in sameas_props:
            for o in g.objects(cur, p):
                if isinstance(o, (URIRef, BNode)) and o not in cluster:
                    cluster.add(o)
                    queue.append(o)
            for s in g.subjects(p, cur):
                if isinstance(s, (URIRef, BNode)) and s not in cluster:
                    cluster.add(s)
                    queue.append(s)

    return cluster


def rewrite_graph_using_cluster(src: Graph, qid: str, cluster: set) -> Graph:
    q = WD[qid]
    out = Graph()
    out.namespace_manager.bind("wd", WD)
    out.namespace_manager.bind("wdt", WDT)
    out.namespace_manager.bind("owl", OWL)
    out.namespace_manager.bind("rdfs", RDFS)
    out.namespace_manager.bind("schema", SCHEMA)
    out.namespace_manager.bind("foaf", FOAF)

    for s, p, o in src:
        ns = q if s in cluster else s
        no = q if o in cluster else o
        out.add((ns, p, no))

    return out


# ---------------- Main ----------------

def main():
    qid = "Q127345"
    wd_entity = WD[qid]

    identifiers = get_identifier_urls(qid)
    print(f"Znaleziono {len(identifiers)} identyfikatorów dla {qid}.\n")

    wikidata_kg = Graph()
    wikidata_kg.namespace_manager.bind("wd", WD)
    wikidata_kg.namespace_manager.bind("wdt", WDT)
    wikidata_kg.namespace_manager.bind("owl", OWL)
    wikidata_kg.namespace_manager.bind("rdfs", RDFS)
    wikidata_kg.namespace_manager.bind("schema", SCHEMA)
    wikidata_kg.namespace_manager.bind("foaf", FOAF)

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

            main_subj = pick_main_subject(src, identifier=identifier, final_url=final_url)
            if main_subj is None:
                print(f"   RDF: {rdf_url} -> brak sensownego subjecta (pomijam)")
                continue

            cluster = collect_sameas_cluster(src, main_subj)

            rewritten = rewrite_graph_using_cluster(src, qid=qid, cluster=cluster)

            # (opcjonalnie) dopnij informację o źródle
            wikidata_kg.add((wd_entity, OWL.sameAs, URIRef(final_url)))
            wikidata_kg.add((wd_entity, OWL.sameAs, URIRef(rdf_url)))

            wikidata_kg += rewritten
            imported_total += len(rewritten)

            subj_preview = str(main_subj) if isinstance(main_subj, URIRef) else f"_:{main_subj}"
            print(f"   RDF: {rdf_url}")
            print(f"      main_subject: {subj_preview}")
            print(f"      cluster_size: {len(cluster)}")
            print(f"      added_triples: {len(rewritten)}")

        print()

    out_path = f"wikidata_kg_{qid}_semantic.ttl"
    wikidata_kg.serialize(destination=out_path, format="turtle")

    print("======================================")
    print(f"Zmergowano trójek: {imported_total}")
    print(f"Zapisano graf do: {out_path}")


if __name__ == "__main__":
    main()
